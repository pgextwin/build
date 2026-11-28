#!/usr/bin/env python3
"""Offline K3 and PR-B5 artifact contract tests; uses public RFC 8032 test keys."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
k3 = import_module("verify-central-k3-admission")
identity = import_module("fleet-release-identity")
legacy = import_module("chat-signed-main-audit")
router = import_module("ci-router")
auth, audit, claims = k3.auth, k3.audit, k3.claims
rfc = runpy.run_path(str(ROOT / "tests/test-verify-local-authorized-candidate.py"))
sign_ticket = rfc["sign_ticket"]
canonical = k3.ticket_verifier.canonical_json

NOW = datetime(2026, 11, 28, 15, 40, tzinfo=timezone.utc)
TIMESTAMP = "2026-11-28T15:40:00Z"
MAIN, BASE, PIN, EXTENSION_SOURCE, ISSUER_MAIN, CLAIM_COMMIT = (c * 40 for c in "abcdef")
REQUEST_ID = "1" * 32
CANDIDATE_ID = "2" * 20
ISSUER_PREFIX = f"repos/{k3.live.ISSUER_REPOSITORY}"
RUN_ID = 123456789
ISSUER_RUN_ID = 44054867827
EVENT = "schedule"
MAJORS = list(range(15, 20))
ARTIFACT_NAME = "central-signed-main-intent-nonpublishing"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    Path(path).write_text(json.dumps(value), encoding="utf-8")


def contents(path, raw):
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    return {"type": "file", "path": path, "encoding": "base64", "sha": blob,
            "size": len(raw), "content": base64.b64encode(raw).decode("ascii")}


class Fixture:
    def __init__(self, root, extension="pg_bigm", ticket_base=MAIN, event=EVENT):
        self.root = root
        self.extension = extension
        self.ticket_base = ticket_base
        self.event = event
        self.branch = f"auto-candidate/{extension}/{CANDIDATE_ID}"
        self.manifest = f"extensions/{extension}/extension.json"
        self.authority = load(ROOT / k3.AUTHORITY_PATH)
        self.authority.update(policyEpoch=2, issuerPublicKey=rfc["RFC_VECTORS"][0][0])
        self.fleet = load(ROOT / k3.FLEET_PATH)
        self.fleet["entries"].append({
            "repository": k3.REPOSITORY, "mode": "BUILD", "candidateEnabled": True,
            "releasePolicy": self.fleet["releasePolicy"], "reason": "K3 fixture",
        })
        self.admission = load(ROOT / k3.ADMISSION_PATH)
        self.lifecycle = load(ROOT / k3.LIFECYCLE_PATH)
        declarations = ROOT / "tests/fixtures/central-extension"
        self.declaration = k3.central_extension.convert_declaration(
            load(declarations / f"{extension}-extension.json"),
            load(declarations / f"{extension}-package.json"))
        admitted = identity.parse_admission(canonical(self.admission))
        declared = identity.sources(self.declaration, admission=admitted)
        self.sources = {major: declared[major] for major in MAJORS}
        self.upstream = self.declaration["upstream"]["repository"]
        self.inputs = {
            "repository": k3.REPOSITORY, "consumerRunId": 100, "operation": "candidate",
            "plan": {"extension": extension, "candidateId": CANDIDATE_ID, "branch": self.branch},
            "centralScope": k3.local_auth_central.central_scope(extension, self.branch),
            "sources": [dict(src, licenses=[{"sha256": "1" * 64}]) for src in self.sources.values()],
        }
        self.central = {k3.MAIN_ENDPOINT: {"name": "main", "protected": True, "commit": {"sha": MAIN}}}
        self.central_calls = []
        self.issuer_calls = []
        for path, obj in ((k3.AUTHORITY_PATH, self.authority), (k3.FLEET_PATH, self.fleet),
                          (k3.ADMISSION_PATH, self.admission), (k3.LIFECYCLE_PATH, self.lifecycle),
                          (self.manifest, self.declaration)):
            self.set_central(path, obj)
        if ticket_base != MAIN:
            self.set_central(k3.AUTHORITY_PATH, self.authority, sha=ticket_base)
            # A distinct baseline manifest models the pre-merge upstream pin.
            old_declaration = deepcopy(self.declaration)
            old_upstream = old_declaration["upstream"]
            for row in old_upstream.get("perPostgresql", {"default": old_upstream}).values():
                row["commit"] = "0" * 40
            self.set_central(self.manifest, old_declaration, sha=ticket_base)
        caller = (ROOT / auth.CALLER).read_text(encoding="utf-8")
        caller = caller.replace(auth.read_caller_pin(ROOT), PIN)
        self.set_central_raw(auth.CALLER, caller.encode())
        self.ticket = {
            "schemaVersion": 1, "sourceKind": "LOCAL_AUTH_REQUEST_V1", "operation": "candidate",
            "repository": k3.REPOSITORY, "repositoryId": 123, "workflowPath": k3.ticket_verifier.WORKFLOW_PATH,
            "issuerKeyId": k3.live.ISSUER_KEY_ID, "policyEpoch": 2, "requestId": REQUEST_ID, "nonce": "3" * 64,
            "issuedAt": "2026-11-28T15:30:00Z", "notBefore": "2026-11-28T15:30:00Z",
            "expiresAt": "2026-11-28T15:45:00Z",
            "manifestBlob": self.central[self.content_endpoint(self.manifest, ticket_base)]["sha"],
            **dict.fromkeys(("policySha", "centralMainSha", "targetMainSha", "verifierSha"), ticket_base),
        }
        issuer_repo = {"full_name": k3.live.ISSUER_REPOSITORY, "id": 321, "default_branch": "main"}
        self.issuer_run = {
            "id": ISSUER_RUN_ID, "run_attempt": 1,
            "repository": issuer_repo, "head_repository": issuer_repo,
            "head_branch": "main", "head_sha": ISSUER_MAIN,
            "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "workflow_id": k3.issuer_workflow_id, "path": k3.live.ISSUER_WORKFLOW,
        }
        self.issuer = {
            ISSUER_PREFIX: issuer_repo,
            ISSUER_PREFIX + "/git/ref/heads/main": {
                "ref": "refs/heads/main", "object": {"type": "commit", "sha": ISSUER_MAIN}},
            f"{ISSUER_PREFIX}/actions/runs/{ISSUER_RUN_ID}": self.issuer_run,
            f"{ISSUER_PREFIX}/actions/workflows/{k3.issuer_workflow_id}": {
                "id": k3.issuer_workflow_id, "path": k3.live.ISSUER_WORKFLOW},
            f"{ISSUER_PREFIX}/git/ref/claims/{REQUEST_ID}": {
                "ref": f"refs/claims/{REQUEST_ID}", "object": {"type": "commit", "sha": CLAIM_COMMIT}},
        }
        self.claim_endpoint = f"{ISSUER_PREFIX}/contents/claim.json?ref={CLAIM_COMMIT}"
        self.claim_ref = f"{ISSUER_PREFIX}/git/ref/claims/{REQUEST_ID}"
        self.claim = {
            "requestId": REQUEST_ID, "issuerRepository": k3.live.ISSUER_REPOSITORY,
            "issuerRunId": str(ISSUER_RUN_ID), "issuerRunAttempt": "1", "operation": "candidate",
            "recordedAt": "2026-11-28T15:31:00Z",
        }
        self.resign()
        self.artifacts = self.root / "artifacts"
        self.intent_dir, self.audit_dir, self.dist_dir = (self.root / name for name in ("intent", "evidence", "dist"))
        self.dist_dir.mkdir()
        self.zip_paths, self.packages, self.intents = {}, {}, {}
        for major in MAJORS:
            self.make_signing_artifacts(major)

    @staticmethod
    def content_endpoint(path, sha=MAIN):
        return f"{k3.CENTRAL_API}/contents/{path}?ref={sha}"

    def central_api(self, endpoint):
        self.central_calls.append(endpoint)
        if endpoint not in self.central:
            raise OSError("fixture 404")
        return deepcopy(self.central[endpoint])

    def issuer_api(self, endpoint):
        self.issuer_calls.append(endpoint)
        if endpoint not in self.issuer:
            raise OSError("fixture 404")
        return deepcopy(self.issuer[endpoint])

    def set_central_raw(self, path, raw, *, sha=MAIN):
        self.central[self.content_endpoint(path, sha)] = contents(path, raw)

    def set_central(self, path, obj, *, sha=MAIN):
        self.set_central_raw(path, canonical(obj), sha=sha)

    def set_claim(self):
        self.issuer[self.claim_endpoint] = contents("claim.json", canonical(self.claim))

    def set_ticket_bytes(self):
        self.raw_ticket = canonical(self.ticket)
        digest = k3.sha256(self.raw_ticket)
        self.issuance = {
            "repository": k3.live.ISSUER_REPOSITORY, "mainSha": ISSUER_MAIN,
            "workflowPath": k3.live.ISSUER_WORKFLOW, "workflowId": k3.issuer_workflow_id,
            "runId": ISSUER_RUN_ID, "claimCommitSha": CLAIM_COMMIT,
            "requestId": REQUEST_ID, "ticketSha256": digest,
        }
        self.claim["ticketSha256"] = digest
        self.set_claim()

    def resign(self, **overrides):
        self.raw_inputs = canonical(self.inputs)
        self.ticket.update(inputsSha256=k3.sha256(self.raw_inputs),
                           upstreamSourcesSha256=k3.sha256(canonical(self.inputs["sources"])))
        self.ticket.update(overrides)
        sign_ticket(self.ticket)
        self.set_ticket_bytes()

    def zip_and_audit(self, major):
        zip_path, package, intent = self.zip_paths[major], self.packages[major], self.intents[major]
        with zipfile.ZipFile(zip_path, "w") as archive:
            for name, obj in (("PACKAGE-INFO.json", package), (auth.INTENT_NAME, intent)):
                # Fixed ZipInfo timestamp keeps the X-02 sample reproducible.
                archive.writestr(zipfile.ZipInfo(name), canonical(obj))
        subject = {"name": zip_path.name, "digest": {"sha256": k3.sha256(zip_path.read_bytes())}}
        sbom = {"spdxVersion": "SPDX-2.3"}
        cert = {claim: expected for claim, expected, _ in claims.certificate_expectations(intent)}
        predicate_inputs = {
            claims.SLSA: {
                "buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"},
                "runDetails": {"metadata": {"invocationId": intent["run_invocation_uri"]},
                               "builder": {"id": auth.signer_uri(PIN)}},
            },
            claims.SPDX: sbom,
        }
        reports = {}
        raw_claims = {}
        for kind, predicate in predicate_inputs.items():
            raw_claims[kind] = [{"verificationResult": {
                "signature": {"certificate": cert},
                "verifiedTimestamps": [{"type": "Tlog", "timestamp": TIMESTAMP}],
                "statement": {"subject": [subject], "predicateType": kind, "predicate": predicate},
            }}]
            reports[kind] = claims.compare(kind, raw_claims[kind], subject, intent, sbom, {
                "extension": self.extension, "zip_name": zip_path.name,
                "source_package": zip_path.stem, "sha256": subject["digest"]["sha256"],
            })
        report = {"schema_version": 1, "verified": True, "intent": intent,
                  "subject": subject, "claims": reports}
        run = {
            "repository": {"full_name": k3.REPOSITORY}, "path": f"{auth.CALLER}@{auth.REF}",
            "head_sha": MAIN, "head_branch": "main", "event": self.event, "id": RUN_ID, "run_attempt": 1,
            "actor": {"login": auth.OWNER, "id": auth.OWNER_ID, "type": "User"},
            "referenced_workflows": [{"sha": PIN, "path": f"{k3.REPOSITORY}/{auth.REUSABLE}@{PIN}"}],
        }
        directory = self.artifacts / f"central-claims-{self.extension}-pg{major}"
        directory.mkdir(exist_ok=True, parents=True)
        for name, content in (("audit.json", audit.audit(run, intent, report)), ("claims.json", report),
                              ("run.json", run), ("slsa.json", raw_claims[claims.SLSA]),
                              ("spdx.json", raw_claims[claims.SPDX])):
            write(directory / name, content)
        shutil.copytree(directory, self.audit_path(major).parent, dirs_exist_ok=True)

    def intent_path(self, major):
        return self.intent_dir / self.extension / str(major) / auth.INTENT_NAME

    def audit_path(self, major):
        return self.audit_dir / self.extension / str(major) / "audit.json"

    def make_signing_artifacts(self, major):
        src = self.sources[major]
        self.intents[major] = {
            **auth.FIXED_FIELDS, "extension_name": self.extension, "head_sha": MAIN, "reusable_pin_sha": PIN,
            "authentic_event": self.event, "run_id": RUN_ID, "run_attempt": 1,
            "run_invocation_uri": auth.run_uri(RUN_ID, 1), "actor_login": auth.OWNER,
            "extension_source_sha": EXTENSION_SOURCE, "publishing_allowed": False,
            "issue_comment_id": 123 if self.event == "issue_comment" else None,
            "upstream_tarball_sha256": k3.sha256(b"fixture tarball " + src["commit"].encode()),
        }
        artifact_path = self.artifacts / ARTIFACT_NAME / self.extension / str(major) / auth.INTENT_NAME
        artifact_path.parent.mkdir(parents=True)
        write(artifact_path, self.intents[major])
        shutil.copytree(self.artifacts / ARTIFACT_NAME, self.intent_dir, dirs_exist_ok=True)
        self.packages[major] = {
            "schemaVersion": 1, "buildMode": "release-attested",
            "package": {"name": self.extension, "platform": "windows", "architecture": "x64"},
            "upstream": {"repository": self.upstream, **{key: src[key] for key in ("ref", "version", "commit")}},
            "source": {"packagingRepository": k3.REPOSITORY, "packagingCommit": MAIN},
            "buildInfrastructure": {"repository": k3.REPOSITORY, "commit": PIN, "workflow": auth.REUSABLE},
            "postgresql": {"major": major, "testedVersion": f"{major}.1"},
            "workflowRun": {"id": RUN_ID, "attempt": 1, "url": auth.run_uri(RUN_ID, 1).rsplit("/attempts/", 1)[0],
                            "event": self.event, "ref": auth.REF},
        }
        self.zip_paths[major] = self.dist_dir / f"{self.extension}-{src['ref']}-pg{major}-windows-x64.zip"
        self.zip_and_audit(major)

    def verify(self, **overrides):
        inputs = {
            "extension": self.extension, "central_main_sha": MAIN, "reusable_pin_sha": PIN,
            "signing_run_id": RUN_ID, "expected_event": self.event, "raw_ticket_text": self.raw_ticket.decode(),
            "raw_inputs_bytes": self.raw_inputs, "issuance_policy": self.issuance, "dist_dir": self.dist_dir,
            "intent_dir": self.intent_dir, "audit_dir": self.audit_dir, "now": NOW,
            "central_api": self.central_api, "issuer_api": self.issuer_api,
            "ticket_base_sha": self.ticket_base if self.ticket_base != MAIN else None,
        }
        return k3.verify_central_k3_admission(**(inputs | overrides))

    def cli(self, output, **overrides):
        ticket_path, inputs_path, issuance_path = (self.root / name for name in ("ticket", "inputs", "issuance"))
        ticket_path.write_bytes(self.raw_ticket)
        inputs_path.write_bytes(self.raw_inputs)
        write(issuance_path, self.issuance)
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        fake_gh = bin_dir / "gh"
        fake_gh.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "argv = sys.argv[1:]\n"
            "assert argv[:5] == ['api', '--hostname', 'github.com', '--method', 'GET'] and len(argv) == 6\n"
            "assert 'GH_DEBUG' not in os.environ\n"
            "with open(os.environ['K3_TEST_GET_LOG'], 'a', encoding='utf-8') as log:\n"
            "    print(argv[-1], file=log)\n"
            "print(json.dumps(json.loads(Path(os.environ['K3_TEST_FACTS']).read_text())[argv[-1]]))\n",
            encoding="utf-8")
        fake_gh.chmod(0o755)
        facts = self.root / "facts.json"
        write(facts, self.central | self.issuer)
        self.gh_log = self.root / "gh-get.log"
        self.gh_log.unlink(missing_ok=True)
        args = {
            "extension": self.extension, "central-main-sha": MAIN, "reusable-pin-sha": PIN,
            "signing-run-id": RUN_ID, "expected-event": self.event, "now": TIMESTAMP, "ticket": ticket_path,
            "inputs": inputs_path, "issuance-policy": issuance_path, "dist-dir": self.dist_dir,
            "intent-dir": self.intent_dir, "audit-dir": self.audit_dir, "output": output,
        }
        if self.ticket_base != MAIN:
            args["ticket-base-sha"] = self.ticket_base
        return subprocess.run(
            [sys.executable, str(ROOT / k3.ENTRYPOINT),
             *(part for key, value in (args | overrides).items() for part in (f"--{key}", str(value)))],
            env=dict(os.environ, PATH=os.pathsep.join((str(bin_dir), os.environ["PATH"])),
                     K3_TEST_FACTS=str(facts), K3_TEST_GET_LOG=str(self.gh_log), PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, timeout=30, check=False)


class CentralK3Admission(unittest.TestCase):
    def fixture(self, **options):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name), **options)

    def reject(self, fixture, code, **arguments):
        with self.assertRaises(k3.Denied) as caught:
            fixture.verify(**arguments)
        self.assertEqual(caught.exception.code, code)

    def assert_schema(self, result):
        schema = load(k3.RESULT_SCHEMA)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)

    def test_tc01_single_upstream_and_zip_schema(self):
        fixture = self.fixture()
        result = fixture.verify()
        self.assert_schema(result)
        self.assertEqual(result["status"], k3.STATUS)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertIs(result["publishableReceipt"], False)
        self.assertEqual(result["admission"]["admittedMajors"], MAJORS)
        self.assertEqual(result["admission"]["verifiedMajors"], MAJORS)
        self.assertEqual([row["postgresqlMajor"] for row in result["zipResults"]], MAJORS)
        for row in result["zipResults"]:
            raw = fixture.zip_paths[row["postgresqlMajor"]].read_bytes()
            self.assertEqual(row["zipSha256"], k3.sha256(raw))
            self.assertEqual(row["zipSizeBytes"], len(raw))
            self.assertEqual(row["checks"], dict.fromkeys(k3.CHECKS, True))
        refs = result["canonicalReferences"]
        self.assertNotIn("ticketBaseAuthority", refs)
        self.assertEqual(fixture.central_calls[0], k3.MAIN_ENDPOINT)
        self.assertEqual(fixture.central_calls[-1], k3.MAIN_ENDPOINT)
        self.assertTrue(all(endpoint.endswith(f"?ref={MAIN}") for endpoint in fixture.central_calls[1:-1]))
        self.assertEqual(fixture.issuer_calls, list(fixture.issuer))
        for reference in refs.values():
            if "path" not in reference:
                continue
            files = fixture.central if reference["repository"] == k3.REPOSITORY else fixture.issuer
            endpoint = f"repos/{reference['repository']}/contents/{reference['path']}?ref={reference['ref']}"
            fetched = files[endpoint]
            self.assertEqual(reference["blobSha"], fetched["sha"])
            self.assertEqual(reference["contentSha256"], k3.sha256(base64.b64decode(fetched["content"])))
        bad = deepcopy(result)
        bad["zipResults"][0]["checks"]["signature"] = False
        self.assertFalse(Draft202012Validator(load(k3.RESULT_SCHEMA)).is_valid(bad))

    def test_tc02_per_series_upstream(self):
        fixture = self.fixture(extension="pgaudit", event="issue_comment")
        result = fixture.verify()
        self.assert_schema(result)
        self.assertEqual(result["principal"]["signingEvent"], "issue_comment")
        self.assertEqual(len({row["upstreamCommitSha"] for row in result["zipResults"]}), 5)
        for row in result["zipResults"]:
            major = row["postgresqlMajor"]
            source = fixture.sources[major]
            self.assertEqual((row["upstreamRef"], row["upstreamVersion"], row["upstreamCommitSha"]),
                             (source["ref"], source["version"], source["commit"]))
            self.assertEqual(row["upstreamTarballSha256"], fixture.intents[major]["upstream_tarball_sha256"])

    def test_tc03_explicit_candidate_base(self):
        fixture = self.fixture(ticket_base=BASE)
        self.reject(fixture, "K3_SHA_MISMATCH", ticket_base_sha=None)
        result = fixture.verify()
        self.assert_schema(result)
        refs = result["canonicalReferences"]
        self.assertEqual(refs["ticketBaseAuthority"]["ref"], BASE)
        self.assertEqual(refs["ticketBaseDeclaration"]["ref"], BASE)
        self.assertNotEqual(refs["ticketBaseDeclaration"]["blobSha"], refs["extensionDeclaration"]["blobSha"])
        self.assertEqual(result["shaBindings"]["manifestBlobSha"], refs["ticketBaseDeclaration"]["blobSha"])
        self.assertEqual(result["shaBindings"]["centralMainSha"], MAIN)
        self.assertEqual(result["shaBindings"]["ticketBaseSha"], BASE)

    def test_tc04_cli_pr_b5_artifact_layout_and_atomic_failure(self):
        fixture = self.fixture(ticket_base=BASE)
        # PR-B5 uploads the single shared intent tree and a flat evidence artifact per job.
        sibling = fixture.intent_dir / "pgaudit" / "15" / auth.INTENT_NAME
        sibling.parent.mkdir(parents=True)
        write(sibling, fixture.intents[15])
        caller = (ROOT / auth.CALLER).read_text(encoding="utf-8")
        for line in ('intent="intent/$EXTENSION/$PG_MAJOR/central-signed-main-intent.json"',
                     "--output-table evidence/claims.json", "--output evidence/audit.json",
                     "name: central-claims-${{ matrix.extension }}-pg${{ matrix.major }}", "path: evidence/",
                     "name: central-signed-main-intent-nonpublishing", "path: intent"):
            self.assertIn(line, caller)
        for major in MAJORS:
            artifact = fixture.artifacts / f"central-claims-{fixture.extension}-pg{major}"
            self.assertEqual({p.name for p in artifact.iterdir()}, k3.AUDIT_FILES)
            self.assertEqual(fixture.audit_path(major).read_bytes(), (artifact / "audit.json").read_bytes())
        output = fixture.root / "result.json"
        success = fixture.cli(output)
        self.assertEqual((success.returncode, success.stderr), (0, ""))
        self.assert_schema(load(output))
        self.assertEqual(load(output), fixture.verify())
        self.assertEqual(fixture.gh_log.read_text().splitlines(),
                         fixture.central_calls[:4] + fixture.issuer_calls + fixture.central_calls[4:])
        original = output.read_bytes()
        failed = fixture.cli(output, **{"audit-dir": fixture.artifacts})
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stderr), {"error_code": "K3_SIGNING_BINDING_MISMATCH"})
        self.assertEqual(output.read_bytes(), original)
        output.unlink()
        failed = fixture.cli(output, **{"signing-run-attempt": 2})
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stderr), {"error_code": "K3_SIGNING_BINDING_MISMATCH"})
        self.assertFalse(output.exists())
        link = fixture.root / "unsafe-output.json"
        link.symlink_to(fixture.root / "untouched.json")
        failed = fixture.cli(link)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stderr), {"error_code": "K3_OUTPUT_INVALID"})
        self.assertTrue(link.is_symlink())
        self.assertFalse(link.exists())
        self.assertFalse(list(fixture.root.glob(".unsafe-output.json.*")))

    def test_tc05_extension_and_target_swap(self):
        target = "K3_TARGET_EXTENSION_MISMATCH"
        for extension in ("pgaudit", "pg_bigm_extra"):
            with self.subTest(case="NK-01/NK-02", extension=extension):
                fixture = self.fixture()
                branch = f"auto-candidate/{extension}/{CANDIDATE_ID}"
                fixture.inputs["plan"].update(extension=extension, branch=branch)
                fixture.inputs["centralScope"] = k3.local_auth_central.central_scope(extension, branch)
                fixture.resign()
                self.reject(fixture, target)
        fixture = self.fixture()
        fixture.inputs["plan"]["branch"] = f"auto-candidate/pgaudit/{CANDIDATE_ID}"
        fixture.resign()
        self.reject(fixture, target)
        fixture = self.fixture()
        fixture.fleet["entries"].append(dict(fixture.fleet["entries"][-1], repository="pgextwin/PG_BIGM"))
        fixture.set_central(k3.FLEET_PATH, fixture.fleet)
        self.reject(fixture, target)
        self.reject(fixture, target, extension="con")
        for kind in ("intent", "audit", "filename", "metadata"):
            with self.subTest(case="NK-03", kind=kind):
                fixture = self.fixture()
                if kind == "intent":
                    write(fixture.intent_path(15), dict(fixture.intents[15], extension_name="pg_permissions"))
                    expected = "K3_SIGNING_BINDING_MISMATCH"
                elif kind == "audit":
                    path = fixture.audit_path(15)
                    report = load(path)
                    report["verification"]["intent"]["extension_name"] = "pg_permissions"
                    write(path, report)
                    expected = "K3_SIGNING_BINDING_MISMATCH"
                elif kind == "filename":
                    path = fixture.zip_paths[15]
                    path.rename(path.with_name(path.name.replace("pg_bigm", "pg_permissions", 1)))
                    expected = "K3_ZIP_MISSING_OR_EXTRA"
                else:
                    fixture.packages[15]["package"]["name"] = "pg_permissions"
                    fixture.zip_and_audit(15)
                    expected = "K3_ZIP_METADATA_MISMATCH"
                self.reject(fixture, expected)
        fixture = self.fixture()
        fixture.fleet["entries"] = [row for row in fixture.fleet["entries"]
                                    if row["repository"] != "pgextwin/pg_bigm"]
        fixture.set_central(k3.FLEET_PATH, fixture.fleet)
        self.reject(fixture, "K3_EXTENSION_NOT_ADMITTED")
        fixture = self.fixture(ticket_base=BASE)
        fixture.set_central(fixture.manifest, dict(fixture.declaration, name="pgaudit"))
        self.reject(fixture, "K3_DECLARATION_INVALID")

    def test_tc06_admission_series_eol_and_zip_set(self):
        fixture = self.fixture()
        fixture.admission["pg19OptIn"].remove(fixture.extension)
        fixture.set_central(k3.ADMISSION_PATH, fixture.admission)
        self.reject(fixture, "K3_PG_SERIES_NOT_ADMITTED")
        for major, code in ((14, "K3_PG_SERIES_EOL"), (20, "K3_PG_SERIES_NOT_ADMITTED")):
            with self.subTest(case="NK-06", major=major):
                fixture = self.fixture()
                fixture.inputs["sources"].append(dict(fixture.inputs["sources"][0], major=major))
                fixture.resign()
                self.reject(fixture, code)
        fixture = self.fixture(ticket_base=BASE)
        fixture.declaration["postgresql"]["majors"] = [14]
        fixture.set_central(fixture.manifest, fixture.declaration)
        self.reject(fixture, "K3_PG_SERIES_EOL")
        for rows in ([], MAJORS[:-1], [*MAJORS, 15]):
            with self.subTest(case="NK-07", rows=rows):
                fixture = self.fixture()
                fixture.inputs["sources"] = [fixture.sources[major] for major in rows]
                fixture.resign()
                self.reject(fixture, "K3_PG_SERIES_MISMATCH")
        for missing in (True, False):
            fixture = self.fixture()
            path = fixture.zip_paths[15]
            if missing:
                path.unlink()
            else:
                shutil.copyfile(path, fixture.dist_dir / "extra.zip")
            self.reject(fixture, "K3_ZIP_MISSING_OR_EXTRA")
        fixture = self.fixture()
        fixture.packages[15]["postgresql"]["major"] = 16
        fixture.zip_and_audit(15)
        self.reject(fixture, "K3_ZIP_METADATA_MISMATCH")

    def test_tc07_candidate_only_nonpublishing_and_no_j05(self):
        for operation in ("requalify", "publish"):
            with self.subTest(case="NK-09", operation=operation):
                fixture = self.fixture()
                fixture.resign(operation=operation)
                self.reject(fixture, "K3_OPERATION_NOT_ALLOWED")
                fixture = self.fixture()
                fixture.inputs["operation"] = operation
                fixture.resign()
                self.reject(fixture, "K3_OPERATION_NOT_ALLOWED")
                fixture = self.fixture()
                fixture.claim["operation"] = operation
                fixture.set_claim()
                self.reject(fixture, "K3_CLAIM_INVALID")
        fixture = self.fixture()
        fixture.set_central(k3.AUTHORITY_PATH, dict(fixture.authority, publication=True))
        self.reject(fixture, "K3_PUBLICATION_FORBIDDEN")
        fixture = self.fixture()
        fixture.inputs["centralScope"]["publication"] = True
        fixture.resign()
        self.reject(fixture, "K3_PUBLICATION_FORBIDDEN")
        for path, field in ((Fixture.intent_path, "publishing_allowed"), (Fixture.audit_path, "publishing_allowed")):
            fixture = self.fixture()
            evidence = path(fixture, 15)
            write(evidence, load(evidence) | {field: True})
            self.reject(fixture, "K3_SIGNING_BINDING_MISMATCH")
        for injected in (k3.AUTHORITY_PATH, "README.md", "extensions/pgaudit/extension.json"):
            with self.subTest(case="NK-11", path=injected):
                fixture = self.fixture()
                fixture.inputs["centralScope"]["allowedPaths"].append(injected)
                fixture.resign()
                self.reject(fixture, "K3_TARGET_EXTENSION_MISMATCH")
        fixture = self.fixture()
        fixture.authority["boundaries"]["admissionInferred"] = True
        fixture.set_central(k3.AUTHORITY_PATH, fixture.authority)
        self.reject(fixture, "K3_J05_FORBIDDEN")
        fixture = self.fixture(ticket_base=BASE)
        fixture.set_central(fixture.manifest, dict(fixture.declaration, j05=True))
        self.reject(fixture, "K3_J05_FORBIDDEN")
        fixture = self.fixture()
        fixture.inputs["plan"]["j05"] = True
        fixture.resign()
        self.reject(fixture, "K3_J05_FORBIDDEN")

    def test_tc08_authority_ticket_and_claim_windows(self):
        for field, stamp in (("delegationEndsAt", TIMESTAMP),
                             ("delegationStartsAt", "2026-11-28T15:41:00Z"),
                             ("delegationStartsAt", None), ("delegationEndsAt", None)):
            with self.subTest(case="NK-13", field=field, value=stamp):
                fixture = self.fixture()
                if stamp is None:
                    del fixture.authority[field]
                else:
                    fixture.authority[field] = stamp
                fixture.set_central(k3.AUTHORITY_PATH, fixture.authority)
                self.reject(fixture, "K3_AUTHORITY_EXPIRED_OR_OUTSIDE_WINDOW")
                self.assertEqual(fixture.issuer_calls, [])
        for changes in (
            {"expiresAt": TIMESTAMP},
            {"notBefore": "2026-11-28T15:41:01Z"},
            {"expiresAt": "2026-11-28T15:45:01Z"},
            {"notBefore": "2026-11-28T15:29:59Z"},
            {"notBefore": "2026-11-28T15:45:00Z"},
            {"expiresAt": "2026-11-28T15:29:59Z"},
        ):
            with self.subTest(case="NK-14/NK-15", changes=changes):
                fixture = self.fixture()
                fixture.resign(**changes)
                self.reject(fixture, "K3_TICKET_EXPIRED_OR_INVALID_WINDOW")
                self.assertEqual(fixture.issuer_calls, [])
        for recorded in ("2026-11-28T15:29:59Z", "2026-11-28T15:45:00Z"):
            fixture = self.fixture()
            fixture.claim["recordedAt"] = recorded
            fixture.set_claim()
            self.reject(fixture, "K3_CLAIM_INVALID")
        fixture = self.fixture()
        for bad_now in (NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=1)))):
            self.reject(fixture, "K3_INVALID_CLOCK", now=bad_now)
        self.assertEqual(fixture.central_calls, [])

    def test_tc09_ed25519_and_canonical_ticket(self):
        fixture = self.fixture()
        good = bytes.fromhex(fixture.ticket["signature"])
        other_seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        with patch.dict(rfc["test_only_sign"].__globals__, TEST_ONLY_RFC_SEED=other_seed):
            other = rfc["test_only_sign"](canonical({k: v for k, v in fixture.ticket.items() if k != "signature"}))
        for signature in (bytes([good[0] ^ 1]) + good[1:], other,
                          good[:32] + k3.ticket_verifier._L.to_bytes(32, "little"),
                          b"\x01" + bytes(31) + good[32:], bytes(32) + good[32:]):
            with self.subTest(case="NK-17", signature=signature.hex()):
                fixture.ticket["signature"] = signature.hex()
                fixture.set_ticket_bytes()
                self.reject(fixture, "K3_SIGNATURE_INVALID")
        fixture.ticket["signature"] = good.hex()
        fixture.ticket["repositoryId"] += 1
        fixture.set_ticket_bytes()
        self.reject(fixture, "K3_SIGNATURE_INVALID")
        fixture.ticket["repositoryId"] -= 1
        fixture.set_ticket_bytes()
        self.reject(fixture, "K3_SIGNATURE_INVALID", raw_ticket_text=fixture.raw_ticket.decode() + "\n")
        noncanonical = json.dumps(dict(reversed(list(fixture.ticket.items()))), separators=(",", ":"))
        self.reject(fixture, "K3_SIGNATURE_INVALID", raw_ticket_text=noncanonical)
        fixture.resign(issuerKeyId="other-key")
        self.reject(fixture, "K3_AUTHORITY_INVALID")

    def test_tc10_claim_ref_file_and_issuer_run(self):
        rejected = "K3_CLAIM_INVALID"
        for issue in ("missing", "ref-sha", "blob-sha", "ticket-sha"):
            with self.subTest(case="NK-19", issue=issue):
                fixture = self.fixture()
                if issue == "missing":
                    del fixture.issuer[fixture.claim_ref]
                elif issue == "ref-sha":
                    fixture.issuer[fixture.claim_ref]["object"]["sha"] = "0" * 40
                elif issue == "blob-sha":
                    fixture.issuer[fixture.claim_endpoint]["sha"] = "0" * 40
                else:
                    fixture.claim["ticketSha256"] = "0" * 64
                    fixture.set_claim()
                self.reject(fixture, rejected)
        for field, value in (("conclusion", "failure"), ("status", "in_progress"), ("run_attempt", 2),
                             ("event", "schedule"), ("path", ".github/workflows/other.yml"),
                             ("workflow_id", 1)):
            with self.subTest(case="NK-20", field=field):
                fixture = self.fixture()
                fixture.issuer_run[field] = value
                self.reject(fixture, rejected)
        fixture = self.fixture()
        fixture.issuance["workflowId"] += 1
        self.reject(fixture, "K3_ISSUANCE_POLICY_INVALID")
        self.assertEqual(fixture.central_calls, [])

    def test_tc11_four_ticket_shas(self):
        for field in ("policySha", "centralMainSha", "targetMainSha", "verifierSha"):
            with self.subTest(case="NK-21", field=field):
                fixture = self.fixture()
                fixture.resign(**{field: BASE})
                self.reject(fixture, "K3_SHA_MISMATCH")

    def test_tc12_manifest_blob(self):
        fixture = self.fixture()
        fixture.resign(manifestBlob="0" * 40)
        self.reject(fixture, "K3_SHA_MISMATCH")
        fixture = self.fixture(ticket_base=BASE)
        fixture.resign(manifestBlob=fixture.central[fixture.content_endpoint(fixture.manifest)]["sha"])
        self.reject(fixture, "K3_SHA_MISMATCH")

    def test_tc13_signed_input_and_upstream_pins(self):
        for field in ("inputsSha256", "upstreamSourcesSha256"):
            with self.subTest(case="NK-23", field=field):
                fixture = self.fixture()
                fixture.resign(**{field: "0" * 64})
                self.reject(fixture, "K3_SHA_MISMATCH")
        for extension in ("pg_bigm", "pgaudit"):
            fixture = self.fixture(extension=extension)
            fixture.inputs["sources"][0]["commit"] = "0" * 40
            fixture.resign()
            self.reject(fixture, "K3_SHA_MISMATCH")

    def test_tc14_signing_pin_run_and_zip_integrity(self):
        code = "K3_SIGNING_BINDING_MISMATCH"
        fixture = self.fixture()
        self.reject(fixture, "K3_SIGNING_PIN_MISMATCH", reusable_pin_sha=BASE)
        fixture.set_central_raw(auth.CALLER, b"    uses: untrusted/workflow@main\n")
        self.reject(fixture, "K3_SIGNING_PIN_MISMATCH")
        for field, value in (("head_sha", BASE), ("reusable_pin_sha", BASE),
                             ("extension_source_sha", BASE), ("run_id", RUN_ID + 1), ("run_attempt", 2),
                             ("upstream_tarball_sha256", "0" * 64)):
            with self.subTest(case="NK-24", field=field):
                fixture = self.fixture()
                write(fixture.intent_path(16), dict(fixture.intents[16], **{field: value}))
                self.reject(fixture, code)
        for field, value in (("head_sha", BASE), ("path", ".github/workflows/build-extension-attested.yml"),
                             ("id", RUN_ID + 1), ("run_attempt", 2), ("referenced_workflows", [{"sha": BASE}])):
            fixture = self.fixture()
            path = fixture.audit_path(15)
            report = load(path)
            report["run"][field] = value
            write(path, report)
            self.reject(fixture, code)
        fixture = self.fixture()
        fixture.audit_path(15).with_name("unrecognized.json").touch()
        self.reject(fixture, code)
        fixture = self.fixture()
        fixture.intent_path(20).parent.mkdir()
        self.reject(fixture, code)
        fixture = self.fixture()
        path = fixture.audit_path(15)
        original = path.rename(fixture.root / "original.json")
        path.symlink_to(original)
        self.reject(fixture, code)
        fixture = self.fixture()
        path = fixture.zip_paths[15]
        raw = path.read_bytes()
        path.write_bytes(raw[:10] + bytes([raw[10] ^ 1]) + raw[11:])
        self.reject(fixture, "K3_SHA_MISMATCH")
        fixture = self.fixture()
        path = fixture.zip_paths[15]
        target = path.rename(path.with_suffix(".other"))
        path.symlink_to(target)
        self.reject(fixture, "K3_ZIP_MISSING_OR_EXTRA")
        fixture = self.fixture()
        original_check = k3.verify_zip_metadata

        def mutate_after_check(path, *args):
            original_check(path, *args)
            path.write_bytes(path.read_bytes() + b"tampered")

        with patch.object(k3, "verify_zip_metadata", side_effect=mutate_after_check):
            self.reject(fixture, "K3_SHA_MISMATCH")

    def test_tc15_authority_absent_or_unreadable(self):
        for key in ("missing", "non-object", "blob", "json"):
            with self.subTest(case="NK-26", issue=key):
                fixture = self.fixture()
                endpoint = fixture.content_endpoint(k3.AUTHORITY_PATH)
                if key == "missing":
                    del fixture.central[endpoint]
                elif key == "non-object":
                    fixture.set_central(k3.AUTHORITY_PATH, [])
                elif key == "blob":
                    fixture.central[endpoint]["sha"] = BASE
                else:
                    fixture.set_central_raw(k3.AUTHORITY_PATH, b"{")
                self.reject(fixture, "K3_AUTHORITY_ABSENT")
                self.assertEqual(fixture.issuer_calls, [])
        fixture = self.fixture(ticket_base=BASE)
        del fixture.central[fixture.content_endpoint(k3.AUTHORITY_PATH, BASE)]
        self.reject(fixture, "K3_AUTHORITY_ABSENT")
        self.assertEqual(fixture.issuer_calls, [])

    def test_tc16_deny_has_priority_and_never_contacts_issuer(self):
        for changes, code in (
            ({"mode": "DENY", "publication": True}, "K3_AUTHORITY_DENY_MODE"),
            ({"mode": "OBSERVE"}, "K3_AUTHORITY_MODE_INVALID"),
            ({"issuerPublicKey": None}, "K3_AUTHORITY_INVALID"),
            ({"schemaVersion": True}, "K3_AUTHORITY_INVALID"),
            ({"unknown": False}, "K3_AUTHORITY_INVALID"),
        ):
            with self.subTest(case="NK-27", changes=changes):
                fixture = self.fixture(ticket_base=BASE)
                fixture.set_central(k3.AUTHORITY_PATH, fixture.authority | changes)
                self.reject(fixture, code, raw_ticket_text="invalid")
                self.assertEqual(fixture.issuer_calls, [])
                self.assertEqual(fixture.central_calls, [k3.MAIN_ENDPOINT, fixture.content_endpoint(k3.AUTHORITY_PATH)])

    def test_tc17_current_epoch_overrides_historical_ticket(self):
        for base, revoked in ((MAIN, []), (MAIN, [2]), (BASE, [2])):
            with self.subTest(case="NK-28", base=base, revoked=revoked):
                fixture = self.fixture(ticket_base=base)
                fixture.set_central(k3.AUTHORITY_PATH, dict(fixture.authority, policyEpoch=3,
                                                          revokedPolicyEpochs=revoked))
                code = "K3_AUTHORITY_EPOCH_REVOKED" if revoked else "K3_AUTHORITY_EPOCH_MISMATCH"
                self.reject(fixture, code)
                self.assertEqual(fixture.issuer_calls, [])

    def test_tc18_protected_anchor_drift_and_endpoint_allowlists(self):
        fixture = self.fixture()
        fixture.central[k3.MAIN_ENDPOINT]["protected"] = False
        self.reject(fixture, "K3_MAIN_NOT_PROTECTED")
        self.assertEqual(fixture.issuer_calls, [])
        for drift in ({"commit": {"sha": BASE}}, {"protected": False}):
            fixture = self.fixture()

            def drifted(endpoint):
                value = fixture.central_api(endpoint)
                if endpoint == k3.MAIN_ENDPOINT and fixture.central_calls.count(endpoint) == 2:
                    return value | drift
                return value

            self.reject(fixture, "K3_PROTECTED_MAIN_DRIFT", central_api=drifted)
        with patch.object(k3.subprocess, "run") as run:
            for endpoint in (
                f"{k3.CENTRAL_API}/contents/{k3.AUTHORITY_PATH}?ref=main",
                f"{k3.CENTRAL_API}/contents/extensions/con/extension.json?ref={MAIN}",
                f"{k3.CENTRAL_API}/contents/{k3.AUTHORITY_PATH}?ref={MAIN}&other=1",
                f"{k3.CENTRAL_API}/actions/runs/{RUN_ID}",
                f"https://github.com/{k3.MAIN_ENDPOINT}",
            ):
                with self.subTest(case="NK-29", endpoint=endpoint):
                    with self.assertRaisesRegex(k3.Denied, "^K3_ENDPOINT_DENIED$"):
                        k3.github_get(endpoint)
            with self.assertRaisesRegex(k3.ticket_verifier.TicketRejected, "^LIVE_ENDPOINT_DENIED$"):
                k3.live.github_get(f"{ISSUER_PREFIX}/contents/claim.json?ref=main")
            run.assert_not_called()

    def test_tc19_checked_in_pre_b9_authority_is_closed(self):
        fixture = self.fixture()
        for path in (k3.AUTHORITY_PATH, k3.FLEET_PATH, k3.ADMISSION_PATH):
            fixture.set_central_raw(path, (ROOT / path).read_bytes())
        self.assertEqual(load(ROOT / k3.AUTHORITY_PATH)["policyEpoch"], 1)
        self.assertNotIn(k3.REPOSITORY, {row["repository"] for row in load(ROOT / k3.FLEET_PATH)["entries"]})
        self.reject(fixture, "K3_AUTHORITY_TARGET_NOT_ALLOWED")
        self.assertEqual(fixture.issuer_calls, [])
        self.assertNotIn(fixture.content_endpoint(k3.ADMISSION_PATH), fixture.central_calls)

    def test_tc20_legacy_admission_does_not_verify_k3(self):
        for case, expected in (
            ("authority absent", "K3_AUTHORITY_ABSENT"), ("authority denied", "K3_AUTHORITY_DENY_MODE"),
            ("ticket expired", "K3_TICKET_EXPIRED_OR_INVALID_WINDOW"), ("signature broken", "K3_SIGNATURE_INVALID"),
            ("claim absent", "K3_CLAIM_INVALID"), ("epoch revoked", "K3_AUTHORITY_EPOCH_REVOKED"),
        ):
            with self.subTest(case="NK-30", failure=case):
                fixture = self.fixture()
                if case == "authority absent":
                    del fixture.central[fixture.content_endpoint(k3.AUTHORITY_PATH)]
                elif case == "authority denied":
                    fixture.set_central(k3.AUTHORITY_PATH, dict(fixture.authority, mode="DENY"))
                elif case == "ticket expired":
                    fixture.resign(expiresAt=TIMESTAMP)
                elif case == "signature broken":
                    fixture.ticket["signature"] = "0" * 128
                    fixture.set_ticket_bytes()
                elif case == "claim absent":
                    del fixture.issuer[fixture.claim_ref]
                else:
                    fixture.set_central(k3.AUTHORITY_PATH, dict(fixture.authority, revokedPolicyEpochs=[2]))
                self.assertEqual(legacy.protected_admission(
                    lambda endpoint: fixture.central_api(f"{k3.CENTRAL_API}/{endpoint}")),
                    identity.parse_admission(canonical(fixture.admission)))
                self.reject(fixture, expected)

    def test_tc21_p5_and_ci_router(self):
        paths = [k3.ENTRYPOINT, "schema/central-k3-admission-result.schema.json"]
        for path in paths:
            self.assertEqual(k3.local_auth_central.classify_central_path(path), ("P5", None))
        smoke = router.PILOT_SMOKE_EXTENSIONS
        result = router.route_changes([{"filename": path, "status": "added"} for path in paths],
                                      registered=router.registered_extensions(), smoke=smoke)
        self.assertEqual(result["targets"], sorted(smoke))
        self.assertEqual(result["resolver_conclusion"], "success")

    def test_tc22_github_contents_integrity(self):
        for corruption in ({"sha": BASE}, {"content": "%%%invalid"}, {"size": 1}, {"size": None},
                           {"type": "symlink"}, {"target": "file.json"}, {"path": "file.json"},
                           b'{"schemaVersion":1,"schemaVersion":1}', b'{"schemaVersion":NaN}',
                           b'{"schemaVersion":1e999}'):
            with self.subTest(corruption=corruption):
                fixture = self.fixture()
                if isinstance(corruption, dict):
                    fixture.central[fixture.content_endpoint(k3.AUTHORITY_PATH)].update(corruption)
                else:
                    fixture.set_central_raw(k3.AUTHORITY_PATH, corruption)
                self.reject(fixture, "K3_AUTHORITY_ABSENT")
                self.assertEqual(fixture.issuer_calls, [])


if __name__ == "__main__":
    unittest.main()
