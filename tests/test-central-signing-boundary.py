"""Offline CB-70 boundary fixtures. No test requests an OIDC token or signs a ZIP."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import importlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
auth = importlib.import_module("central-signing-auth")
claims = importlib.import_module("verify-central-attestation-claims")
audit = importlib.import_module("central-signed-main-audit")

PACKAGING = "a" * 40
PIN = "b" * 40
EXTENSION_SOURCE = "c" * 40
TARBALL = "d" * 64
UPSTREAM = "e" * 40
EXTENSION = "pg_bigm"
REPOSITORY = "pgextwin/build"
RUN_ID = 123456789
RUN_URL = f"https://github.com/pgextwin/build/actions/runs/{RUN_ID}"
INVOCATION = f"{RUN_URL}/attempts/1"
CONFIG_URI = "https://github.com/pgextwin/build/.github/workflows/central-signed-main.yml@refs/heads/main"
SIGNER_URI = f"https://github.com/pgextwin/build/.github/workflows/central-extension-attested.yml@{PIN}"


class CentralSigningBoundary(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.intent = {
            "schema_version": 1,
            "mode": "m1-central-live-signing-nonpublishing",
            "repository": REPOSITORY,
            "caller_workflow_path": ".github/workflows/central-signed-main.yml",
            "reusable_workflow_path": ".github/workflows/central-extension-attested.yml",
            "reusable_pin_sha": PIN,
            "authentic_event": "schedule",
            "actor_login": "ShutenOishi",
            "head_ref": "refs/heads/main",
            "head_sha": PACKAGING,
            "run_id": RUN_ID,
            "run_attempt": 1,
            "run_invocation_uri": INVOCATION,
            "extension_name": EXTENSION,
            "extension_source_sha": EXTENSION_SOURCE,
            "upstream_tarball_sha256": TARBALL,
            "issue_comment_id": None,
            "publishing_allowed": False,
        }
        self.zip = self.work / "pg_bigm-v1.2-pg17-windows-x64.zip"
        meta = {
            "buildMode": "release-attested",
            "package": {"name": EXTENSION},
            "source": {"packagingRepository": REPOSITORY, "packagingCommit": PACKAGING},
            "buildInfrastructure": {
                "repository": REPOSITORY,
                "commit": PIN,
                "workflow": ".github/workflows/central-extension-attested.yml",
            },
            "workflowRun": {
                "id": RUN_ID, "attempt": 1, "url": RUN_URL, "event": "schedule", "ref": "refs/heads/main",
            },
            "upstream": {"repository": "pgbigm/pg_bigm", "ref": "v1.2", "version": "1.2", "commit": UPSTREAM},
            "postgresql": {"major": 17},
        }
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("PACKAGE-INFO.json", json.dumps(meta))
            archive.writestr("central-signed-main-intent.json", json.dumps(self.intent))
        self.sha = hashlib.sha256(self.zip.read_bytes()).hexdigest()
        self.sbom = self.work / f"{self.zip.stem}.spdx.json"
        self.sbom_content = {
            "spdxVersion": "SPDX-2.3",
            "name": self.zip.stem,
            "creationInfo": {"creators": ["Tool: syft-1.54.1"]},
            "packages": [{
                "SPDXID": "SPDXRef-Archive",
                "name": self.zip.stem,
                "versionInfo": "1.2",
                "supplier": "Organization: pgextwin",
                "checksums": [{"algorithm": "SHA256", "checksumValue": self.sha}],
            }],
            "relationships": [{
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Archive",
            }],
        }
        auth.write_json(self.sbom, self.sbom_content)
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "buildSignerURI": SIGNER_URI,
            "subjectAlternativeName": SIGNER_URI,
            "buildSignerDigest": PIN,
            "runInvocationURI": INVOCATION,
            "buildConfigURI": CONFIG_URI,
            "buildConfigDigest": PACKAGING,
            "sourceRepositoryURI": "https://github.com/pgextwin/build",
            "sourceRepositoryDigest": PACKAGING,
            "sourceRepositoryRef": "refs/heads/main",
            "githubWorkflowSHA": PACKAGING,
            "githubWorkflowRef": "refs/heads/main",
            "buildTrigger": "schedule",
        }
        verified = {
            "signature": {"certificate": cert},
            "verifiedTimestamps": [{"type": "Tlog", "timestamp": "2026-11-28T14:00:00Z"}],
            "statement": {"subject": [{"name": self.zip.name, "digest": {"sha256": self.sha}}]},
        }
        self.slsa = [{"verificationResult": deepcopy(verified)}]
        self.spdx = [{"attestation": {"bundle": {}}, "verificationResult": deepcopy(verified)}]
        self.statement(self.slsa).update(
            predicateType="https://slsa.dev/provenance/v1",
            predicate={
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "externalParameters": {"workflow": {
                        "repository": "https://github.com/pgextwin/build",
                        "ref": "refs/heads/main",
                        "path": ".github/workflows/central-signed-main.yml",
                    }},
                },
                "runDetails": {"metadata": {"invocationId": INVOCATION}, "builder": {"id": SIGNER_URI}},
            },
        )
        self.statement(self.spdx).update(
            predicateType="https://spdx.dev/Document/v2.3", predicate=deepcopy(self.sbom_content),
        )
        self.run_json = {
            "id": RUN_ID, "path": ".github/workflows/central-signed-main.yml@refs/heads/main",
            "head_branch": "main", "head_sha": PACKAGING, "event": "schedule",
            "actor": {"login": "ShutenOishi", "id": 27071164, "type": "User"},
            "repository": {"full_name": REPOSITORY}, "run_attempt": 1,
            "referenced_workflows": [{
                "path": f"pgextwin/build/.github/workflows/central-extension-attested.yml@{PIN}",
                "sha": PIN,
            }],
        }
        self.event = self.work / "event.json"
        self.env = {
            "GITHUB_EVENT_PATH": str(self.event),
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": PACKAGING,
            "GITHUB_WORKFLOW_SHA": PACKAGING,
            "GITHUB_WORKFLOW_REF": "pgextwin/build/.github/workflows/central-signed-main.yml@refs/heads/main",
            "GITHUB_RUN_ID": str(RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_ACTOR": "ShutenOishi",
            "GITHUB_ACTOR_ID": "27071164",
            "M1_JOB_WORKFLOW_SHA": PIN,
            "M1_JOB_WORKFLOW_REPOSITORY": REPOSITORY,
            "M1_EXTENSION": EXTENSION,
            "M1_MAJOR": "17",
            "M1_EXTENSION_SOURCE_SHA": EXTENSION_SOURCE,
            "M1_PACKAGING_SHA": PACKAGING,
            "M1_REUSABLE_PIN_SHA": PIN,
            "M1_UPSTREAM_TARBALL_SHA256": TARBALL,
            "M1_CALLER_RUN_ID": str(RUN_ID),
            "M1_CALLER_RUN_ATTEMPT": "1",
            "M1_CALLER_EVENT": "schedule",
            "M1_AUTH_ARTIFACT": "central-signed-main-intent-nonpublishing",
            "M1_BUILD_CONFIG_URI": CONFIG_URI,
            "M1_SIGNER_URI": SIGNER_URI,
        }
        self.schedule = {"schedule": "23 3 * * *"}
        self.comment = {
            "action": "created",
            "repository": {"full_name": REPOSITORY},
            "issue": {"number": 311},
            "comment": {
                "id": 790,
                "user": {"login": "ShutenOishi", "id": 27071164, "type": "User"},
                "author_association": "OWNER",
                "body": "/pgextwin sign-main pg_bigm",
            },
        }
        auth.write_json(self.event, self.schedule)

    @staticmethod
    def statement(results):
        return results[0]["verificationResult"]["statement"]

    @staticmethod
    def certificate(results):
        return results[0]["verificationResult"]["signature"]["certificate"]

    def compare(self, **changes):
        return claims.verify_claims(**{
            "zip_path": self.zip, "sbom_path": self.sbom, "slsa": self.slsa,
            "spdx": self.spdx, "intent": self.intent, "expected_event": "schedule",
            **changes,
        })

    def denied(self, code, operation, *args, **kwargs):
        with self.assertRaises(auth.Denied) as context:
            operation(*args, **kwargs)
        self.assertEqual(code, context.exception.code)

    def change_certificate(self, ns, key, value, code):
        for predicate, original in (("slsa", self.slsa), ("spdx", self.spdx)):
            with self.subTest(case=ns, predicate=predicate, claim=key):
                results = deepcopy(original)
                self.certificate(results)[key] = value
                self.denied(code, self.compare, **{predicate: results})

    def test_tc01_permissions_pins_and_ns36(self):
        caller = (ROOT / auth.CALLER).read_text()
        reusable = (ROOT / auth.REUSABLE).read_text()
        with redirect_stdout(io.StringIO()):
            policy = runpy.run_path(str(ROOT / "tests/test-github-actions-security.py"))
        check = policy["central_signing_errors"]
        upload = policy["upload_v7"].group(1)
        self.assertEqual([], check(caller, reusable, upload))
        changes = (
            ("  contents: read", "  contents: read\n  issues: write"),
            ("permissions:\n", "permissions: write-all\nreplaced_permissions:\n"),
            ("on:\n", "on:\n  pull_request_target:\n"),
        )
        for before, after in changes:
            for index, source in enumerate((caller, reusable)):
                with self.subTest(case="NS-36", change=after, document=index):
                    mutant = source.replace(before, after, 1)
                    self.assertNotEqual(source, mutant)
                    documents = [caller, reusable]
                    documents[index] = mutant
                    self.assertTrue(check(*documents, upload))

    def test_tc02_caller_pin_names_an_existing_reusable_commit(self):
        sha = auth.read_caller_pin(ROOT)
        self.assertRegex(sha, r"^[a-f0-9]{40}$")
        self.assertEqual("commit", auth.git(ROOT, "cat-file", "-t", sha))
        pinned = subprocess.check_output(["git", "show", f"{sha}:{auth.REUSABLE}"], cwd=ROOT)
        self.assertEqual((ROOT / auth.REUSABLE).read_bytes(), pinned)
        caller = yaml.load((ROOT / auth.CALLER).read_text(), Loader=yaml.BaseLoader)
        invoke = caller["jobs"]["invoke_central_signer"]
        self.assertNotIn("secrets", invoke)
        self.assertEqual(f"{REPOSITORY}/{auth.REUSABLE}@{sha}", invoke["uses"])
        with self.subTest(case="NS-11"):
            self.denied(auth.BAD_SHA, auth.validate_intent, {**self.intent, "reusable_pin_sha": "main"})

    def test_tc03_reusable_trigger_and_single_subject_paths(self):
        workflow = yaml.load((ROOT / auth.REUSABLE).read_text(), Loader=yaml.BaseLoader)
        self.assertEqual({"workflow_call"}, set(workflow["on"]))
        jobs = workflow["jobs"]
        self.assertEqual("package", jobs["attest"]["needs"])
        steps = [step for step in jobs["attest"]["steps"] if step.get("uses", "").startswith("actions/attest@")]
        self.assertEqual(["slsa", "spdx"], [step["id"] for step in steps])
        for step in steps:
            self.assertEqual("${{ steps.subject.outputs.zip }}", step["with"]["subject-path"])
        self.assertEqual("${{ steps.subject.outputs.sbom }}", steps[1]["with"]["sbom-path"])

    def test_tc04_independent_sha_fields(self):
        auth.validate_intent(self.intent)
        self.assertEqual(4, len({PACKAGING, PIN, EXTENSION_SOURCE, TARBALL}))
        for misplaced in (EXTENSION_SOURCE, PIN):
            self.change_certificate("NS-09", "sourceRepositoryDigest", misplaced,
                                    "CLAIMS_SOURCE_REPO_MISMATCH")
        for key, value in (("head_sha", TARBALL), ("upstream_tarball_sha256", PACKAGING)):
            with self.subTest(case="NS-10", claim=key):
                self.denied(auth.BAD_SHA, auth.validate_intent, {**self.intent, key: value})
        for name, value in (("M1_EXTENSION_SOURCE_SHA", PIN), ("M1_UPSTREAM_TARBALL_SHA256", "e" * 64),
                            ("M1_JOB_WORKFLOW_SHA", PACKAGING)):
            self.denied(auth.BAD_SHA, auth.verify_runtime, self.intent, {**self.env, name: value})

    def test_tc05_authentic_events_and_zero_target_noop(self):
        auth.verify_runtime(self.intent, self.env)
        auth.write_json(self.event, self.comment)
        env = {**self.env, "GITHUB_EVENT_NAME": "issue_comment", "M1_CALLER_EVENT": "issue_comment"}
        run, extension = auth.verify_trigger(env)
        self.assertEqual(EXTENSION, extension)
        self.assertEqual(790, run["issue_comment_id"])
        intent_dir = self.work / "intent"
        ext = self.work / "extensions" / EXTENSION
        ext.mkdir(parents=True)
        auth.write_json(ext / "extension.json", {"upstream": {"repository": "pgbigm/pg_bigm"}})
        with (patch.object(auth, "git", return_value=PACKAGING),
              patch.object(auth, "declared_extensions", return_value=[EXTENSION]),
              patch.object(auth, "extension_source", return_value=EXTENSION_SOURCE),
              patch.object(auth, "extension_dir", return_value=ext),
              patch.object(auth, "read_caller_pin", return_value=PIN),
              patch.object(auth, "matrix_rows", return_value=[{"major": 17, "upstreamCommit": UPSTREAM}]),
              patch.object(auth, "upstream_digest", return_value=TARBALL)):
            outputs = auth.emit_intents(self.work, intent_dir, env)
        self.assertEqual("true", outputs["has_targets"])
        self.assertEqual(auth.ARTIFACT_NAME, outputs["auth_artifact_name"])
        emitted = auth.load_intent(intent_dir / EXTENSION / "17" / auth.INTENT_NAME)
        self.assertFalse(emitted["publishing_allowed"])
        self.assertEqual(INVOCATION, emitted["run_invocation_uri"])
        auth.verify_runtime(emitted, env)

        auth.write_json(self.event, self.schedule)
        checkout = self.work / "checkout"
        checkout.mkdir()
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "empty"],
                       check=True)
        head = auth.git(checkout, "rev-parse", "HEAD")
        output_dir = self.work / "empty-intent"
        with patch.object(auth, "read_caller_pin", return_value=PIN):
            empty = auth.emit_intents(checkout, output_dir, {
                **self.env, "GITHUB_SHA": head, "GITHUB_WORKFLOW_SHA": head,
            })
        self.assertEqual("false", empty["has_targets"])
        self.assertEqual({"include": []}, json.loads(empty["matrix"]))
        self.assertFalse(output_dir.exists())
        caller = yaml.load((ROOT / auth.CALLER).read_text(), Loader=yaml.BaseLoader)
        self.assertEqual([{"cron": self.schedule["schedule"]}], caller["on"]["schedule"])
        for job in ("invoke_central_signer", "verify_central_claims"):
            self.assertEqual("needs.authenticate_and_prepare.outputs.has_targets == 'true'",
                             caller["jobs"][job]["if"])

    def test_tc06_rejects_forged_triggers_and_intents(self):
        for name in ("workflow_dispatch", "push", "pull_request", "pull_request_target",
                     "workflow_run", "repository_dispatch"):
            with self.subTest(case="NS-01" if name == "workflow_dispatch" else "NS-02", event=name):
                self.denied("AUTH_EVENT_NOT_ALLOWED", auth.verify_trigger,
                            {**self.env, "GITHUB_EVENT_NAME": name})
        for issue in ({"number": 310}, {"number": 311, "pull_request": {}}):
            with self.subTest(case="NS-03", issue=issue):
                auth.write_json(self.event, {**self.comment, "issue": issue})
                self.denied("AUTH_ISSUE_NOT_CENTRAL_311", auth.verify_trigger,
                            {**self.env, "GITHUB_EVENT_NAME": "issue_comment"})
        for claim, value in (("login", "other"), ("id", 42), ("type", "Bot")):
            with self.subTest(case="NS-04", claim=claim):
                payload = deepcopy(self.comment)
                payload["comment"]["user"][claim] = value
                auth.write_json(self.event, payload)
                self.denied("AUTH_ACTOR_NOT_OWNER", auth.verify_trigger,
                            {**self.env, "GITHUB_EVENT_NAME": "issue_comment"})
        payload = deepcopy(self.comment)
        payload["comment"]["author_association"] = "MEMBER"
        auth.write_json(self.event, payload)
        self.denied("AUTH_ACTOR_NOT_OWNER", auth.verify_trigger,
                    {**self.env, "GITHUB_EVENT_NAME": "issue_comment"})
        for body in ("/pgextwin sign-main pg_bigm\nextra", "/pgextwin sign-main ../pg_bigm"):
            payload = deepcopy(self.comment)
            payload["comment"]["body"] = body
            auth.write_json(self.event, payload)
            self.denied("AUTH_COMMAND_INVALID", auth.verify_trigger,
                        {**self.env, "GITHUB_EVENT_NAME": "issue_comment"})
        auth.write_json(self.event, self.schedule)
        for ns, key, value, code in (
            ("NS-05", "GITHUB_REF", "refs/heads/feature", "AUTH_REF_NOT_MAIN"),
            ("NS-06", "GITHUB_RUN_ID", str(RUN_ID + 1), "AUTH_RUN_ID_MISMATCH"),
            ("NS-07", "GITHUB_RUN_ATTEMPT", "2", "AUTH_RUN_ATTEMPT_MISMATCH"),
        ):
            with self.subTest(case=ns):
                self.denied(code, auth.verify_runtime, self.intent, {**self.env, key: value})
        with self.subTest(case="NS-08"):
            self.denied(auth.INVALID_INTENT, auth.load_intent, self.work / auth.INTENT_NAME)
            self.denied(auth.INVALID_INTENT, auth.validate_intent, {**self.intent, "unknown": "extra"})
            self.denied("AUTH_PUBLISHING_FORBIDDEN", auth.validate_intent,
                        {**self.intent, "publishing_allowed": True})
            self.denied(auth.INVALID_INTENT, auth.validate_intent, {**self.intent, "schema_version": True})

    def test_tc07_finalizer_executes_central_guard_and_preserves_legacy_contract(self):
        finalizer = (ROOT / "scripts/finalize-package.ps1").read_text()
        guard = finalizer.split('if ($PackagingRepository -ceq "pgextwin/build")', 1)[1]
        central, legacy = guard.split('elseif ($WorkflowEvent -eq "issue_comment")', 1)
        self.assertIn("scripts/central-signing-auth.py", central)
        self.assertRegex(central, r"--verify-finalizer")
        self.assertIn('if ($LASTEXITCODE -ne 0)', central)
        self.assertIn("scripts/finalize-owner-source.py", legacy)
        self.assertIn('"workflow_dispatch", "push"', legacy)

        intent_path = self.work / auth.INTENT_NAME
        auth.write_json(intent_path, self.intent)
        command = [
            sys.executable, str(ROOT / "scripts/central-signing-auth.py"), "--verify-finalizer",
            "--intent", str(intent_path), "--event", str(self.event), "--repository", REPOSITORY,
            "--extension", EXTENSION, "--workflow-event", "schedule", "--run-id", str(RUN_ID),
            "--run-attempt", "1", "--ref", "refs/heads/main", "--run-url", RUN_URL,
            "--packaging-sha", PACKAGING, "--reusable-pin-sha", PIN, "--reusable-workflow", auth.REUSABLE,
        ]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        for event in ("workflow_dispatch", "push", "pull_request", "pull_request_target"):
            with self.subTest(event=event):
                result = subprocess.run(command, env={**self.env, "GITHUB_EVENT_NAME": event},
                                        capture_output=True, text=True)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertEqual("AUTH_EVENT_NOT_ALLOWED", json.loads(result.stderr)["error_code"])
        command[command.index("--run-id") + 1] = str(RUN_ID + 1)
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual(auth.INVALID_INTENT, json.loads(result.stderr)["error_code"])

    def test_tc08_one_zip_subject_per_predicate(self):
        for predicate, original in (("slsa", self.slsa), ("spdx", self.spdx)):
            for case, subjects in (
                ("NS-31", [{"name": self.zip.name, "digest": {"sha256": self.sha}},
                           {"name": "other.zip", "digest": {"sha256": self.sha}}]),
                ("NS-33", [{"name": "other.zip", "digest": {"sha256": self.sha}}]),
                ("NS-33", [{"name": self.zip.name, "digest": {"sha256": "a" * 64}}]),
                ("NS-33", [{"name": self.zip.name, "digest": {"sha256": self.sha, "sha1": "a" * 40}}]),
            ):
                with self.subTest(case=case, predicate=predicate):
                    results = deepcopy(original)
                    self.statement(results)["subject"] = subjects
                    self.denied(claims.SUBJECT, self.compare, **{predicate: results})

    def test_tc09_both_predicates_emit_the_complete_table(self):
        report = self.compare(major=17, upstream_repository="pgbigm/pg_bigm", upstream_commit=UPSTREAM)
        self.assertTrue(report["verified"])
        self.assertEqual(self.intent, report["intent"])
        for kind, rows in report["claims"].items():
            self.assertEqual(list(range(1, 22)), [row["number"] for row in rows])
            self.assertEqual(19, sum(row["status"] == "match" for row in rows))
            self.assertEqual(self.sha, rows[16]["expected"][0]["digest"]["sha256"])
            self.assertIn(kind, (claims.SLSA, claims.SPDX))
        for number, reason in [(18, claims.SLSA), (20, claims.SPDX)]:
            row = report["claims"][reason][number - 1]
            self.assertEqual(reason, row["actual"]["predicateType"])
        self.assertFalse(audit.audit(self.run_json, self.intent, report)["publishing_allowed"])

    def test_tc10_signer_path_and_commit(self):
        for ns, key, value, code in (
            ("NS-12", "buildSignerURI", SIGNER_URI.replace("central-extension", "build-extension"),
             "CLAIMS_SIGNER_URI_MISMATCH"),
            ("NS-13", "buildSignerURI", SIGNER_URI.replace(PIN, PACKAGING), "CLAIMS_SIGNER_URI_MISMATCH"),
            ("NS-13", "buildSignerURI", SIGNER_URI.replace(PIN, auth.REF), "CLAIMS_SIGNER_URI_MISMATCH"),
            ("NS-14", "buildSignerDigest", PACKAGING, "CLAIMS_SIGNER_DIGEST_MISMATCH"),
        ):
            self.change_certificate(ns, key, value, code)

    def test_tc11_san_issuer_and_legacy_claim(self):
        self.change_certificate("NS-15", "subjectAlternativeName", CONFIG_URI, "CLAIMS_SAN_MISMATCH")
        self.change_certificate("NS-16", "issuer", "https://example.invalid", "CLAIMS_ISSUER_MISMATCH")
        self.change_certificate("NS-17", "runnerInvocationURI", INVOCATION,
                                "CLAIMS_LEGACY_RUNNER_URI_FORBIDDEN")

    def test_tc12_build_config_and_source_identity(self):
        for ns, key, value, code in (
            ("NS-18", "buildConfigURI", CONFIG_URI.replace("main", "feature"), "CLAIMS_BUILD_CONFIG_MISMATCH"),
            ("NS-19", "buildConfigDigest", PIN, "CLAIMS_BUILD_CONFIG_MISMATCH"),
            ("NS-20", "sourceRepositoryURI", "https://github.com/fork/build", "CLAIMS_SOURCE_REPO_MISMATCH"),
            ("NS-21", "sourceRepositoryDigest", "f" * 40, "CLAIMS_SOURCE_REPO_MISMATCH"),
            ("NS-05", "sourceRepositoryRef", "refs/heads/feature", "CLAIMS_SOURCE_REPO_MISMATCH"),
            ("NS-22", "githubWorkflowSHA", PIN, "CLAIMS_WORKFLOW_SHA_REF_MISMATCH"),
            ("NS-22", "githubWorkflowRef", "refs/heads/feature", "CLAIMS_WORKFLOW_SHA_REF_MISMATCH"),
            ("NS-23", "buildTrigger", "workflow_dispatch", "CLAIMS_TRIGGER_MISMATCH"),
        ):
            self.change_certificate(ns, key, value, code)
        self.denied("CLAIMS_TRIGGER_MISMATCH", self.compare, expected_event="issue_comment")

    def test_tc13_verified_timestamps_and_exact_envelopes(self):
        for predicate, original in (("slsa", self.slsa), ("spdx", self.spdx)):
            for timestamp in ([], [{}], {"timestamp": "2026-11-28"}):
                with self.subTest(case="NS-24", predicate=predicate, timestamp=timestamp):
                    results = deepcopy(original)
                    results[0]["verificationResult"]["verifiedTimestamps"] = timestamp
                    self.denied("CLAIMS_TIMESTAMPS_MISSING", self.compare, **{predicate: results})
            missing = deepcopy(original)
            del missing[0]["verificationResult"]["verifiedTimestamps"]
            self.denied("CLAIMS_TIMESTAMPS_MISSING", self.compare, **{predicate: missing})
            for invalid in (original * 2, [{**original[0], "unknown": None}]):
                with self.subTest(case="NS-25", predicate=predicate):
                    self.denied(claims.ENVELOPE, self.compare, **{predicate: invalid})

    def test_tc14_both_predicates_required(self):
        with self.subTest(case="NS-26"):
            self.denied(claims.ENVELOPE, self.compare, slsa=None)
        self.denied(claims.ENVELOPE, self.compare, spdx=[])

    def test_tc15_slsa_predicate_and_workflow(self):
        for field in ("predicateType", "buildDefinition", "builder", "externalParameters"):
            with self.subTest(case="NS-27", missing_or_bad=field):
                results = deepcopy(self.slsa)
                statement = self.statement(results)
                predicate = statement["predicate"]
                if field == "predicateType":
                    statement[field] = claims.SPDX
                elif field == "buildDefinition":
                    del predicate[field]
                elif field == "builder":
                    del predicate["runDetails"][field]
                else:
                    predicate["buildDefinition"][field]["workflow"]["ref"] = "refs/heads/feature"
                self.denied(claims.SLSA_INVALID, self.compare, slsa=results)
        optional = deepcopy(self.slsa)
        del self.statement(optional)["predicate"]["buildDefinition"]["externalParameters"]
        self.assertTrue(self.compare(slsa=optional)["verified"])

    def test_tc16_slsa_invocation_and_both_certificates_bind_run_attempt(self):
        for ns, uri in (("NS-06", INVOCATION.replace(str(RUN_ID), str(RUN_ID + 1))),
                        ("NS-07", f"{RUN_URL}/attempts/2")):
            self.change_certificate(ns, "runInvocationURI", uri, "CLAIMS_RUN_INVOCATION_MISMATCH")
            with self.subTest(case="NS-28", invocation=uri):
                results = deepcopy(self.slsa)
                self.statement(results)["predicate"]["runDetails"]["metadata"]["invocationId"] = uri
                self.denied("CLAIMS_RUN_INVOCATION_MISMATCH", self.compare, slsa=results)

    def test_tc17_valid_slsa_cannot_cover_invalid_spdx_certificate(self):
        for field, value, code in (
            ("buildSignerURI", CONFIG_URI, "CLAIMS_SIGNER_URI_MISMATCH"),
            ("buildTrigger", "issue_comment", "CLAIMS_TRIGGER_MISMATCH"),
            ("runInvocationURI", f"{RUN_URL}/attempts/2", "CLAIMS_RUN_INVOCATION_MISMATCH"),
        ):
            with self.subTest(case="NS-29", claim=field):
                results = deepcopy(self.spdx)
                self.certificate(results)[field] = value
                self.denied(code, self.compare, spdx=results)

    def test_tc18_spdx_kind_version_and_local_equality(self):
        for field in ("predicateType", "spdxVersion", "name"):
            with self.subTest(case="NS-30", claim=field):
                results = deepcopy(self.spdx)
                statement = self.statement(results)
                if field == "predicateType":
                    statement[field] = claims.SLSA
                else:
                    statement["predicate"][field] = "incorrect"
                self.denied(claims.SPDX_MISMATCH, self.compare, spdx=results)

    def test_tc19_zip_and_sbom_must_belong_to_the_intended_extension(self):
        with self.subTest(case="NS-32"):
            self.denied(claims.CROSS, self.compare, intent={**self.intent, "extension_name": "pg_permissions"})
        for key in ("extension_source_sha", "upstream_tarball_sha256"):
            with self.subTest(binding=key):
                self.denied(claims.CROSS, self.compare, intent={**self.intent, key: "f" * len(self.intent[key])})
        self.denied(claims.CROSS, self.compare, major=18)
        self.denied(claims.CROSS, self.compare, upstream_repository="pgbigm/pg_bigm",
                    upstream_commit="f" * 40)

    def test_tc20_audit_run_and_verified_claims_report(self):
        report = self.compare()
        result = audit.audit(self.run_json, self.intent, report)
        self.assertEqual(INVOCATION, result["run"]["run_invocation_uri"])
        plain_path = deepcopy(self.run_json)
        plain_path["referenced_workflows"][0] = {
            "path": f"{REPOSITORY}/{auth.REUSABLE}", "sha": PIN, "ref": PIN,
        }
        self.assertEqual(report, audit.audit(plain_path, self.intent, report)["verification"])
        for references in (
            [], [{"path": f"{REPOSITORY}/{auth.REUSABLE}", "sha": PACKAGING}],
            [{**self.run_json["referenced_workflows"][0], "ref": PACKAGING}],
            self.run_json["referenced_workflows"] + [{"path": "other", "sha": PIN}],
        ):
            with self.subTest(case="NS-34", references=references):
                self.denied("AUDIT_REFERENCED_WORKFLOW_MISMATCH", audit.audit,
                            {**self.run_json, "referenced_workflows": references}, self.intent, report)
        for field, value, code in (
            ("head_sha", EXTENSION_SOURCE, "AUDIT_RUN_HEAD_SHA_MISMATCH"),
            ("head_branch", "feature", "AUDIT_RUN_HEAD_SHA_MISMATCH"),
            ("path", auth.REUSABLE, "AUDIT_RUN_PATH_MISMATCH"),
            ("event", "issue_comment", "AUDIT_RUN_EVENT_MISMATCH"),
            ("actor", {"login": "other"}, "AUDIT_RUN_ACTOR_MISMATCH"),
            ("id", RUN_ID + 1, "AUDIT_RUN_ID_MISMATCH"),
            ("run_attempt", 2, "AUDIT_RUN_ATTEMPT_MISMATCH"),
        ):
            with self.subTest(case="NS-35", field=field):
                self.denied(code, audit.audit, {**self.run_json, field: value}, self.intent, report)
        report["claims"][claims.SPDX].pop()
        self.denied(audit.BAD_CLAIMS, audit.audit, self.run_json, self.intent, report)

    def test_tc21_existing_verifier_misses_the_new_boundary(self):
        output = self.work / "spdx-verified.json"
        for case in ("NS-26", "NS-31", "NS-12"):
            with self.subTest(case=case):
                fixture = deepcopy(self.spdx)
                slsa = self.slsa
                if case == "NS-26":
                    slsa = []
                    code = claims.ENVELOPE
                elif case == "NS-31":
                    self.statement(fixture)["subject"].append({"name": "other.zip", "digest": {"sha256": self.sha}})
                    code = claims.SUBJECT
                else:
                    self.certificate(fixture)["buildSignerURI"] = CONFIG_URI
                    code = "CLAIMS_SIGNER_URI_MISMATCH"
                auth.write_json(output, fixture)
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/verify-sbom-attestation.py"),
                     "--verification-json", str(output), "--sbom", str(self.sbom), "--zip", str(self.zip)],
                    capture_output=True, text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.denied(code, self.compare, spdx=fixture, slsa=slsa)

    def test_tc22_p5_and_selective_ci_routing(self):
        local_auth = importlib.import_module("local_auth_central")
        router = importlib.import_module("ci-router")
        paths = [auth.CALLER, auth.REUSABLE]
        for path in paths:
            self.assertEqual(("P5", None), local_auth.classify_central_path(path))
        result = router.route_changes([{"filename": path, "status": "added"} for path in paths],
                                      registered=router.PILOT_SMOKE_EXTENSIONS,
                                      smoke=router.PILOT_SMOKE_EXTENSIONS)
        self.assertEqual("success", result["resolver_conclusion"])
        self.assertEqual(set(router.PILOT_SMOKE_EXTENSIONS), set(result["targets"]))


if __name__ == "__main__":
    unittest.main()
