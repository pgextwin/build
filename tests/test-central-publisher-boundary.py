#!/usr/bin/env python3
"""F21-07 TC-01–24 and NP-01–32. All GitHub operations use local fixtures."""

from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from datetime import date
import hashlib
from importlib import import_module
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
c = import_module("central-publisher-contract")
intake = import_module("central-publisher-intake")
runner = import_module("central-publisher-run")
manifest = import_module("central-publisher-t0-t3-manifest")
previous = runpy.run_path(str(ROOT / "tests/test-central-k3-admission.py"))
K3Fixture = previous["Fixture"]
K3Fixture.__init__.__globals__["PIN"] = c.PIN
NOW, MAIN, SIGNING_RUN = (previous[key] for key in ("NOW", "MAIN", "RUN_ID"))
CATALOG_COMMIT = "c" * 40
RELEASE_ID = 112233
PUBLISHER_RUN = 7654321
SAMPLE_DIR = os.environ.get("CENTRAL_PUBLISHER_SAMPLE_DIR")


def read(path):
    return json.loads(path.read_bytes())


def write(path, data):
    path.write_bytes(c.json_bytes(data))
    return path


class Fixture:
    def __init__(self, directory):
        self.directory = directory
        self.k3 = K3Fixture(directory)
        ext = self.k3.extension
        self.request = {"ext": ext, "pg": 17, "sha": MAIN, "run": SIGNING_RUN, "attempt": 1,
                        "tag": c.release_tag(self.k3.declaration, 3)}
        self.tag = self.request["tag"]
        self.encoded = self.tag.replace("/", "%2F")
        self.signing_endpoint = f"{c.REPO}/actions/runs/{SIGNING_RUN}"
        self.ref_endpoint = f"git/ref/tags/{self.encoded}"
        self.release_endpoint = f"releases/tags/{self.encoded}"
        self.inventory = "releases?per_page=100&page=1"
        self.comment = "/pgextwin publish-central " + " ".join(
            f"{key}={value}" for key, value in self.request.items())
        commenter = {"login": c.trigger.OWNER, "id": c.trigger.OWNER_ID, "type": "User"}
        notice = {"id": 456, "user": commenter, "author_association": "OWNER", "body": self.comment,
                  "issue_url": f"https://api.github.com/{c.REPO}/issues/311",
                  "created_at": previous["TIMESTAMP"], "updated_at": previous["TIMESTAMP"]}
        issue = {"number": 311, "state": "open"}
        repo = {"full_name": c.REPOSITORY}
        self.event = {"action": "created", "repository": repo, "sender": commenter,
                      "issue": issue, "comment": notice}
        event_file = write(directory / "event.json", self.event)
        self.env = {
            "GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REPOSITORY": c.REPOSITORY,
            "GITHUB_EVENT_PATH": str(event_file), "GITHUB_REF": c.auth.REF,
            "GITHUB_ACTOR": c.trigger.OWNER, "GITHUB_ACTOR_ID": str(c.trigger.OWNER_ID),
            "GITHUB_TRIGGERING_ACTOR": c.trigger.OWNER, "GITHUB_SHA": MAIN,
            "GITHUB_WORKFLOW_SHA": MAIN, "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": f"{c.REPOSITORY}/{c.trigger.WORKFLOW}@{c.auth.REF}",
            "GITHUB_RUN_ID": str(PUBLISHER_RUN), "GITHUB_OUTPUT": str(directory / "outputs"),
        }
        k3_fleet = self.k3.fleet
        for row in k3_fleet["entries"]:
            if row["repository"] == c.REPOSITORY:
                row["reason"] = "Central Publisher enabled"
            if row["repository"] == f"pgextwin/{ext}":
                row["reason"] = "Central publication enabled"
        self.k3.set_central(c.k3.FLEET_PATH, k3_fleet)
        self.args = SimpleNamespace(
            trigger_comment=self.comment, expected_protected_sha=MAIN,
            fleet_config=write(directory / "fixture-fleet.json", k3_fleet),
            intent_dir=self.k3.intent_dir, unsigned_dir=self.k3.artifacts,
            signed_dir=self.k3.artifacts, claims_dir=self.k3.artifacts,
            ticket=directory / "ticket.json", inputs=directory / "inputs.json",
            issuance_policy=write(directory / "issuer-policy.json", self.k3.issuance),
            out_duplicate_observation=directory / "central-duplicate-observation.json",
            out_plan=directory / "plan.json", plan=directory / "plan.json",
            recovery_file=directory / "central-publisher-recovery.json",
            out_manifest=directory / "central-zip-t0-t3-manifest.json",
            phase="prepare", cli_receipt=None, catalog_commit=None, skip_release_publish=False)
        self.args.ticket.write_bytes(self.k3.raw_ticket)
        self.args.inputs.write_bytes(self.k3.raw_inputs)
        self.release = None
        self.other_release = None
        self.ref = None
        self.calls = []
        self.token_log = []
        self.writes = []
        self.files = {}
        self.failure = None
        self.race = False
        self.attestations = []
        self.downloads = []
        self.archives = {}
        for pg in self.k3.sources:
            self.add_attestation_fixture(pg)
        sample_run = read(self.claim_dir(17) / "run.json") | {"status": "completed", "conclusion": "success"}
        self.k3.central.update({f"{c.REPO}/issues/comments/456": deepcopy(notice),
                                f"{c.REPO}/issues/311": deepcopy(issue),
                                self.signing_endpoint: deepcopy(sample_run),
                                self.signing_endpoint + "/attempts/1": deepcopy(sample_run)})

    def claim_dir(self, pg):
        return self.k3.artifacts / c.artifact_names(self.request["ext"], pg)[2]

    def add_attestation_fixture(self, pg):
        unsigned, signed, claims = (self.k3.artifacts / name for name in
                                    c.artifact_names(self.request["ext"], pg))
        path = self.k3.zip_paths[pg]
        digest = c.package.sha256_file(path)
        sbom = {"spdxVersion": "SPDX-2.3", "name": path.stem,
                "creationInfo": {"creators": ["Tool: syft-1.54.1"]},
                "documentDescribes": ["SPDXRef-Archive"],
                "packages": [{"SPDXID": "SPDXRef-Archive", "name": path.stem,
                              "supplier": "Organization: pgextwin",
                              "versionInfo": self.k3.sources[pg]["version"],
                              "checksums": [{"algorithm": "SHA256", "checksumValue": digest}]}]}
        for folder in (unsigned, signed):
            folder.mkdir()
            shutil.copyfile(path, folder / path.name)
            write(folder / (path.stem + ".spdx.json"), sbom)
        slsa, spdx = read(claims / "slsa.json"), read(claims / "spdx.json")
        spdx[0]["verificationResult"]["statement"]["predicate"] = sbom
        write(claims / "spdx.json", spdx)
        for kind in ("slsa", "spdx"):
            write(signed / f"{kind}.sigstore.json", {"fixture": kind})
        report = c.audit.verify.verify_claims(path, signed / (path.stem + ".spdx.json"), slsa, spdx,
                                                self.k3.intents[pg], "schedule", major=pg)
        write(claims / "claims.json", report)
        write(claims / "audit.json", c.audit.audit(read(claims / "run.json"), self.k3.intents[pg], report))

    def use_artifact_downloads(self):
        for number, path in enumerate(sorted(self.k3.artifacts.iterdir()), 100):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                for child in sorted(path.rglob("*")):
                    if child.is_file():
                        archive.write(child, child.relative_to(path).as_posix())
            data = output.getvalue()
            self.archives[path.name] = (
                {"name": path.name, "id": number, "expired": False, "size_in_bytes": len(data),
                 "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                 "workflow_run": {"id": SIGNING_RUN, "head_branch": "main", "head_sha": MAIN}}, data)
        self.args.intent_dir = self.args.unsigned_dir = self.args.signed_dir = self.args.claims_dir = None

    def archive(self, endpoint, destination):
        number = int(endpoint.split("/")[-2])
        self.downloads.append(number)
        destination.write_bytes(next(data for row, data in self.archives.values() if row["id"] == number))

    def get(self, endpoint, *, missing=False):
        self.calls.append(endpoint)
        if endpoint.startswith(self.signing_endpoint + "/artifacts?"):
            name = parse_qs(urlsplit(endpoint).query)["name"][0]
            row, _ = self.archives[name]
            return {"total_count": 1, "artifacts": [deepcopy(row)]}
        if endpoint.startswith(f"{c.REPO}/") and endpoint not in self.k3.central:
            path = endpoint.removeprefix(f"{c.REPO}/")
            if path == self.ref_endpoint:
                result = self.ref
            elif path == self.release_endpoint:
                result = self.release if self.release and not self.release["draft"] else None
            elif path == f"releases/{RELEASE_ID}":
                result = self.release
            elif path == self.inventory:
                result = [row for row in (self.release, self.other_release) if row is not None]
            else:
                raise AssertionError(endpoint)
            if result is None and not missing:
                raise AssertionError(endpoint)
            return deepcopy(result)
        return self.k3.central_api(endpoint)

    def attest(self, zip_path, sbom, signed, intent, major):
        self.attestations.append(major)
        with patch.object(c.subprocess, "run") as gh:
            gh.side_effect = lambda command, **_: SimpleNamespace(
                stdout=(self.claim_dir(major) / f"{Path(command[command.index('--bundle') + 1]).name.split('.')[0]}.json").read_bytes())
            result = c.verify_attestations(zip_path, sbom, signed, intent, major)
        if gh.call_count != 2:
            raise AssertionError("SLSA and SPDX must both be checked")
        return result

    def issue(self, action=intake.intake):
        issuer_api = SimpleNamespace(get=self.k3.issuer_api)
        return action(self.args, self, issuer_api, self.env, now=NOW, attestation_check=self.attest)

    def prepare(self):
        self.issue()
        result = self.issue(runner.run_phase)
        self.env["CENTRAL_PUBLISHER_PREPARED_SHA256"] = c.digest(result)
        self.args.phase = "publish"
        return result

    def existing_ref(self):
        return {"ref": "refs/tags/" + self.tag, "object": {"type": "commit", "sha": MAIN}}

    @contextmanager
    def mint(self, fleet, key, env):
        self.token_log.append("mint")
        if self.race:
            self.ref = self.existing_ref()
        try:
            yield "fixture-token"
        finally:
            self.token_log.append("revoke")

    def writer_get(self, path, *, release_page=False):
        result = self.get(f"{c.REPO}/{path}", missing=not release_page)
        return (result, False) if release_page else result

    def writer_command(self, *command):
        if command[:3] == ("gh", "release", "download"):
            path = Path(command[command.index("--dir") + 1])
            name = command[command.index("--pattern") + 1]
            (path / name).write_bytes(self.files[name])
            return
        self.writes.append(command[:4])
        if self.failure:
            raise self.failure
        if command[:4] == ("gh", "api", "-X", "POST"):
            self.ref = self.existing_ref()
        elif command[:3] == ("gh", "release", "create"):
            folder = Path(command[4]).parent
            self.files = {path.name: path.read_bytes() for path in folder.iterdir()}
            self.release = self.make_release(self.files, draft=True)
            self.release["body"] = Path(command[command.index("--notes-file") + 1]).read_text()
        elif command[:4] == ("gh", "api", "-X", "PATCH"):
            self.release["draft"] = False
        else:
            raise AssertionError(command)

    def make_release(self, files, *, draft=False):
        return {"tag_name": self.tag, "id": RELEASE_ID, "draft": draft, "target_commitish": MAIN,
                "html_url": f"https://github.com/{c.REPOSITORY}/releases/tag/{self.encoded}",
                "published_at": previous["TIMESTAMP"],
                "assets": [{"id": i, "name": name, "size": len(data), "state": "uploaded",
                            "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
                           for i, (name, data) in enumerate(sorted(files.items()), 20)]}

    def publish(self):
        self.env["PUBLISHER_PRIVATE_KEY"] = "fixture-only"
        with patch.object(runner.writer, "get", side_effect=self.writer_get), \
             patch.object(runner.writer, "run", side_effect=self.writer_command), redirect_stdout(io.StringIO()):
            return runner.run_phase(self.args, self, SimpleNamespace(get=self.k3.issuer_api), self.env,
                                    now=NOW, attestation_check=self.attest, mint=self.mint)

    def receipt(self, document):
        return {"schemaVersion": "pgextwin-cli-batch-download/v1", "releaseMetadataVerified": False,
                **manifest.RECEIPT_CONSTANTS, "zipCount": len(document["entries"]),
                "packages": [{"extension": row["extension"], "pgMajor": str(row["pgMajor"]),
                              "relativePath": f"pg{row['pgMajor']}/{row['fileName']}", "bytes": row["size"],
                              "sha256": row["sha256"], "releaseTag": document["od01Tag"],
                              "catalogCommit": CATALOG_COMMIT, "repositoryId": 43,
                              "releaseId": row["release"]["releaseId"], "assetId": row["release"]["assetId"]}
                             for row in reversed(document["entries"])]}


class Boundary(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)

    def fixture(self, name="fixture"):
        directory = self.directory / name
        directory.mkdir()
        return Fixture(directory)

    def denied(self, code, action, *args):
        with self.assertRaises(c.Denied) as error:
            action(*args)
        self.assertEqual(error.exception.code, code)

    def sample(self, source, name):
        if SAMPLE_DIR:
            shutil.copyfile(source, Path(SAMPLE_DIR) / name)

    def assert_observation(self, f, kind):
        value = read(f.args.out_duplicate_observation)
        self.assertEqual(value["observationKind"], kind)
        self.assertEqual(value["tokenMinted"], kind != c.PREWRITE)
        self.assertEqual(value["writerAbsentDenied"], kind == c.WRITER)
        unknown = kind == c.UNKNOWN
        self.assertEqual(value["writeAttempted"], unknown)
        self.assertEqual(value["recoveryJsonGenerated"], unknown)
        self.assertEqual(f.args.recovery_file.exists(), unknown)
        self.assertEqual(value["unchangedAfterDenial"], not unknown)
        self.assertEqual(c.digest(value["beforeGet"]), value["beforeGetSha256"])
        self.assertEqual(c.digest(value["afterGet"]), value["afterGetSha256"])
        if not unknown:
            self.assertEqual(value["beforeGetSha256"], value["afterGetSha256"])
            self.assertIsNone(value["recoveryJsonPath"])
            self.assertEqual(f.writes, [])
        self.assertFalse(f.args.out_manifest.exists())
        return value

    def test_TC_01_intake_admits_protected_run_and_downloads_every_target(self):
        f = self.fixture()
        f.use_artifact_downloads()
        document = f.issue()
        self.assertEqual(document["request"], f.request)
        self.assertEqual(read(f.args.plan), document)
        self.assertEqual(set(f.attestations), set(f.k3.sources))
        self.assertEqual(len(f.downloads), 1 + 3 * len(f.k3.sources))
        self.assertGreater(len(f.k3.issuer_calls), 0)
        self.assertEqual(f.writes, [])

    def test_TC_02_rejects_legacy_and_malformed_commands(self):
        f = self.fixture()
        for case, text, expected in (
            ("NP-01", "/pgextwin publish pgvector", "CPUB_LEGACY_CONTRACT_REJECTED"),
            ("NP-02", '{"source":"external-direct"}', "CPUB_LEGACY_CONTRACT_REJECTED"),
            ("NP-02", "/pgextwin owner-source pg_bigm", "CPUB_LEGACY_CONTRACT_REJECTED"),
            ("NP-03", f.comment + " unknown=x", c.MALFORMED),
            ("NP-03", f.comment + " ext=pg_bigm", c.MALFORMED),
            ("NP-03", f.comment + "\n/pgextwin publish", c.MALFORMED),
            ("NP-03", f.comment + " && id", c.MALFORMED),
            ("NP-03", f.comment.rsplit(" ", 1)[0], c.MALFORMED),
            ("NP-03", c.PREFIX.rstrip(), c.MALFORMED),
        ):
            with self.subTest(case=case, text=text):
                self.denied(expected, c.parse_trigger, text)

    def test_TC_03_rejects_unauthorized_actor_pr_and_fork(self):
        f = self.fixture()
        for label, change in (
            ("actor", {"sender": {"login": "someone"}}),
            ("pr", {"issue": f.event["issue"] | {"pull_request": {}}}),
            ("fork", {"repository": {"full_name": "some-user/build"}}),
            ("closed", {"issue": f.event["issue"] | {"state": "closed"}}),
        ):
            with self.subTest(case="NP-04", label=label):
                write(Path(f.env["GITHUB_EVENT_PATH"]), f.event | change)
                self.denied(c.UNAUTHORIZED, f.issue)
        self.assertEqual(f.writes, [])

    def test_TC_04_rejects_extension_and_prefix_collisions(self):
        f = self.fixture()
        original_path = f.k3.intent_path(17)
        changed = read(original_path)
        write(original_path, changed | {"extension_name": "postgis"})
        self.denied(c.EXT, f.issue)  # NP-05
        write(original_path, changed)
        with TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "central-signed-pg_bigmscale-pg17"
            wrong.mkdir()
            self.denied(c.EXT, c.check_artifact_roster, Path(tmp), "signed", "pg_bigm", [17])  # NP-06
        path = f.claim_dir(17) / "claims.json"
        claims = read(path)
        claims["subject"]["name"] = "postgis-1.2-pg17-windows-x64.zip"
        write(path, claims)
        self.denied(c.EXT, f.issue)  # NP-07
        pending = self.pending(f, reuse=False)
        receipt = f.receipt(pending)
        receipt["packages"][0]["extension"] = "postgis"
        self.denied(c.EXT, manifest.attach, pending, receipt, CATALOG_COMMIT, pending["entries"])

    def test_TC_05_rejects_wrong_postgresql_major(self):
        f = self.fixture()
        self.denied(c.PG, c.intent_series, f.k3.intent_dir, f.request | {"pg": 14})  # NP-08

    def test_TC_06_rejects_live_and_artifact_attempt_substitution(self):
        f = self.fixture()
        latest = f.k3.central[f.signing_endpoint]
        latest["run_attempt"] = 2
        self.denied(c.ATTEMPT, f.issue)  # NP-09
        latest["run_attempt"] = 1
        path = f.claim_dir(17) / "run.json"
        write(path, read(path) | {"run_attempt": 2})
        self.denied(c.ATTEMPT, f.issue)  # NP-10

    def test_TC_07_rejects_wrong_run_and_unfinished_or_failed_run(self):
        f = self.fixture()
        latest = f.k3.central[f.signing_endpoint]
        for case, change in (("NP-11", {"id": 19}), ("NP-12", {"conclusion": "failure"}),
                             ("NP-12", {"status": "in_progress", "conclusion": None}),
                             ("NP-12", {"conclusion": "cancelled"})):
            with self.subTest(case=case, change=change):
                f.k3.central[f.signing_endpoint] = latest | change
                self.denied(c.RUN, f.issue)

    def test_TC_08_rejects_wrong_or_abbreviated_protected_sha(self):
        f = self.fixture()
        f.args.expected_protected_sha = "f" + MAIN[1:]
        self.denied(c.SHA, f.issue)  # NP-13
        for value in ("aabbccdd", "main", "A" * 40):
            self.denied(c.SHA, c.parse_trigger, f.comment.replace(MAIN, value))  # NP-14

    def test_TC_09_rejects_workflow_or_pin_swap_and_reexecutes_k3(self):
        f = self.fixture()
        latest = f.k3.central[f.signing_endpoint]
        for change in ({"path": ".github/workflows/other.yml"}, {"referenced_workflows": []}):
            with self.subTest(case="NP-15", change=change):
                f.k3.central[f.signing_endpoint] = latest | change
                self.denied(c.K3, f.issue)
        f.k3.central[f.signing_endpoint] = latest
        write(f.k3.artifacts / "admitted.json", {"admitted": True, "verified": True})
        f.k3.authority["policyEpoch"] += 1
        f.k3.set_central(c.k3.AUTHORITY_PATH, f.k3.authority)
        self.denied(c.K3, f.issue)  # NP-16; genuine verifier rejects the revoked epoch
        self.assertGreater(len(f.attestations), 0)

    def test_TC_10_OD01_uses_exact_legacy_suffix_and_single_url_encoding(self):
        f = self.fixture()
        c.identity.validate_release_tag(f.k3.declaration, f.tag.split("/")[1])
        self.assertEqual(f.tag, "pg_bigm/v1.2-20261118-windows.3")
        for value in ("pg_bigm_1.2_pg17", "postgis/v1.2-windows.3", "pg_bigm%2Fv1.2-windows.3",
                      "pg_bigm//v1.2-windows.3", "pg_bigm/../v1.2-windows.3"):
            with self.subTest(case="NP-17", value=value):
                self.denied(c.TAG, c.parse_trigger, f.comment.replace(f.tag, value))
        self.denied(c.TAG, c.verify_tag, f.request | {"tag": "pg_bigm/v99.2-windows.3"}, f.k3.declaration)
        c.snapshot(f, f.request, [{"pgMajor": 17}])
        self.assertIn(f"{c.REPO}/releases/tags/pg_bigm%2Fv1.2-20261118-windows.3", f.calls)
        self.assertIn(f"{c.REPO}/git/ref/tags/pg_bigm%2Fv1.2-20261118-windows.3", f.calls)
        self.assertEqual(unquote(f.encoded), f.tag)

    def test_TC_11_prepare_then_publishes_once_with_provenance_and_manifest(self):
        f = self.fixture()
        plan = f.prepare()
        self.assertEqual(f.token_log, [])
        self.assertEqual(f.writes, [])
        prepared = f.env["CENTRAL_PUBLISHER_PREPARED_SHA256"]
        f.env["CENTRAL_PUBLISHER_PREPARED_SHA256"] = "0" * 64
        self.denied(runner.PLAN, f.publish)
        self.assertEqual(f.token_log, [])
        f.env["CENTRAL_PUBLISHER_PREPARED_SHA256"] = prepared
        document = f.publish()
        self.assertEqual(f.token_log, ["mint", "revoke"])
        self.assertEqual(len(f.writes), 3)
        self.assertEqual(document["stageStatus"], manifest.PENDING)
        self.assertEqual(read(f.args.out_manifest), document)
        marker = next(line for line in f.release["body"].splitlines() if line.startswith(c.MARKER))
        self.assertEqual(json.loads(marker.removeprefix(c.MARKER)), c.provenance(f.request, plan["entries"]))
        self.assertEqual(read(f.args.recovery_file)["state"], "PUBLISHED_VERIFIED")

    def test_TC_12_route_1_duplicate_release_ref_and_distinct_tag_same_run(self):
        for label, case in (("release", "NP-18"), ("ref", "NP-19"), ("run", "NP-20")):
            with self.subTest(case=case):
                f = self.fixture(label)
                if label == "release":
                    f.release = f.make_release({})
                elif label == "ref":
                    f.ref = f.existing_ref()
                else:
                    marker = c.provenance(f.request | {"pg": 16, "tag": c.release_tag(f.k3.declaration, 1)}, [])
                    f.other_release = {"id": 3434, "tag_name": marker["od01Tag"], "draft": False,
                                       "body": c.MARKER + json.dumps(marker)}
                self.denied(f"CPUB_{c.PREWRITE}", f.issue)
                self.assert_observation(f, c.PREWRITE)
                self.assertEqual(f.token_log, [])
                self.assertFalse(f.args.plan.exists())
                if label == "release":
                    self.sample(f.args.out_duplicate_observation, "central-duplicate-observation-sample.json")
        for phase in ("prepare", "publish"):
            with self.subTest(phase=phase):
                f = self.fixture(phase)
                f.prepare()
                f.args.phase = phase
                f.ref = f.existing_ref()
                self.denied(f"CPUB_{c.PREWRITE}", f.publish)
                self.assert_observation(f, c.PREWRITE)
                self.assertEqual(f.token_log, [])

    def test_TC_13_route_2_writer_absent_denial_has_no_recovery(self):
        f = self.fixture()
        f.prepare()
        f.race = True
        with patch.object(runner.writer, "absent", wraps=runner.writer.absent) as absent:
            self.denied(f"CPUB_{c.WRITER}", f.publish)  # NP-21, NP-22
        absent.assert_called_once_with(f.tag)
        self.assert_observation(f, c.WRITER)
        self.assertEqual(f.token_log, ["mint", "revoke"])
        self.sample(f.args.out_duplicate_observation, "central-duplicate-observation-route2-sample.json")

    def test_TC_14_route_3_502_and_timeout_quarantine_without_retry(self):
        for label, error in (("http", HTTPError("https://mock.invalid", 502, "fixture", {}, None)),
                             ("timeout", subprocess.TimeoutExpired("fixture", 1))):
            with self.subTest(case="NP-23", label=label):
                f = self.fixture(label)
                f.prepare()
                f.failure = error
                self.denied(f"CPUB_{c.UNKNOWN}", f.publish)
                self.assert_observation(f, c.UNKNOWN)
                self.assertEqual(read(f.args.recovery_file)["state"], "WRITE_OUTCOME_UNKNOWN_TAG_RESERVATION")
                self.assertEqual(f.writes, [("gh", "api", "-X", "POST")])
                self.assertEqual(f.token_log, ["mint", "revoke"])
                if label == "http":
                    self.sample(f.args.out_duplicate_observation, "central-duplicate-observation-route3-sample.json")
                    self.sample(f.args.recovery_file, "central-publisher-recovery-route3-sample.json")

    def test_TC_15_writer_optional_notes_are_backward_compatible(self):
        f = self.fixture()
        args = f.directory, {"name": f.request["ext"]}, {"releaseTag": f.tag, "majors": [17]}, MAIN, {}
        results = []
        for index, options in enumerate(({}, {"extra_notes": None}, {"extra_notes": ""},
                                         {"extra_notes": "CENTRAL_MARKER fixture"})):
            recovery = f.directory / f"notes-{index}.json"
            with patch.object(runner.writer, "absent"), \
                 patch.object(runner.writer, "run", side_effect=runner.writer.Denied("fixture stop after notes")):
                with self.assertRaises(runner.writer.Denied):
                    runner.writer.publish_preverified(*args, recovery, publish_run_id=1, **options)
            results.append(recovery.with_suffix(".md").read_bytes())
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])
        self.assertEqual(results[3], results[0] + b"\nCENTRAL_MARKER fixture\n")

    def pending(self, f, majors=(16, 17), *, reuse=True):
        if reuse:
            all_rows = f.issue()["entries"]
        else:
            all_rows = []
            for major in majors:
                chain = {}
                for stage in ("T0", "T1", "T2"):
                    chain[stage] = c.package.handoff_record(stage, f.request["ext"], major,
                                                            f.k3.zip_paths[major], list(chain.values())[-1]
                                                            if chain else None)
                row = {key: chain["T2"][key] for key in ("extension", "pgMajor", "fileName", "sha256", "size")}
                all_rows.append(row | {"handoffs": chain})
        rows = [row for row in reversed(all_rows) if row["pgMajor"] in majors]
        files = {row["fileName"]: f.k3.zip_paths[row["pgMajor"]].read_bytes() for row in rows}
        return manifest.build(f.request, rows, f.make_release(files), rows)

    def test_TC_16_complete_single_and_multi_target_manifests_match_schema(self):
        f = self.fixture()
        schema = read(manifest.SCHEMA)
        manifest.Draft202012Validator.check_schema(schema)
        for majors in ((17,), (16, 17)):
            with self.subTest(majors=majors):
                pending = self.pending(f, majors)
                complete = manifest.attach(pending, f.receipt(pending), CATALOG_COMMIT, pending["entries"])
                manifest.Draft202012Validator(schema).validate(complete)
                for row in complete["entries"]:
                    actual = c.k3.zip_identity(f.k3.zip_paths[row["pgMajor"]])
                    for stage in row["handoffs"].values():
                        self.assertEqual((stage["sha256"], stage["size"]), actual)
                    self.assertEqual((row["release"]["assetSha256"], row["release"]["assetSize"]), actual)
                    self.assertEqual((row["cliReceipt"]["sha256"], row["cliReceipt"]["bytes"]), actual)

    def test_TC_17_cli_attaches_receipt_and_verifies_deterministic_output(self):
        f = self.fixture()
        rows = [row for row in f.issue()["entries"] if row["pgMajor"] in (16, 17)]
        expected = write(f.directory / "expected.json", rows)
        handoffs = write(f.directory / "handoff.json", list(reversed(rows)))
        release = write(f.directory / "release.json", f.make_release({
            row["fileName"]: f.k3.zip_paths[row["pgMajor"]].read_bytes() for row in rows}))
        path = f.args.out_manifest
        common = ["--manifest", str(path), "--expected-targets-json", str(expected)]
        self.assertEqual(manifest.main(["--mode", "build", *common, "--trigger-comment", f.comment,
                                        "--handoff-metadata", str(handoffs), "--release-metadata", str(release)]), 0)
        first_bytes = path.read_bytes()
        pending = read(path)
        self.assertEqual(pending["stageStatus"], manifest.PENDING)
        self.assertEqual([row["pgMajor"] for row in pending["entries"]], [16, 17])
        receipt = write(f.directory / "DOWNLOAD-INFO.json", f.receipt(pending))
        attach = ["--mode", "attach-cli-receipt", *common, "--cli-receipt", str(receipt),
                  "--catalog-commit", CATALOG_COMMIT, "--require-complete"]
        self.assertEqual(manifest.main(attach), 0)
        complete_bytes = path.read_bytes()
        path.write_bytes(first_bytes)
        self.assertEqual(manifest.main(attach), 0)
        self.assertEqual(path.read_bytes(), complete_bytes)
        self.assertEqual(manifest.main(["--mode", "verify", *common, "--require-complete"]), 0)
        self.sample(path, "central-zip-t0-t3-manifest-sample.json")

    def test_TC_18_missing_surplus_or_duplicate_target_rejected(self):
        f = self.fixture()
        pending = self.pending(f)
        expected = pending["entries"]
        self.denied(manifest.INCOMPLETE, manifest.validate, pending, expected + [["pg_bigm", 18, "other.zip"]])  # NP-24
        self.denied(manifest.INCOMPLETE, manifest.validate, pending, expected[:1])  # NP-25
        for packages in ([], f.receipt(pending)["packages"][:1],
                         [f.receipt(pending)["packages"][0]] * 2):
            receipt = f.receipt(pending) | {"packages": packages}
            self.denied(manifest.INCOMPLETE, manifest.attach, pending, receipt, CATALOG_COMMIT, expected)

    def test_TC_19_handoff_release_and_cli_must_match_same_bytes(self):
        f = self.fixture()
        pending = self.pending(f)
        for container, key, value in (("T0", "size", 1), ("T1", "previousSha256", "0" * 64),
                                      ("T2", "sha256", "0" * 64), ("release", "assetSha256", "0" * 64),
                                      ("release", "assetSize", 1)):
            with self.subTest(case="NP-26", stage=container, key=key):
                changed = deepcopy(pending)
                row = changed["entries"][0]
                target = row["release"] if container == "release" else row["handoffs"][container]
                target[key] = value
                self.denied(manifest.MISMATCH, manifest.validate, changed, pending["entries"])
        for key, value in (("sha256", "0" * 64), ("bytes", 1)):
            receipt = f.receipt(pending)
            receipt["packages"][0][key] = value
            self.denied(manifest.MISMATCH, manifest.attach, pending, receipt, CATALOG_COMMIT, pending["entries"])  # NP-27

    def test_TC_20_rejects_missing_ids_and_invalid_catalog_receipt(self):
        f = self.fixture()
        pending = self.pending(f)
        for key, value in (("releaseId", None), ("assetId", 0), ("assetId", True)):
            changed = deepcopy(pending)
            changed["entries"][0]["release"][key] = value
            self.denied(manifest.INCOMPLETE, manifest.validate, changed, pending["entries"])  # NP-28
        for key, value in [("source", "unknown"), ("verificationLevel", "AUTHORIZED"),
                           *[(flag, True) for flag in manifest.RECEIPT_FLAGS], ("signatureVerified", 0)]:
            receipt = f.receipt(pending) | {key: value}
            self.denied(manifest.INCOMPLETE, manifest.attach, pending, receipt, CATALOG_COMMIT, pending["entries"])  # NP-29
        for key, value in (("relativePath", "../other.zip"), ("releaseId", 1), ("assetId", 1),
                           ("releaseTag", "wrong"), ("catalogCommit", "d" * 40)):
            receipt = f.receipt(pending)
            receipt["packages"][0][key] = value
            self.denied(manifest.INCOMPLETE, manifest.attach, pending, receipt, CATALOG_COMMIT, pending["entries"])

    def test_TC_21_missing_bundle_and_corrupt_zip_rejected(self):
        f = self.fixture()
        folder = f.k3.artifacts / c.artifact_names(f.request["ext"], 17)[1]
        bundle = folder / "slsa.sigstore.json"
        data = bundle.read_bytes()
        bundle.unlink()
        self.denied(c.LAYOUT, f.issue)
        bundle.write_bytes(data)
        with (folder / f.k3.zip_paths[17].name).open("ab") as archive:
            archive.write(b"tamper")
        self.denied(c.LAYOUT, f.issue)  # NP-30

    def test_TC_22_checked_in_fleet_fails_before_minting_or_writing(self):
        f = self.fixture()
        f.prepare()
        f.args.fleet_config = ROOT / c.k3.FLEET_PATH
        self.denied(c.POLICY, f.publish)  # NP-31
        self.assertEqual(f.token_log, [])
        self.assertEqual(f.writes, [])
        self.assertFalse(f.args.recovery_file.exists())

    def test_TC_23_pg14_eol_uses_explicit_reference_dates(self):
        f = self.fixture()
        self.assertIn(14, c.identity.maintained_majors(f.k3.declaration, f.k3.lifecycle, date(2026, 11, 12)))
        self.assertNotIn(14, c.identity.maintained_majors(f.k3.declaration, f.k3.lifecycle, date(2026, 11, 13)))
        self.assertEqual(f.issue()["entries"][0]["pgMajor"], 15)

    def test_TC_24_security_rules_protect_combo_6_and_pin_actions(self):
        checker = runpy.run_path(str(ROOT / "tests/test-github-actions-security.py"))
        check = checker["central_publisher_errors"]
        path = ROOT / ".github/workflows/publisher-candidate-intake.yml"
        raw = path.read_bytes()
        self.assertEqual(check(raw), [])
        unsafe = (raw.replace(b"  isolated_external_direct_catalog_pr:", b"  renamed_combo:"),
                  raw.replace(b"  isolated_owner_source_formal_publisher:", b"  renamed_owner:"),
                  raw.replace(b"central-publisher-intake-formal", b"central-publisher-intake"),
                  raw.replace(b"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
                              b"        with:\n          name: central-publisher-plan",
                              b"actions/download-artifact@v8\n        with:\n          name: central-publisher-plan"))
        for changed in unsafe:
            with self.subTest(case="NP-32"):
                self.assertNotEqual(changed, raw)
                self.assertTrue(check(changed))
        self.assertIn(str(manifest.SCHEMA.relative_to(ROOT)), c.k3.local_auth_central.P5_FILES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
