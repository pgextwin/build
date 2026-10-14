#!/usr/bin/env python3
"""PRE-G4 wholly synthetic signatures/API: hostile joins must DENY."""
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pre_g4_attempt", ROOT / "scripts/issue-75-attempt-provenance-readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REPO = "pgextwin/plpgsql_check"
PACKAGING = "37cb5ee00f556fd6b57e439a5e19cd210125a571"
UPSTREAM = "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911"
RUN_ID = 38128142145
MAJORS = (14, 15, 16, 17, 18)
URI = f"https://github.com/{REPO}/actions/runs/{RUN_ID}/attempts/1"


def archive(pkg):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as z:
        z.writestr("PACKAGE-INFO.json", json.dumps(pkg))
    return buffer.getvalue()


class AttemptBoundaryTests(TestCase):
    def setUp(self):
        self.packages = {}
        self.sboms = {}
        self.zips = {}
        self.proofs = {}
        self.run = {"id": RUN_ID, "run_attempt": 1, "head_sha": PACKAGING,
                    "head_branch": "main", "event": "workflow_dispatch",
                    "path": m.PROMOTE_PATH, "repository": {"full_name": REPO},
                    "status": "completed", "conclusion": "failure"}
        for pg in MAJORS:
            self.packages[pg] = {
                "buildMode": "release-attested", "package": {"name": "plpgsql_check"},
                "postgresql": {"major": pg},
                "source": {"packagingRepository": REPO, "packagingCommit": PACKAGING},
                "upstream": {"commit": UPSTREAM},
                "buildInfrastructure": {"repository": "pgextwin/build",
                    "workflow": m.SIGNER_PATH, "commit": m.SIGNER_SHA},
                "workflowRun": {"id": RUN_ID, "attempt": 1,
                    "url": f"https://github.com/{REPO}/actions/runs/{RUN_ID}",
                    "event": "workflow_dispatch", "ref": "refs/heads/main"}}
            self.sboms[pg] = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}
        self.rebuild()

    def rebuild(self):
        for pg in MAJORS:
            self.zips[pg] = archive(self.packages[pg])
            digest = sha256(self.zips[pg]).hexdigest()
            cert = {"issuer": m.ISSUER, "runnerInvocationURI": URI,
                "sourceRepositoryURI": "https://github.com/" + REPO,
                "sourceRepositoryDigest": PACKAGING,
                "sourceRepositoryRef": "refs/heads/main",
                "buildSignerURI": "https://github.com/pgextwin/build/" + m.SIGNER_PATH + "@refs/heads/main",
                "buildSignerDigest": m.SIGNER_SHA,
                "buildTrigger": "workflow_dispatch"}
            prov = {"buildDefinition": {"buildType": "fixture"},
                    "runDetails": {"builder": {"id": "https://github.com/actions/runner"},
                        "metadata": {"invocationId": URI}}}
            self.proofs[pg] = {}
            for kind, value in ((m.PROVENANCE, prov), (m.SPDX, self.sboms[pg])):
                self.proofs[pg][kind] = [{"verificationResult": {
                    "statement": {"predicateType": kind,
                        "subject": [{"name": f"plpgsql_check-pg{pg}-windows-x64.zip",
                            "digest": {"sha256": digest}}],
                        "predicate": deepcopy(value)},
                    "signature": {"certificate": deepcopy(cert)},
                    "verifiedTimestamps": [{"fixture": "NOT A SIGNATURE"}]}}]

    def check(self, **kwargs):
        return m.inspect_offline(self.zips, self.sboms, self.proofs, self.run,
                                 repo=REPO, packaging_sha=PACKAGING,
                                 upstream_sha=UPSTREAM, **kwargs)

    def test_nominal_mock_remains_blocked_no_receipt(self):
        result = self.check()
        self.assertEqual(result["decision"], "BLOCKED")
        self.assertEqual(result["attemptBinding"], "NOT_CRYPTOGRAPHICALLY_ATTESTED")
        self.assertFalse(result["publishableReceipt"])
        self.assertFalse(result["mutationsEnabled"])
        self.assertEqual(result["publication"], "DENY")
        self.assertEqual(set(result["zipSha256ByMajor"]), set(map(str, MAJORS)))

    def test_missing_null_boolean_zero_string_and_wrong_attempt(self):
        for bad in ("ABSENT", None, False, True, 0, "1", 2):
            with self.subTest(value=bad):
                self.setUp()
                if bad == "ABSENT":
                    del self.packages[14]["workflowRun"]["attempt"]
                else:
                    self.packages[14]["workflowRun"]["attempt"] = bad
                self.rebuild()
                with self.assertRaises(m.Deny): self.check()

    def test_pg_major_run_id_or_attempt_mixing(self):
        for field, value in (("id", RUN_ID + 1), ("attempt", 2)):
            with self.subTest(field=field):
                self.setUp()
                self.packages[18]["workflowRun"][field] = value
                self.rebuild()
                with self.assertRaises(m.Deny): self.check()

    def test_api_run_id_attempt_sha_branch_event_path_repository(self):
        for field, value in (
            ("id", RUN_ID + 1), ("run_attempt", 2), ("run_attempt", False),
            ("head_sha", "0" * 40), ("head_branch", "topic"),
            ("event", "push"), ("path", ".github/workflows/windows.yml"),
            ("repository", {"full_name": "evil/repo"}), ("status", "queued")):
            with self.subTest(field=field, value=value):
                self.setUp()
                self.run[field] = value
                with self.assertRaises(m.Deny): self.check()

    def test_package_upstream_packaging_builder_sha_event_ref(self):
        for section, key, value in (
            ("source", "packagingCommit", "0" * 40),
            ("upstream", "commit", "1" * 40),
            ("buildInfrastructure", "commit", "2" * 40),
            ("buildInfrastructure", "workflow", ".github/workflows/forged.yml"),
            ("workflowRun", "event", "push"),
            ("workflowRun", "ref", "refs/heads/evil"),
            ("workflowRun", "url", "https://example.test/fake")):
            with self.subTest(section=section, key=key):
                self.setUp()
                self.packages[14][section][key] = value
                self.rebuild()
                with self.assertRaises(m.Deny): self.check()

    def test_bad_certificate_oidc_signer_run_attempt_source(self):
        for key, value in (
            ("issuer", "https://evil.test"),
            ("runnerInvocationURI", URI[:-1] + "2"),
            ("sourceRepositoryURI", "https://github.com/evil/repo"),
            ("sourceRepositoryDigest", "f" * 40),
            ("sourceRepositoryRef", "refs/heads/evil"),
            ("buildSignerURI", "https://github.com/evil/forged.yml"),
            ("buildSignerDigest", "f" * 40),
            ("buildTrigger", "push")):
            with self.subTest(key=key):
                self.setUp()
                self.proofs[14][m.PROVENANCE][0]["verificationResult"]["signature"]["certificate"][key] = value
                with self.assertRaises(m.Deny): self.check()
        for missing in ("signature", "verifiedTimestamps"):
            with self.subTest(missing=missing):
                self.setUp()
                del self.proofs[14][m.SPDX][0]["verificationResult"][missing]
                with self.assertRaises(m.Deny): self.check()

    def test_wrong_zip_digest_slsa_invocation_spdx_predicate_missing_proof(self):
        for label in ("digest", "slsa", "spdx", "empty", "tamper"):
            with self.subTest(label=label):
                self.setUp()
                if label == "digest":
                    self.proofs[14][m.PROVENANCE][0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
                if label == "slsa":
                    self.proofs[14][m.PROVENANCE][0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = URI + "/forged"
                if label == "spdx":
                    self.proofs[14][m.SPDX][0]["verificationResult"]["statement"]["predicate"] = {"spdxVersion": "SPDX-2.3"}
                if label == "empty":
                    self.proofs[14][m.SPDX] = []
                if label == "tamper":
                    self.zips[14] += b"tampered"
                with self.assertRaises(m.Deny): self.check()

    def test_api_401_403_429_500_timeout_missing_and_toctou(self):
        for exc in (PermissionError("401"), PermissionError("403"),
                    RuntimeError("429"), OSError("500"), TimeoutError("timeout")):
            with self.subTest(exception=exc):
                with self.assertRaises(m.Unavailable):
                    m.fetch_twice(lambda _: (_ for _ in ()).throw(exc), RUN_ID)
        with self.assertRaises(m.Deny):
            m.fetch_twice(lambda _: None, RUN_ID)
        snapshots = iter([self.run, {**self.run, "run_attempt": 2}])
        with self.assertRaises(m.Deny):
            m.fetch_twice(lambda _: next(snapshots), RUN_ID)
        paths = []
        result = m.fetch_twice(lambda path: paths.append(path) or deepcopy(self.run), RUN_ID)
        self.assertEqual(result, self.run)
        self.assertEqual(paths, ["actions/runs/" + str(RUN_ID)] * 2)


if __name__ == "__main__":
    main()
