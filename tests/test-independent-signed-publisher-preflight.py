#!/usr/bin/env python3
"""Hostile offline second-job equality tests; fixtures are not signatures."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = load("independent_signed_publisher_check",
            "scripts/independent-signed-publisher-preflight.py")
sample = load("nonpublishing_signed_bridge_fixtures",
              "tests/test-automatic-publisher-bridge.py")
FLOW = (ROOT / ".github/workflows/verify-signed-candidate-readonly.yml").read_text("utf-8")
MAJORS = [14, 15, 16, 17, 18]


def fixture(name="pg_ivm"):
    a = deepcopy(sample.fixture()["audit"])
    a["repository"] = "pgextwin/" + name
    ext = {"schemaVersion": 1, "name": name,
           "postgresql": {"majors": MAJORS},
           "upstream": {"repository": gate.identity.UPSTREAMS[name],
                        "ref": "v1.2-20250903" if name == "pg_bigm" else "v1.0",
                        "version": "1.2" if name == "pg_bigm" else "1.0",
                        "commit": "b" * 40}}
    lc = {"schemaVersion": 1, "postgresql": [
        {"major": m, "eol": "2035-12-31"} for m in MAJORS]}
    return {"first": a, "second": deepcopy(a),
            "repo": "pgextwin/" + name, "sha": sample.SHA,
            "run_id": sample.RUN_ID, "attempt": sample.ATTEMPT,
            "manifest": ext, "lifecycle": lc,
            "event": "push", "ref": "refs/heads/main"}


class IndependentSecondOpinion(unittest.TestCase):
    def test_17_clean_shapes_remain_nonpublishing(self):
        for name in gate.identity.UPSTREAMS:
            with self.subTest(name=name):
                r = gate.compare(**fixture(name))
                self.assertEqual(r["status"],
                                 "INDEPENDENT_SIGNED_RECHECK_MATCH_NONPUBLISHING")
                self.assertEqual(r["maintainedMajors"], MAJORS)
                self.assertIs(r["assetByteDigestsMatch"], True)
                for key in ("publishableReceipt", "publicationAuthorized",
                            "automaticReleaseEnabled", "publisherWriteEnabled"):
                    self.assertIs(r[key], False)
                self.assertEqual((r["goB"], r["g4"], r["g5"]),
                                 ("NO_GO", "NO_GO", "NO_GO"))
                for forbidden in ("authorizationMode", "operator", "releaseTag",
                                  "GH_TOKEN", "receipt"):
                    self.assertNotIn(forbidden, r)

    def test_race_or_forged_original_evidence_cannot_match_second_job(self):
        changes = (
            lambda v: v["first"]["zipSha256ByMajor"].update({"14": "f" * 64}),
            lambda v: v["first"]["spdxSha256ByMajor"].update({"18": "f" * 64}),
            lambda v: v["first"]["grypeSha256ByMajor"].update({"16": "f" * 64}),
            lambda v: v["first"]["grypePolicyByMajor"]["15"].update(status="BLOCKING_FINDINGS",
                blockingFindingCount=1),
            lambda v: v["first"].update(mainMergeSha="f" * 40),
            lambda v: v["first"].update(runAttempt=2),
            lambda v: v["first"].update(candidatePr=99),
            lambda v: v["second"].update(cryptographicVerification="FAKE"),
            lambda v: v["first"].update(publicationAuthorized=True),
            lambda v: v["second"].update(automaticReleaseEnabled=True),
            lambda v: v["first"]["zipSha256ByMajor"].pop("17"),
            lambda v: v["first"]["spdxSha256ByMajor"].update({"19": "f" * 64}),
            lambda v: v.update(sha="f" * 40),
            lambda v: v.update(attempt=2),
            lambda v: v.update(event="workflow_dispatch"),
            lambda v: v.update(ref="refs/heads/evil"),
            lambda v: v["lifecycle"]["postgresql"].pop(),
            lambda v: v["manifest"]["upstream"].update(repository="evil/upstream"),
        )
        for k, change in enumerate(changes):
            with self.subTest(case=k), self.assertRaises(gate.Denied):
                v = fixture()
                change(v)
                gate.compare(**v)

    def test_both_tampered_identically_still_deny_unsafe_authority(self):
        changes = (
            lambda v: v.update(publicationAuthorized=True),
            lambda v: v.update(publishableReceipt=True),
            lambda v: v.update(automaticReleaseEnabled=True),
            lambda v: v.update(authorizationMode="manual-dispatch"),
            lambda v: v["grypePolicyByMajor"]["14"].update(
                status="BLOCKING_FINDINGS", blockingFindingCount=1),
            lambda v: v["grypePolicyByMajor"]["14"]["findingCountBySeverity"].update(High=1),
            lambda v: v["zipSha256ByMajor"].pop("14"),
            lambda v: v.update(runId=0),
        )
        for k, change in enumerate(changes):
            with self.subTest(case=k), self.assertRaises(gate.Denied):
                v = fixture()
                change(v["first"])
                change(v["second"])
                gate.compare(**v)

    def test_missing_and_ambiguous_json_rejected(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "recheck.json"
            with self.assertRaises(gate.Denied):
                gate.read_json(p)
            p.write_text('{"runId":1,"runId":2}', "utf-8")
            with self.assertRaises(gate.Denied):
                gate.read_json(p)
            p.write_text('[]', "utf-8")
            with self.assertRaises(gate.Denied):
                gate.read_json(p)

    def test_independent_job_reexecutes_real_gh_signature_and_has_no_write(self):
        self.assertIn("  signed_audit:", FLOW)
        self.assertIn("  publisher_second_opinion:", FLOW)
        body = FLOW.split("  publisher_second_opinion:", 1)[1]
        self.assertIn("needs: signed_audit", body)
        self.assertIn("Verify fresh ZIP/SPDX/Grype Sigstore in separate job", body)
        self.assertIn("automatic-signed-candidate-audit.py", body)
        self.assertIn("independent-signed-publisher-preflight.py", body)
        self.assertIn("name: automatic-signed-candidate-audit-nonpublishing", body)
        self.assertIn("name: automatic-signed-build-intent-nonpublishing", body)
        self.assertIn("name: independent-signed-publisher-preflight-nonpublishing", body)
        self.assertIn("attestations: read", body)
        self.assertIn("contents: read", body)
        for forbidden in ("contents: write", "id-token: write",
                          "attestations: write", "permission-actions: write",
                          "gh release create", "gh workflow run",
                          "--clobber", "continue-on-error:"):
            self.assertNotIn(forbidden, body)
        code = (ROOT / "scripts/independent-signed-publisher-preflight.py").read_text("utf-8")
        for forbidden in ("subprocess", "urllib", "import requests",
                          "gh release create", "github.token", "GH_TOKEN", "publish_release"):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
