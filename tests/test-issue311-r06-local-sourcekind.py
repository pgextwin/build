#!/usr/bin/env python3
"""R06 request source-kind pilot: hostile original-ZIP/local candidate fixtures."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "r06_kind", ROOT / "scripts/issue311-r06-local-sourcekind.py")
kind = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kind)


def original():
    targets = kind.scan.win.TARGETS
    return {
        "schemaVersion": 1, "requestId": kind.scan.REQUEST,
        "requestSha256": "a" * 64, "sourceRunId": kind.SOURCE_RUN,
        "sourceHeadSha": kind.SOURCE_HEAD, "sourceEvent": "push",
        "admissionScope": "AUDIT_ONLY_REQUEST_READONLY_SCAN_NOT_SCHEDULE",
        "result": "SCANNED", "publicationAuthorized": False,
        "targetMainSha": targets.copy(),
        "perTargetStatus": {repo: "up-to-date" for repo in targets},
        "report": {
            "schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
            "publication": "DENY", "candidatePrCreated": False,
            "fleetSize": 17, "indeterminate": 0, "updatesDetected": 0,
            "extensions": [{"repository": r, "mainSha": s, "status": "up-to-date",
                            "updates": []} for r, s in targets.items()],
        },
    }


def verified():
    return {
        "result": "SCANNED_VERIFIED", "sourceKind": "AUTHENTICATED_REQUEST_READONLY_SCAN",
        "sourceRunId": kind.SOURCE_RUN, "sourceRunAttempt": 1,
        "sourceHeadSha": kind.SOURCE_HEAD,
        "originalZipArtifactId": kind.SOURCE_ARTIFACT,
        "originalZipSha256": kind.SOURCE_ZIP_SHA256,
        "targetCount": 17, "verifiedTargets": sorted(kind.scan.win.TARGETS),
        "candidateAdmissionAuthorized": False,
        "publicationAuthorized": False, "genuineSchedule": False,
        "requestSha256": "a" * 64,
    }


class KindTests(unittest.TestCase):
    def decide(self, raw=None, proof=None, repo=None, sha=None):
        repo = kind.PILOT if repo is None else repo
        sha = kind.scan.win.TARGETS[kind.PILOT] if sha is None else sha
        return kind.classify(raw if raw is not None else original(),
                             proof if proof is not None else verified(), repo, sha)

    def test_authentic_original_no_update_is_not_candidate(self):
        answer = self.decide()
        self.assertEqual(answer["decision"], "NO_UPDATE")
        self.assertEqual(answer["sourceKind"], kind.SOURCE_KIND)
        self.assertTrue(answer["originalOuterZipByteVerified"])
        for forbidden in ("candidateAdmissionAuthorized", "publisherSourceKindAuthorized",
                          "publicationAuthorized", "genuineSchedule"):
            self.assertIs(answer[forbidden], False)

    def test_indicated_upstream_update_still_denies_writes(self):
        data = original()
        row = next(x for x in data["report"]["extensions"]
                   if x["repository"] == kind.PILOT)
        row["status"] = "update-available"
        row["updates"] = [{"version": "v99", "commit": "c" * 40}]
        data["perTargetStatus"][kind.PILOT] = "update-available"
        data["report"]["updatesDetected"] = 1
        decision = self.decide(raw=data)
        self.assertEqual(decision["decision"], "UPDATE_PRESENT_NOT_AUTHORIZED")
        self.assertFalse(decision["candidateAdmissionAuthorized"])

    def test_hard_deny_forged_source_proof(self):
        changes = [
            ("result", "SCANNED_VERIFIED_RECOVERED"),
            ("sourceKind", "ORIGINAL_OUTER_ZIP_VERIFIED"),
            ("sourceRunId", 23456),
            ("sourceRunAttempt", 2),
            ("sourceHeadSha", "c" * 40),
            ("originalZipArtifactId", 999),
            ("originalZipSha256", "f" * 64),
            ("targetCount", 16),
            ("verifiedTargets", [kind.PILOT]),
            ("candidateAdmissionAuthorized", True),
            ("publicationAuthorized", True),
            ("genuineSchedule", True),
            ("requestSha256", "b" * 64),
        ]
        for key, value in changes:
            with self.subTest(field=key):
                item = verified()
                item[key] = value
                with self.assertRaisesRegex(ValueError, "R06_LOCAL_KIND_DENY"):
                    self.decide(proof=item)

    def test_hard_deny_forged_original_or_partial_fleet(self):
        for path, value in (
            (("sourceEvent",), "schedule"),
            (("result",), "SCANNED_VERIFIED"),
            (("publicationAuthorized",), True),
            (("requestSha256",), "b" * 64),
            (("targetMainSha",), {}),
            (("report", "indeterminate"), 1),
            (("report", "fleetSize"), 16),
            (("report", "updatesDetected"), 2),
            (("report", "publication"), "ALLOW"),
            (("report", "candidatePrCreated"), True),
            (("perTargetStatus",), {}),
        ):
            with self.subTest(path=path):
                item = original()
                node = item
                for part in path[:-1]:
                    node = node[part]
                node[path[-1]] = value
                with self.assertRaisesRegex(ValueError, "R06_(LOCAL_KIND|SCAN)_DENY"):
                    self.decide(raw=item)

    def test_missing_duplicate_changed_main_and_inconsistent_updates(self):
        for defect in ("missing", "duplicate", "changed", "orphan_update",
                       "lying_status", "wrong_target_sha"):
            item = original()
            rows = item["report"]["extensions"]
            if defect == "missing":
                rows.pop()
            elif defect == "duplicate":
                rows[-1] = copy.deepcopy(rows[0])
            elif defect == "changed":
                rows[0]["mainSha"] = "f" * 40
            elif defect == "orphan_update":
                rows[0]["updates"] = [{"version": "v99"}]
            elif defect == "lying_status":
                rows[0]["status"] = "update-available"
            with self.subTest(defect=defect):
                with self.assertRaisesRegex(ValueError, "R06_(LOCAL_KIND|SCAN)_DENY"):
                    self.decide(raw=item, sha=("f" * 40 if defect == "wrong_target_sha"
                                               else None))

    def test_foreign_target_denied(self):
        with self.assertRaisesRegex(ValueError, "R06_LOCAL_KIND_DENY"):
            self.decide(repo="pgextwin/evil")

    def test_readonly_entrypoint_cannot_emit_legacy_authorization(self):
        workflow = (ROOT / ".github/workflows/issue311-r06-local-sourcekind.yml").read_text()
        self.assertIn("r-20261029-r06sourcepilot01.json", workflow)
        for forbidden in ("schedule:", "workflow_dispatch:", "contents: write",
                          "pull-requests: write", "secrets.", "gh release ", "PUBLISH=ALLOW"):
            self.assertNotIn(forbidden, workflow)
        script = (ROOT / "scripts/issue311-r06-local-sourcekind.py").read_text()
        self.assertIn("proof.verify_for_source(", script)
        self.assertIn("proof.original_zip(", script)
        self.assertNotIn("workflow_dispatch", script)


if __name__ == "__main__":
    unittest.main()
