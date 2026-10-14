#!/usr/bin/env python3
"""Issue #75 PRE-G4 offline recovery evidence DENY fixtures; zero GitHub I/O."""
from copy import deepcopy
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "inert_recovery", ROOT / "scripts" / "release-recovery-evidence.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

TAG = "v2.10.15-windows.1"  # only a synthetic, never reserved or published
SHA = "a" * 40
DIGEST = "b" * 64


def evidence(stage="DRAFT_VERIFIED"):
    return {
        "schemaVersion": 2, "state": stage, "tag": TAG, "runId": 101,
        "commit": SHA,
        "reservation": {
            "outcome": "CREATED", "httpStatus": 201,
            "ref": "refs/tags/" + TAG, "objectSha": SHA,
        },
        "releaseId": None if stage == "TAG_RESERVED" else 701,
        "assetInventory": {"package.zip": DIGEST, "package.spdx.json": "c" * 64},
    }


def snapshot(stage="DRAFT_VERIFIED"):
    release = {
        "id": 701, "tag_name": TAG, "target_commitish": SHA,
        "draft": stage in {"DRAFT_STAGED", "DRAFT_VERIFIED"},
        "assets": [
            {"id": 801, "name": "package.zip", "state": "uploaded",
             "digest": "sha256:" + DIGEST},
            {"id": 802, "name": "package.spdx.json", "state": "uploaded",
             "digest": "sha256:" + "c" * 64},
        ],
    }
    return {
        "complete": True, "httpStatus": 200,
        "tagRef": {"ref": "refs/tags/" + TAG, "objectSha": SHA},
        "release": None if stage == "TAG_RESERVED" else release,
    }


def classify(record=None, first=None, second=None):
    record = evidence() if record is None else record
    first = snapshot() if first is None else first
    second = deepcopy(first) if second is None else second
    return recovery.classify_recovery_evidence(record, [first, second])


class RecoveryTests(TestCase):
    def assert_nonpublishing(self, result):
        self.assertIs(result["publicationAuthorized"], False)
        self.assertIs(result["retryAuthorized"], False)
        self.assertIs(result["mutationAuthorized"], False)
        self.assertEqual(result["permittedActions"], ["MANUAL_READ_ONLY_TRIAGE"])

    def test_all_stages_are_read_only_even_when_consistent(self):
        for stage in ("TAG_RESERVED", "DRAFT_STAGED", "DRAFT_VERIFIED",
                      "PUBLISHED_AUDIT_PENDING", "PUBLISHED_VERIFIED"):
            with self.subTest(stage=stage):
                result = classify(evidence(stage), snapshot(stage))
                self.assertEqual(result["classification"], "CONSISTENT_READ_ONLY")
                self.assert_nonpublishing(result)

    def test_current_v1_and_recovery_write_loss_are_unknown(self):
        for record in ({}, {"schemaVersion": 1, "state": "DRAFT_STAGED",
                            "tag": TAG, "runId": 101, "commit": SHA},
                       None):
            if record is None:
                # Simulate no recovery artifact/file at all.
                result = recovery.classify_recovery_evidence(None, [snapshot(), snapshot()])
            else:
                result = classify(record)
            self.assertEqual(result["classification"], "UNKNOWN_QUARANTINE")
            self.assert_nonpublishing(result)

    def test_lost_post_response_422_429_and_bad_reservation_are_unknown(self):
        mutations = [
            lambda r: r.pop("reservation"),
            lambda r: r["reservation"].update(outcome="UNKNOWN"),
            lambda r: r["reservation"].update(httpStatus=422),
            lambda r: r["reservation"].update(httpStatus=429),
            lambda r: r["reservation"].update(httpStatus=None),
            lambda r: r["reservation"].update(httpStatus=True),
            lambda r: r["reservation"].update(ref="refs/tags/occupied"),
            lambda r: r["reservation"].update(objectSha="d" * 40),
        ]
        for mutate in mutations:
            record = evidence()
            mutate(record)
            with self.subTest(mutate=str(mutate)):
                result = classify(record)
                self.assertEqual(result["classification"], "UNKNOWN_QUARANTINE")
                self.assert_nonpublishing(result)

    def test_immutable_release_identity_draft_and_tag_conflicts(self):
        mutations = [
            lambda s: s["tagRef"].update(objectSha="d" * 40),
            lambda s: s["tagRef"].update(ref="refs/tags/other"),
            lambda s: s["release"].update(id=702),
            lambda s: s["release"].update(tag_name="other"),
            lambda s: s["release"].update(target_commitish="d" * 40),
            lambda s: s["release"].update(draft=False),
            lambda s: s.update(release=None),
            lambda s: s.update(httpStatus=404),
            lambda s: s.update(httpStatus=429),
            lambda s: s.update(complete=False),
        ]
        for mutate in mutations:
            s = snapshot()
            mutate(s)
            with self.subTest(mutate=str(mutate)):
                result = classify(first=s)
                self.assertEqual(result["classification"], "UNKNOWN_QUARANTINE")
                self.assert_nonpublishing(result)
        record = evidence()
        record["releaseId"] = 702
        self.assertEqual(classify(record)["classification"], "UNKNOWN_QUARANTINE")

    def test_partial_duplicate_extra_and_wrong_digest_assets_unknown(self):
        mutations = [
            lambda a: a.pop(),
            lambda a: a.append(deepcopy(a[0])),
            lambda a: a.append({"id": 803, "name": "extra", "state": "uploaded",
                                "digest": "sha256:" + DIGEST}),
            lambda a: a[0].update(digest="sha256:" + "0" * 64),
            lambda a: a[0].update(state="starter"),
            lambda a: a[0].update(id=a[1]["id"]),
        ]
        for mutate in mutations:
            s = snapshot()
            mutate(s["release"]["assets"])
            with self.subTest(mutate=str(mutate)):
                result = classify(first=s)
                self.assertEqual(result["classification"], "UNKNOWN_QUARANTINE")
                self.assert_nonpublishing(result)

    def test_communication_error_unknown_and_two_reads_must_agree(self):
        first, second = snapshot(), snapshot()
        self.assertEqual(recovery.classify_recovery_evidence(
            evidence(), [first])["classification"], "UNKNOWN_QUARANTINE")
        self.assertEqual(recovery.classify_recovery_evidence(
            evidence(), [first, first])["classification"], "UNKNOWN_QUARANTINE")
        second["release"]["id"] = 702
        self.assertEqual(recovery.classify_recovery_evidence(
            evidence(), [first, second])["classification"], "UNKNOWN_QUARANTINE")
        for failed in ({"error": "timeout"}, {"httpStatus": 503}, None):
            self.assertEqual(classify(first=failed)["classification"],
                             "UNKNOWN_QUARANTINE")

    def test_replay_existing_tag_and_draft_partial_are_not_restartable(self):
        # Even fully consistent remote evidence never authorizes a second POST
        # or PATCH. A tag-only record cannot justify continuing a Draft write.
        reserved = classify(evidence("TAG_RESERVED"), snapshot("TAG_RESERVED"))
        self.assert_nonpublishing(reserved)
        occupied = snapshot("TAG_RESERVED")
        occupied["release"] = snapshot()["release"]
        self.assertEqual(classify(evidence("TAG_RESERVED"), occupied)["classification"],
                         "UNKNOWN_QUARANTINE")
        missing_id = evidence("DRAFT_STAGED")
        del missing_id["releaseId"]
        self.assertEqual(classify(missing_id)["classification"], "UNKNOWN_QUARANTINE")

    def test_malformed_types_are_unknown_not_exceptions(self):
        for field, value in (("state", []), ("schemaVersion", True),
                             ("tag", "../evil"), ("runId", True),
                             ("commit", "wrong"), ("assetInventory", {}),
                             ("releaseId", True)):
            record = evidence()
            record[field] = value
            with self.subTest(field=field):
                self.assertEqual(classify(record)["classification"], "UNKNOWN_QUARANTINE")


if __name__ == "__main__":
    main()
