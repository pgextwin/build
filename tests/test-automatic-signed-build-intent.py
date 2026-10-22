#!/usr/bin/env python3
"""Hostile offline decision/witness joins; never a publication permit."""
from copy import deepcopy
from datetime import date
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "signing_intent", ROOT / "scripts" / "automatic-signed-build-intent.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
fleet = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))
central = json.loads((ROOT / "metadata" / "release-promotion.json").read_text("utf-8"))
SOURCE = "5" * 40
HEAD = "c" * 40
MAIN = "d" * 40
BRANCH = "auto-candidate/" + "e" * 20


def fixture():
    return dict(
        witness={"schemaVersion": 1, "status": "MERGED_NATIVE_CANDIDATE_NONPUBLISHING",
                 "repository": "pgextwin/orafce", "candidatePr": 8,
                 "candidateBranch": BRANCH, "candidateHeadSha": HEAD,
                 "mainMergeSha": MAIN, "candidateCiRunId": 123,
                 "nativeAuditRunId": 124, "nativeAuditArtifactId": 125,
                 "releaseTagStem": "v4.17.1", "maintainedMajors": [14,15,16,17,18],
                 "sourcesAndZipDigests": [{"major": major, "sourceSha": SOURCE,
                                            "zipSha256": "f"*64}
                                           for major in range(14,19)],
                 "signedArtifactsVerified": False, "publishableReceipt": False,
                 "publicationAuthorized": False, "automaticReleaseEnabled": False},
        decision={"schemaVersion": 1, "extension": "orafce", "repository": "orafce/orafce",
                  "releasePolicy": "manual-only", "status": "candidate",
                  "candidateId": "e"*20, "branch": BRANCH,
                  "updates": [{"major": None, "ref": "VERSION_4_17_1",
                               "version": "4.17.1", "commit": SOURCE}]},
        manifest={"schemaVersion": 1, "name": "orafce",
                  "upstream": {"repository": "orafce/orafce",
                               "ref": "VERSION_4_17_1",
                               "version": "4.17.1", "commit": SOURCE},
                  "postgresql": {"majors": [14,15,16,17,18]}},
        lifecycle={"schemaVersion":1, "postgresql":[
            {"major": major, "eol": "2030-11-12"} for major in range(14,19)]},
        fleet=deepcopy(fleet), central_policy=deepcopy(central),
        local_candidate_policy={"schemaVersion":1,"enabled":True,
                                "releasePolicy":"manual-only","workflow":"windows.yml"},
        today=date(2026,10,22),
    )


class SigningIntentTests(unittest.TestCase):
    def test_fully_joined_intent_cannot_publish(self):
        value = gate.plan(**fixture())
        self.assertEqual(value["status"],
                         "ELIGIBLE_FOR_FURTHER_SIGNED_BUILD_AUDIT_NONPUBLISHING")
        self.assertEqual(value["candidateBranch"], BRANCH)
        self.assertEqual(value["candidatePr"], 8)
        for key in ("signedArtifactsVerified","publishableReceipt",
                    "publicationAuthorized","automaticReleaseEnabled"):
            self.assertIs(value[key], False)
        self.assertNotIn("authorizationMode", value)
        self.assertNotIn("operator", value)

    def test_forged_cross_run_data_and_policy_fail_closed(self):
        bad = [
            lambda x: x["witness"].update(status="VERIFIED_MANUAL_DISPATCH"),
            lambda x: x["witness"].update(repository="pgextwin/other"),
            lambda x: x["witness"].update(candidatePr=0),
            lambda x: x["witness"].update(candidateHeadSha=MAIN),
            lambda x: x["witness"].update(candidateHeadSha="oops"),
            lambda x: x["witness"].update(candidateBranch="auto-candidate/other"),
            lambda x: x["witness"].update(mainMergeSha="invalid"),
            lambda x: x["witness"].update(candidateCiRunId=0),
            lambda x: x["witness"].update(nativeAuditRunId=None),
            lambda x: x["witness"].update(nativeAuditArtifactId=0),
            lambda x: x["witness"].update(signedArtifactsVerified=True),
            lambda x: x["witness"].update(publishableReceipt="false"),
            lambda x: x["witness"].update(publicationAuthorized=True),
            lambda x: x["witness"].update(automaticReleaseEnabled=True),
            lambda x: x["witness"].update(releaseTagStem="v1.0"),
            lambda x: x["witness"]["sourcesAndZipDigests"].pop(),
            lambda x: x["witness"]["sourcesAndZipDigests"][0].update(major=15),
            lambda x: x["witness"]["sourcesAndZipDigests"][0].update(sourceSha=HEAD),
            lambda x: x["witness"]["sourcesAndZipDigests"][0].update(zipSha256="b"*63),
            lambda x: x["decision"].update(status="release"),
            lambda x: x["decision"].update(repository="attacker/orafce"),
            lambda x: x["decision"].update(extension="pg_ivm"),
            lambda x: x["decision"].update(releasePolicy="automatic"),
            lambda x: x["decision"].update(candidateId="x"*20),
            lambda x: x["decision"].update(branch="auto-candidate/00000000000000000000"),
            lambda x: x["decision"].update(updates=[]),
            lambda x: x["decision"]["updates"][0].update(commit=HEAD),
            lambda x: x["decision"]["updates"][0].update(version="4.16.13"),
            lambda x: x["decision"]["updates"][0].update(major=15),
            lambda x: x["decision"]["updates"][0].update(initialOnly=True),
            lambda x: x["manifest"]["upstream"].update(commit=HEAD),
            lambda x: x["manifest"].update(name="evil"),
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["fleet"]["entries"].pop(),
            lambda x: x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x: x["central_policy"].update(releasePolicy="automatic"),
            lambda x: x["central_policy"]["allowedRepositories"].pop(),
            lambda x: x["local_candidate_policy"].update(releasePolicy="automatic"),
            lambda x: x["local_candidate_policy"].update(enabled=False),
        ]
        for i, change in enumerate(bad):
            with self.subTest(case=i), self.assertRaises(gate.Denied):
                args = fixture()
                change(args)
                gate.plan(**args)


if __name__ == "__main__":
    unittest.main()
