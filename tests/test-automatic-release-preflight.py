#!/usr/bin/env python3
"""Offline adversarial tests for prospective automatic signed Release trigger."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "automatic_release_preflight", ROOT / "scripts" / "automatic-release-preflight.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
FLEET = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))
BASE, AFTER, HEAD = "a" * 40, "b" * 40, "c" * 40
BRANCH = "auto-candidate/" + "d" * 20
FILE = {"path": "config/extension.json", "status": "modified"}


def fixture():
    return dict(
        fleet=deepcopy(FLEET),
        event={"event": "push", "ref": "refs/heads/main", "repository": "pgextwin/orafce",
               "before": BASE, "after": AFTER, "created": False, "deleted": False,
               "actor": "ShutenOishi"},
        pr={"number": 8, "repository": "pgextwin/orafce", "merged": True,
            "draft": False, "base": "main", "mergeCommit": AFTER,
            "mergedBy": "ShutenOishi", "author": "github-actions[bot]",
            "headSha": HEAD, "branch": BRANCH, "changedFiles": [dict(FILE)]},
        commit={"sha": AFTER, "parents": [BASE], "files": [dict(FILE)]},
        checks={"sha": HEAD, "requiredWindows": "success", "githubActionsAppId": 15368,
                "matrix": "success", "allMaintainedMajorsPassed": True,
                "protectedMainEnforced": True},
        candidate={"branch": BRANCH, "headSha": HEAD, "event": "workflow_dispatch",
                   "status": "completed", "conclusion": "success", "id": 123},
        decision={"candidateBranch": BRANCH, "conclusion": "success", "id": 122},
        audit={"status": "VERIFIED", "candidateRunId": 123, "candidateHeadSha": HEAD,
               "fullMatrix": True, "sourceIdentityMatched": True, "licenseMatched": True},
        release={"tag": "v4.17.1-windows.1", "tagExists": False,
                 "releaseExists": False, "upstreamIsNewer": True},
        permitted_mergers={"ShutenOishi"},
    )


class AutomaticReleaseAdmissionTests(unittest.TestCase):
    def test_valid_candidate_is_only_a_nonpublishing_work_item(self):
        result = gate.preflight(**fixture())
        self.assertEqual(result["status"], "ELIGIBLE_FOR_FURTHER_AUTHENTICATED_AUDIT")
        self.assertEqual(result["repository"], "pgextwin/orafce")
        for key in ("publicationAuthorized", "publishableReceipt",
                    "signedArtifactsVerified", "automaticReleaseEnabled"):
            self.assertIs(result[key], False)
        self.assertNotIn("authorizationMode", result)
        self.assertNotIn("confirmRelease", result)

    def test_forged_events_and_incomplete_candidate_fail_closed(self):
        variants = [
            lambda x: x["event"].update(event="schedule"),
            lambda x: x["event"].update(event="workflow_dispatch"),
            lambda x: x["event"].update(ref="refs/heads/evil"),
            lambda x: x["event"].update(actor="github-actions[bot]"),
            lambda x: x["event"].update(repository="pgextwin/evil"),
            lambda x: x["event"].update(created=True),
            lambda x: x["commit"].update(parents=[BASE, HEAD]),
            lambda x: x["commit"].update(files=[FILE, {"path": "promote.yml", "status": "modified"}]),
            lambda x: x["commit"].update(sha=HEAD),
            lambda x: x["pr"].update(merged=False),
            lambda x: x["pr"].update(draft=True),
            lambda x: x["pr"].update(mergedBy="SomebodyElse"),
            lambda x: x["pr"].update(author="rogue"),
            lambda x: x["pr"].update(mergeCommit=HEAD),
            lambda x: x["pr"].update(branch="main"),
            lambda x: x["pr"].update(changedFiles=[]),
            lambda x: x["checks"].update(sha=AFTER),
            lambda x: x["checks"].update(requiredWindows="action_required"),
            lambda x: x["checks"].update(matrix="failure"),
            lambda x: x["checks"].update(githubActionsAppId=9999),
            lambda x: x["checks"].update(allMaintainedMajorsPassed=False),
            lambda x: x["checks"].update(protectedMainEnforced=False),
            lambda x: x["candidate"].update(event="pull_request"),
            lambda x: x["candidate"].update(headSha=BASE),
            lambda x: x["candidate"].update(conclusion="failure"),
            lambda x: x["decision"].update(candidateBranch="auto-candidate/evil"),
            lambda x: x["decision"].update(conclusion="failure"),
            lambda x: x["audit"].update(status="FAILED"),
            lambda x: x["audit"].update(candidateRunId=124),
            lambda x: x["audit"].update(sourceIdentityMatched=False),
            lambda x: x["audit"].update(licenseMatched=False),
            lambda x: x["release"].update(tagExists=True),
            lambda x: x["release"].update(releaseExists=True),
            lambda x: x["release"].update(upstreamIsNewer=False),
            lambda x: x["release"].update(tag="../bad"),
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["fleet"]["entries"].pop(),
            lambda x: x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x: x.update(permitted_mergers={"github-actions[bot]"}),
        ]
        for index, mutation in enumerate(variants):
            with self.subTest(case=index), self.assertRaises(gate.Denied):
                args = fixture()
                mutation(args)
                gate.preflight(**args)


if __name__ == "__main__":
    unittest.main()
