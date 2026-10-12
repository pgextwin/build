#!/usr/bin/env python3
"""Offline Phase-B authorization PR allow/deny fixtures; never publishes."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "chatpr", ROOT/"scripts"/"chat-pr-authorization.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

BASE = "a"*40
AFTER = "b"*40
HEAD = "c"*40
CANDIDATE = "d"*40
TAG = "v2.10.14-windows.3"
REPO = "pgextwin/plpgsql_check"
PATH = ".github/release-authorizations/"+TAG+".json"
OPERATOR = "HumanOperator"


def fixture():
    request = {
        "schemaVersion":1, "type":"pgextwin-chat-authorized-release",
        "repository":REPO, "releaseTag":TAG, "packagingMainSha":BASE,
        "candidatePr":12, "candidateHeadSha":CANDIDATE,
        "candidateRunId":123456, "decisionRunId":123455,
        "operatorLogin":OPERATOR, "confirmRelease":"PUBLISH",
    }
    event = {
        "ref":"refs/heads/main", "repository":{"full_name":REPO},
        "before":BASE, "after":AFTER, "sender":{"login":OPERATOR},
        "created":False, "deleted":False, "commits":[{"id":AFTER}],
    }
    pr = {
        "number":33, "merged":True, "state":"closed",
        "merge_commit_sha":AFTER,
        "base":{"ref":"main","repo":{"full_name":REPO}},
        "head":{"ref":"auth-release/"+TAG, "sha":HEAD,
                "repo":{"full_name":REPO}},
        "user":{"login":OPERATOR}, "merged_by":{"login":OPERATOR},
    }
    commit = {"sha":AFTER, "parents":[{"sha":BASE}],
              "files":[{"filename":PATH,"status":"added"}]}
    return dict(
        request=request, repository=REPO, event=event, pr=pr,
        pr_files=[{"filename":PATH,"status":"added"}],
        commit=commit,
        ci={"headSha":HEAD, "allRequiredChecksPassed":True,
            "requiredChecks":["Windows required summary"]},
        effective_rules={"protectedMain":True, "requiredChecksEnforced":True,
                         "restrictDirectPush":True},
        allowed_operators={OPERATOR},
    )


class ApprovalTests(unittest.TestCase):
    def test_positive_context_only_no_release(self):
        result = lib.verify_approval(**fixture())
        self.assertEqual(result["operator"],OPERATOR)
        self.assertEqual(result["authorizationPr"],33)
        self.assertEqual(result["authorizationCommit"],AFTER)
        self.assertEqual(result["packagingMainSha"],BASE)
        self.assertEqual(result["candidateHeadSha"],CANDIDATE)
        self.assertEqual(result["event"],"push")
        self.assertNotIn("authorizationMode",result)
        self.assertNotIn("status",result)

    def test_schema_operator_and_candidate_denials(self):
        cases = [
            lambda x:x["request"].update(schemaVersion=True),
            lambda x:x["request"].update(confirmRelease="publish"),
            lambda x:x["request"].update(type="free-form"),
            lambda x:x["request"].update(extra="MALICIOUS"),
            lambda x:x["request"].pop("decisionRunId"),
            lambda x:x["request"].update(candidatePr=True),
            lambda x:x["request"].update(candidateRunId=0),
            lambda x:x["request"].update(candidateHeadSha="short"),
            lambda x:x["request"].update(packagingMainSha=AFTER),
            lambda x:x["request"].update(releaseTag="../evil"),
            lambda x:x["request"].update(repository="pgextwin/attacker"),
            lambda x:x["request"].update(operatorLogin="github-actions[bot]"),
            lambda x:x["allowed_operators"].clear(),
        ]
        self.assert_all_denied(cases)

    def test_push_provenance_and_merge_denials(self):
        cases = [
            lambda x:x["event"].update(ref="refs/heads/release/bypass"),
            lambda x:x["event"].update(before=HEAD),
            lambda x:x["event"].update(after=HEAD),
            lambda x:x["event"].update(created=True),
            lambda x:x["event"].update(deleted=True),
            lambda x:x["event"]["sender"].update(login="intruder"),
            lambda x:x["event"]["repository"].update(full_name="pgextwin/evil"),
            lambda x:x["event"]["commits"].append({"id":AFTER}),
            lambda x:x["commit"]["parents"].append({"sha":HEAD}),
            lambda x:x["commit"]["parents"][0].update(sha=HEAD),
            lambda x:x["commit"]["files"].append({"filename":"config/extension.json","status":"modified"}),
            lambda x:x["commit"]["files"][0].update(status="modified"),
            lambda x:x["pr"].update(merged=False),
            lambda x:x["pr"].update(state="open"),
            lambda x:x["pr"].update(merge_commit_sha=HEAD),
            lambda x:x["pr"]["user"].update(login="intruder"),
            lambda x:x["pr"]["merged_by"].update(login="github-actions[bot]"),
            lambda x:x["pr"]["base"].update(ref="dev"),
            lambda x:x["pr_files"].append({"filename":".github/workflows/promote.yml","status":"modified"}),
            lambda x:x["pr_files"][0].update(status="modified"),
        ]
        self.assert_all_denied(cases)

    def test_required_ci_and_branch_protection_denials(self):
        cases = [
            lambda x:x["ci"].update(headSha=AFTER),
            lambda x:x["ci"].update(allRequiredChecksPassed=False),
            lambda x:x["ci"].update(requiredChecks=[]),
            lambda x:x["ci"].update(requiredChecks=[""]),
            lambda x:x["effective_rules"].update(protectedMain=False),
            lambda x:x["effective_rules"].update(requiredChecksEnforced=False),
            lambda x:x["effective_rules"].update(restrictDirectPush=False),
        ]
        self.assert_all_denied(cases)

    def assert_all_denied(self,cases):
        for index, mutate in enumerate(cases):
            context = fixture()
            mutate(context)
            with self.subTest(index=index), self.assertRaises(lib.Denied):
                lib.verify_approval(**context)


if __name__ == "__main__":
    unittest.main()
