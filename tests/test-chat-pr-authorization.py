#!/usr/bin/env python3
"""Offline Phase-B authorization PR allow/deny fixtures; never publishes."""
from copy import deepcopy
import json
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

def committed_fixture(context):
    """Construct independently matching PR and commit blob identities for tests."""
    x = deepcopy(context)
    raw = json.dumps(x.pop("request"), sort_keys=True, separators=(",", ":"))
    sha = lib.git_blob_sha(raw.encode("utf-8"))
    x["pr_files"][0]["sha"] = sha
    x["commit"]["files"][0]["sha"] = sha
    return x, raw


def verify_fixture(context):
    x, raw = committed_fixture(context)
    return lib.verify_approval(raw, **x)


class ApprovalTests(unittest.TestCase):
    def test_positive_context_only_no_release(self):
        result = verify_fixture(fixture())
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
            lambda x:x["pr"]["head"].update(ref="other/"+TAG),
            lambda x:x["pr"].update(number=True),
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

    def test_committed_blob_identity_and_duplicate_key_denials(self):
        args, raw = committed_fixture(fixture())
        self.assertEqual(lib.verify_approval(raw, **args)["authorizationCommit"], AFTER)
        cases = [
            (raw.replace('"confirmRelease":"PUBLISH"', '"confirmRelease":"publish"'), args),
            (raw.replace('"confirmRelease":"PUBLISH"',
                         '"confirmRelease":"PUBLISH","confirmRelease":"PUBLISH"'), args),
            (raw + " ", args),
            ({"confirmRelease": "PUBLISH"}, args),
        ]
        for index, (payload, snapshots) in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(lib.Denied):
                lib.verify_approval(payload, **snapshots)
        bad_commit = deepcopy(args)
        bad_commit["commit"]["files"][0]["sha"] = "f" * 40
        with self.assertRaises(lib.Denied):
            lib.verify_approval(raw, **bad_commit)
        bad_pr = deepcopy(args)
        bad_pr["pr_files"][0]["sha"] = "f" * 40
        with self.assertRaises(lib.Denied):
            lib.verify_approval(raw, **bad_pr)

    def test_two_independent_verifier_results_must_bind_exactly(self):
        approved=verify_fixture(fixture())
        candidate={
            "schemaVersion":1,
            "status":"VERIFIED_CHAT_PR_AUTHORIZATION",
            "authorizationMode":"chat-pr-authorization",
            "operator":OPERATOR,"repository":REPO,"releaseTag":TAG,
            "trustedCommit":AFTER,"candidatePr":12,
            "candidateHeadSha":CANDIDATE,
            "candidateRunId":123456,"decisionRunId":123455,
            "majors":[14,15,16,17,18],"sources":[],
        }
        bound=lib.bind_verified_receipt(candidate,approved)
        self.assertEqual(bound["authorizationCommit"],AFTER)
        self.assertEqual(bound["authorizationPr"],33)
        self.assertEqual(bound["authorizationBaseSha"],BASE)
        for k,bad in [
            ("operator","attacker"), ("repository","pgextwin/evil"),
            ("releaseTag","v0-windows.1"), ("trustedCommit",BASE),
            ("candidatePr",99), ("candidateHeadSha",HEAD),
            ("candidateRunId",9),("decisionRunId",8),
            ("authorizationMode","manual-dispatch"),
            ("status","VERIFIED_MANUAL_DISPATCH")]:
            mutated=dict(candidate); mutated[k]=bad
            with self.subTest(field=k),self.assertRaises(lib.Denied):
                lib.bind_verified_receipt(mutated,approved)
        damaged=dict(approved); damaged["event"]="schedule"
        with self.assertRaises(lib.Denied):
            lib.bind_verified_receipt(candidate,damaged)

    def assert_all_denied(self,cases):
        for index, mutate in enumerate(cases):
            context = fixture()
            mutate(context)
            with self.subTest(index=index), self.assertRaises(lib.Denied):
                verify_fixture(context)


if __name__ == "__main__":
    unittest.main()
