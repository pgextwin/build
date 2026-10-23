#!/usr/bin/env python3
"""Pure hostile fixtures for guarded SHA-only GitHub native Auto-merge."""
import copy
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pinmerge", root / "scripts" / "verified-pin-automerge.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
OLD, NEW, HEAD = "a"*40, "b"*40, "c"*40
REPO = "pgextwin/pgtap"
PATH = ".github/workflows/update-watch.yml"


def fixture():
    checks = [
        {"name": name, "status": "completed", "conclusion": "success",
         "app": {"id": 15368}} for name in sorted(lib.REQUIRED)
    ]
    return dict(
        repository=REPO, expected_head=HEAD, expected_central=NEW,
        pr={"number":42, "state":"open", "draft":False, "merged":False,
            "mergeable":True, "mergeable_state":"clean",
            "user":{"login":"ShutenOishi"},
            "head":{"sha":HEAD, "ref":"auto-pin/central-schedule", "repo":{"full_name":REPO}},
            "base":{"ref":"main", "repo":{"full_name":REPO}}},
        files=[{"filename":PATH, "status":"modified", "changes":2,
                "patch":"@@ -24,1 +24,1 @@\n"
                        "-    uses: "+lib.SHARED+"@"+OLD+"\n"
                        "+    uses: "+lib.SHARED+"@"+NEW+"\n"}],
        ci_run={"event":"pull_request", "run_attempt":1,"status":"completed",
                "conclusion":"success","head_sha":HEAD,
                "path":".github/workflows/windows.yml",
                "head_branch":"auto-pin/central-schedule",
                "head_repository":{"full_name":REPO},
                "associated_pr_number":42,
                "pull_requests":[]},
        checks=checks,
        metadata={"full_name":REPO, "allow_auto_merge":True,
                  "allow_squash_merge":True},
        main={"name":"main","protected":True},
        central={"commit":{"sha":NEW},"protected":True},
        fleet={"schemaVersion":1,"entries":[{"repository":REPO}]},
        central_runs=[{"event":"push","head_sha":NEW,"status":"completed",
                       "conclusion":"success","run_attempt":1}],
    )


class AutoMergeGuards(unittest.TestCase):
    def test_positive_is_explicit_squash_expected_head_nonpublishing(self):
        command = lib.admit(**fixture())
        self.assertEqual(command, [
            "gh","pr","merge","42","-R",REPO,"--auto","--squash",
            "--match-head-commit",HEAD])
        self.assertNotIn("--admin",command)
        self.assertNotIn("release",command)

    def test_reject_held_repositories(self):
        for repo in ("pgextwin/pg_bigm","pgextwin/orafce"):
            x=fixture()
            x["repository"]=repo
            with self.subTest(repo=repo), self.assertRaises(lib.Denied):
                lib.admit(**x)

    def test_reject_changes_outside_one_pinned_uses_line(self):
        candidates = [
            lambda x:x["files"].append(copy.deepcopy(x["files"][0])),
            lambda x:x["files"][0].update(filename="config/extension.json"),
            lambda x:x["files"][0].update(changes=4),
            lambda x:x["files"][0].update(patch=x["files"][0]["patch"]+
                                             "+    permissions: write-all\n"),
            lambda x:x["files"][0].update(patch=x["files"][0]["patch"].replace(NEW,"main")),
            lambda x:x["files"][0].update(patch=x["files"][0]["patch"].replace(NEW,OLD)),
            lambda x:x["files"][0].update(patch=x["files"][0]["patch"].replace(
                "operator-update-auto.yml","promote-verified-release.yml")),
        ]
        self.deny_cases(candidates)

    def test_reject_untrusted_pr_state_and_identity(self):
        candidates=[
            lambda x:x["pr"].update(draft=True),
            lambda x:x["pr"].update(mergeable_state="behind"),
            lambda x:x["pr"].update(mergeable_state="blocked"),
            lambda x:x["pr"].update(mergeable=False),
            lambda x:x["pr"].update(state="closed"),
            lambda x:x["pr"]["head"].update(sha=OLD),
            lambda x:x["pr"]["head"].update(ref="fix/not-auto-owned"),
            lambda x:x["pr"]["head"]["repo"].update(full_name="attacker/fork"),
            lambda x:x["pr"]["base"].update(ref="release"),
            lambda x:x["pr"]["user"].update(login="intruder"),
        ]
        self.deny_cases(candidates)

    def test_reject_stale_central_and_invalid_proof(self):
        candidates=[
            lambda x:x["central"]["commit"].update(sha=OLD),
            lambda x:x["central_runs"].clear(),
            lambda x:x["central_runs"][0].update(event="workflow_dispatch"),
            lambda x:x["central_runs"][0].update(conclusion="failure"),
            lambda x:x["fleet"]["entries"].append({"repository":REPO}),
            lambda x:x["fleet"]["entries"].clear(),
            lambda x:x["main"].update(protected=False),
            lambda x:x["metadata"].update(allow_auto_merge=False),
            lambda x:x["metadata"].update(allow_squash_merge=False),
        ]
        self.deny_cases(candidates)

    def test_reject_broken_or_improper_ci(self):
        candidates=[
            lambda x:x["ci_run"].update(event="workflow_dispatch"),
            lambda x:x["ci_run"].update(run_attempt=2),
            lambda x:x["ci_run"].update(conclusion="failure"),
            lambda x:x["ci_run"].update(head_sha=OLD),
            lambda x:x["ci_run"].update(associated_pr_number=999),
            lambda x:x["ci_run"].update(head_branch="attacker/change"),
            lambda x:x["ci_run"]["head_repository"].update(full_name="attacker/fork"),
            lambda x:x["checks"][0].update(conclusion="skipped"),
            lambda x:x["checks"][0]["app"].update(id=999),
            lambda x:x["checks"].clear(),
        ]
        self.deny_cases(candidates)

    def test_plpgsql_extra_checks_required_without_weakening(self):
        x=fixture()
        x["repository"]="pgextwin/plpgsql_check"
        x["metadata"]["full_name"]=x["repository"]
        x["pr"]["head"]["repo"]["full_name"]=x["repository"]
        x["pr"]["base"]["repo"]["full_name"]=x["repository"]
        x["fleet"]["entries"][0]["repository"]=x["repository"]
        with self.assertRaises(lib.Denied):
            lib.admit(**x)
        x["checks"] += [
            {"name":n,"status":"completed","conclusion":"success","app":{"id":15368}}
            for n in ("syntax","Regression-test immutable Release preflight")]
        self.assertIn("--squash",lib.admit(**x))

    def deny_cases(self, candidates):
        for i, mutate in enumerate(candidates):
            x=fixture()
            mutate(x)
            with self.subTest(case=i), self.assertRaises(lib.Denied):
                lib.admit(**x)


if __name__ == "__main__":
    unittest.main()
