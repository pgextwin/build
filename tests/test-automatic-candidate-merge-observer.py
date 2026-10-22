#!/usr/bin/env python3
"""Hostile offline tests for READ-ONLY authentic 17-extension PR provenance."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "observer", ROOT / "scripts" / "automatic-candidate-merge-observer.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
ROSTER = [item["repository"] for item in
          json.loads((ROOT / "metadata" / "automation-fleet.json").read_text("utf-8"))["entries"]]
BASE, COMMIT, HEAD, BLOB = "a" * 40, "b" * 40, "c" * 40, "d" * 40
REPO = "pgextwin/orafce"
BRANCH = "auto-candidate/" + "e" * 20
FILE = {"filename": "config/extension.json", "status": "modified", "sha": BLOB}
ACTOR = "ShutenOishi"


def fixture():
    return dict(
        repository=REPO, actor=ACTOR, expected_sha=COMMIT, roster=list(ROSTER),
        event={"ref": "refs/heads/main",
               "repository": {"full_name": REPO},
               "sender": {"login": ACTOR}, "before": BASE, "after": COMMIT,
               "created": False, "deleted": False, "commits": [{"id": COMMIT}]},
        commit={"sha": COMMIT, "parents": [{"sha": BASE}], "files": [dict(FILE)]},
        prs=[{
            "number": 8, "state": "closed", "merged": True, "draft": False,
            "merge_commit_sha": COMMIT, "body": "<!-- pgextwin-candidate:v1:" + "e" * 20 + " -->",
            "base": {"ref": "main", "repo": {"full_name": REPO}},
            "head": {"ref": BRANCH, "sha": HEAD, "repo": {"full_name": REPO}},
            "user": {"login": "github-actions[bot]"},
            "merged_by": {"login": ACTOR},
        }],
        files=[dict(FILE)],
        branch={"name": "main", "protected": True, "commit": {"sha": COMMIT},
                "protection": {"required_status_checks": {"checks": [
                    {"context": "Windows required summary", "app_id": 15368}]}}},
        checks=[{"name": "Windows required summary", "head_sha": HEAD,
                 "app": {"id": 15368}, "status": "completed", "conclusion": "success"}],
        runs=[{"id": 400, "name": "Windows CI/CD", "event": "pull_request",
               "head_sha": HEAD, "status": "completed", "conclusion": "success"}],
    )


class ObserverTests(unittest.TestCase):
    def test_exact_normal_push_is_observational_only(self):
        result = lib.verify_snapshot(**fixture())
        self.assertEqual(result["status"], "AUTHENTICATED_PR_CI_ONLY")
        self.assertEqual(result["candidateCiRunId"], 400)
        for field in ("publicationAuthorized", "publishableReceipt",
                      "allMaintainedMajorsAudited", "candidateArtifactAuditVerified",
                      "effectiveBranchRulesAudited", "signatureAndProvenanceVerified"):
            self.assertIs(result[field], False)
        self.assertNotIn("authorizationMode", result)
        self.assertNotIn("releaseTag", result)

    def test_realistic_forgery_and_incomplete_evidence_denied(self):
        mutations = [
            lambda a: a["roster"].pop(),
            lambda a: a["roster"].append(a["roster"][0]),
            lambda a: a.update(repository="pgextwin/not_registered"),
            lambda a: a.update(actor="github-actions[bot]"),
            lambda a: a.update(actor="RandomMaintainer"),
            lambda a: a["event"].update(ref="refs/heads/feature"),
            lambda a: a["event"]["sender"].update(login="SomebodyElse"),
            lambda a: a["event"].update(before=HEAD),
            lambda a: a["event"].update(after=HEAD),
            lambda a: a["event"].update(created=True),
            lambda a: a["event"].update(deleted=True),
            lambda a: a["event"].update(commits=[]),
            lambda a: a["event"].update(commits=[{"id": COMMIT}, {"id": COMMIT}]),
            lambda a: a["commit"].update(sha=HEAD),
            lambda a: a["commit"].update(parents=[{"sha": HEAD}]),
            lambda a: a["commit"].update(parents=[{"sha": BASE}, {"sha": HEAD}]),
            lambda a: a["commit"].update(files=[]),
            lambda a: a["commit"].update(files=[dict(FILE), dict(FILE)]),
            lambda a: a["commit"]["files"][0].update(filename=".github/workflows/promote.yml"),
            lambda a: a["prs"].clear(),
            lambda a: a["prs"].append(deepcopy(a["prs"][0])),
            lambda a: a["prs"][0].update(merged=False),
            lambda a: a["prs"][0].update(draft=True),
            lambda a: a["prs"][0].update(merge_commit_sha=HEAD),
            lambda a: a["prs"][0].update(body=""),
            lambda a: a["prs"][0]["user"].update(login="ShutenOishi"),
            lambda a: a["prs"][0]["merged_by"].update(login="github-actions[bot]"),
            lambda a: a["prs"][0]["head"].update(sha=COMMIT),
            lambda a: a["prs"][0]["head"].update(ref="main"),
            lambda a: a["prs"][0]["base"].update(ref="not-main"),
            lambda a: a["prs"][0]["base"]["repo"].update(full_name="evil/repo"),
            lambda a: a["files"][0].update(sha="f" * 40),
            lambda a: a["files"][0].update(status="added"),
            lambda a: a["branch"].update(protected=False),
            lambda a: a["branch"]["commit"].update(sha=HEAD),
            lambda a: a["branch"]["protection"]["required_status_checks"].update(checks=[]),
            lambda a: a["branch"]["protection"]["required_status_checks"]["checks"][0].update(app_id=999),
            lambda a: a["checks"][0].update(head_sha=COMMIT),
            lambda a: a["checks"][0].update(status="queued"),
            lambda a: a["checks"][0].update(conclusion="action_required"),
            lambda a: a["checks"][0].update(conclusion="failure"),
            lambda a: a["checks"][0]["app"].update(id=999),
            lambda a: a["checks"].append(deepcopy(a["checks"][0])),
            lambda a: a["runs"][0].update(event="workflow_dispatch"),
            lambda a: a["runs"][0].update(status="in_progress"),
            lambda a: a["runs"][0].update(conclusion="failure"),
            lambda a: a["runs"][0].update(head_sha=COMMIT),
            lambda a: a["runs"][0].update(id=0),
            lambda a: a["runs"].append(deepcopy(a["runs"][0])),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(i=i), self.assertRaises(lib.Denied):
                kwargs = fixture()
                mutate(kwargs)
                lib.verify_snapshot(**kwargs)


if __name__ == "__main__":
    unittest.main()
