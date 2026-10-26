#!/usr/bin/env python3
"""Hostile denial fixtures for approval/rerun native candidate schedule repair."""
import importlib.util
from pathlib import Path
from copy import deepcopy
import unittest
root = Path(__file__).resolve().parents[1]
sp = importlib.util.spec_from_file_location("native_recovery",
    root/"scripts"/"recover-native-pr-candidate.py")
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
REPO="pgextwin/hypopg"
HEAD="a"*40
MAIN="b"*40
BRANCH="auto-candidate/"+"c"*20
RUN=40290702780

def data():
    pr={"number":41,"state":"open",
        "user":{"login":"github-actions[bot]"},
        "head":{"ref":BRANCH,"sha":HEAD},"base":{"ref":"main"}}
    run={"id":RUN,"name":"Windows CI/CD","path":".github/workflows/windows.yml",
         "event":"pull_request","head_branch":BRANCH,"head_sha":HEAD,
         "head_repository":{"full_name":REPO},"status":"completed",
         "conclusion":"success","run_attempt":2}
    return [pr],{"total_count":1,"workflow_runs":[run]}

class CandidateNativeRecoveryTests(unittest.TestCase):
    def test_real_approved_attempt_two_selected_without_rerun(self):
        prs, runs=data()
        self.assertEqual(m.choose_candidate(REPO,prs,runs),RUN)

    def test_empty_candidate_is_strict_noop(self):
        prs,runs=data()
        self.assertIsNone(m.choose_candidate(REPO,[],runs))

    def test_authenticated_discovery_query_exact_literal_question_mark(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        expected="actions/runs?event=pull_request&head_sha="+HEAD+"&per_page=100"
        response=SimpleNamespace(returncode=0,stdout='{"total_count":0,"workflow_runs":[]}')
        with patch.object(m.subprocess,"run",return_value=response) as call:
            self.assertEqual(m.get_json(REPO,expected)["total_count"],0)
            self.assertEqual(call.call_args.args[0][-1],"repos/"+REPO+"/"+expected)
        for invalid in (
            "actions/runsevent=pull_request&head_sha="+HEAD+"&per_page=100",
            "actions/runs\\\\event=pull_request&head_sha="+HEAD+"&per_page=100",
            "actions/runs?event=workflow_dispatch&head_sha="+HEAD+"&per_page=100",
            "actions/runs?event=pull_request&head_sha="+HEAD+"&per_page=100&actor=evil",
        ):
            with self.subTest(invalid=invalid),self.assertRaises(m.Denied):
                m.get_json(REPO,invalid)

    def test_risky_mutations_denied(self):
        changes=[
            lambda p,r:p[0]["head"].update(sha="d"*40),
            lambda p,r:p[0]["head"].update(ref="auto-candidate/"+"d"*20),
            lambda p,r:p[0]["base"].update(ref="release/evil"),
            lambda p,r:r["workflow_runs"][0].update(event="workflow_dispatch"),
            lambda p,r:r["workflow_runs"][0].update(conclusion="action_required"),
            lambda p,r:r["workflow_runs"][0].update(status="queued"),
            lambda p,r:r["workflow_runs"][0].update(head_sha="e"*40),
            lambda p,r:r["workflow_runs"][0].update(head_repository={"full_name":"evil/hypopg"}),
            lambda p,r:r["workflow_runs"][0].update(name="fake"),
            lambda p,r:r["workflow_runs"][0].update(path=".github/workflows/dispatch.yml"),
            lambda p,r:r["workflow_runs"].append(deepcopy(r["workflow_runs"][0])),
            lambda p,r:r.update(total_count=101),
            lambda p,r:p.append(deepcopy(p[0])),
        ]
        for i, change in enumerate(changes):
            with self.subTest(case=i), self.assertRaises(m.Denied):
                ps, rs=data()
                change(ps,rs)
                m.choose_candidate(REPO,ps,rs)

    def test_schedule_identity_gate_and_pre_authorization_denial(self):
        prs,runs=data()
        for event, ref, sha in (
                ("workflow_dispatch","refs/heads/main",MAIN),
                ("push","refs/heads/main",MAIN),
                ("schedule","refs/heads/evil",MAIN),
                ("schedule","refs/heads/main","bad")):
            with self.subTest(event=event,ref=ref), self.assertRaises(m.Denied):
                m.reconcile(REPO,event,ref,sha,prs,runs,lambda _:None)

    def test_no_release_and_no_privileged_action_endpoint(self):
        src=(root/"scripts"/"recover-native-pr-candidate.py").read_text()
        self.assertIn("native.validate(",src)
        self.assertIn('event_name == "schedule"',src)
        self.assertNotIn("workflow_dispatch",src.split("def get_json",1)[0])
        self.assertNotIn("gh pr merge",src)
        self.assertNotIn("gh workflow run",src)
        workflow=(root/".github/workflows"/"recover-native-pr-candidate.yml").read_text()
        self.assertIn("workflow_call:",workflow)
        self.assertIn("github.event_name == 'schedule'",workflow)
        self.assertNotIn("permission-contents: write",workflow)
        self.assertNotIn("id-token: write",workflow)

if __name__ == "__main__":
    unittest.main()
