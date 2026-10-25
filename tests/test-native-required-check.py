#!/usr/bin/env python3
"""Bind genuine native check suites; other same-HEAD runs supply no authority."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("native_required_test",ROOT/"scripts/native-required-check.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
REPO="pgextwin/hypopg"
HEAD="84b8eafa5393cf5c953a8b77f1326a53bd2df043"
RUN=40221822297;SUITE=109014352191;CHECK=121321014263
DISPATCH_SUITE=109014350055;DISPATCH_CHECK=121256250376

def fixture():
    # Actual authenticated REST identities observed 2026-10-26 JST. GitHub's
    # official Approve-and-run advanced original native Run to attempt2.
    native={"id":CHECK,"name":"Windows required summary","head_sha":HEAD,
            "check_suite":{"id":SUITE},"app":{"id":15368},
            "details_url":"https://github.com/"+REPO+"/actions/runs/"+str(RUN)+"/job/"+str(CHECK),
            "status":"completed","conclusion":"success"}
    dispatch=deepcopy(native);dispatch.update(id=DISPATCH_CHECK,
        check_suite={"id":DISPATCH_SUITE},details_url="https://github.com/"+REPO+
            "/actions/runs/40221821540/job/"+str(DISPATCH_CHECK))
    return dict(repository=REPO,head=HEAD,
        run={"id":RUN,"name":"Windows CI/CD","event":"pull_request",
             "path":".github/workflows/windows.yml","run_attempt":2,
             "check_suite_id":SUITE,"head_sha":HEAD,
             "head_repository":{"full_name":REPO},
             "status":"completed","conclusion":"success"},
        checks={"total_count":2,"check_runs":[native,dispatch]})

class NativeCheckSuiteTests(unittest.TestCase):
    def test_real_native_approval_attempt_accepts_its_own_suite_only(self):
        proof=gate.verify(**fixture())
        self.assertEqual(proof,{"runId":RUN,"runAttempt":2,"checkSuiteId":SUITE,
                                "checkRunId":CHECK,"headSha":HEAD})

    def test_dispatch_success_cannot_replace_missing_or_failed_native_check(self):
        for conclusion in ("failure","action_required","skipped",None):
            args=fixture();args["checks"]["check_runs"][0]["conclusion"]=conclusion
            with self.subTest(conclusion=conclusion),self.assertRaises(gate.Denied):
                gate.verify(**args)
        args=fixture();args["checks"]["check_runs"].pop(0);args["checks"]["total_count"]=1
        with self.assertRaises(gate.Denied):gate.verify(**args)
        args=fixture();args["run"].update(event="workflow_dispatch",check_suite_id=DISPATCH_SUITE)
        with self.assertRaises(gate.Denied):gate.verify(**args)

    def test_unrelated_dispatch_failure_does_not_override_native_success(self):
        args=fixture();args["checks"]["check_runs"][1]["conclusion"]="failure"
        self.assertEqual(gate.verify(**args)["checkRunId"],CHECK)

    def test_duplicate_required_summary_inside_same_suite_is_ambiguous(self):
        for conclusion in ("success","failure"):
            args=fixture();duplicate=deepcopy(args["checks"]["check_runs"][0])
            duplicate.update(id=CHECK+1,conclusion=conclusion)
            args["checks"]["check_runs"].append(duplicate);args["checks"]["total_count"]=3
            with self.subTest(conclusion=conclusion),self.assertRaises(gate.Denied):
                gate.verify(**args)

    def test_missing_forged_or_wrong_suite_app_run_and_head_fail_closed(self):
        for change in (
            lambda a:a["run"].pop("check_suite_id"),
            lambda a:a["run"].update(check_suite_id=True),
            lambda a:a["run"].update(check_suite_id=SUITE+1),
            lambda a:a["run"].update(check_suite_id=DISPATCH_SUITE),
            lambda a:a["run"].update(run_attempt=True),
            lambda a:a["run"].update(run_attempt=0),
            lambda a:a["run"].update(path=".github/workflows/promote.yml"),
            lambda a:a["run"].update(head_repository={"full_name":"attacker/hypopg"}),
            lambda a:a["checks"]["check_runs"][0].pop("check_suite"),
            lambda a:a["checks"]["check_runs"][0].update(check_suite={"id":True}),
            lambda a:a["checks"]["check_runs"][0].update(head_sha="a"*40),
            lambda a:a["checks"]["check_runs"][0].update(app={"id":999}),
            lambda a:a["checks"]["check_runs"][0].update(status="in_progress"),
            lambda a:a["checks"]["check_runs"][0].update(details_url="https://attacker.invalid/forged"),
            lambda a:a["checks"].update(total_count=100),
            lambda a:a["checks"].update(total_count=3),
            lambda a:a["checks"]["check_runs"][1].update(id=CHECK),
        ):
            args=fixture();change(args)
            with self.subTest(change=str(change)),self.assertRaises(gate.Denied):
                gate.verify(**args)

if __name__=="__main__":unittest.main()
