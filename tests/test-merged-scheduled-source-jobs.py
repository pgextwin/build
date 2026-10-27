#!/usr/bin/env python3
"""Hostile original local schedule signed-source inventory checks. NOT cryptographic tests."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "merged_scheduled_signed_jobs",ROOT/"scripts/merged-scheduled-source-jobs.py")
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
REPO="pgextwin/orafce"
SHA="a"*40
RUN=123456
MAJORS=[14,15,16,17,18]

def sample():
    run={"id":RUN,"run_attempt":1,"event":"schedule","head_sha":SHA,
         "head_branch":"main","path":gate.CALLER,"status":"completed",
         "conclusion":"success","repository":{"full_name":REPO}}
    labels=[gate.AUTH,gate.SIGN+"Resolve extension and PostgreSQL matrix",
            gate.AUDITOR_A,gate.AUDITOR_B,gate.JOIN]
    labels.extend(gate.SIGN+f"PostgreSQL {m} / Windows x64" for m in MAJORS)
    jobs=[]
    for n,label in enumerate(labels):
        job_id=700+n
        jobs.append({"id":job_id,"run_id":RUN,"run_attempt":1,
              "head_sha":SHA,"status":"completed","conclusion":"success",
              "name":label,
              "check_run_url":f"https://api.github.com/repos/{REPO}/check-runs/{job_id}",
              "html_url":f"https://github.com/{REPO}/actions/runs/{RUN}/job/{job_id}"})
    # Other permitted unrelated inherited candidate jobs may be skipped,
    # but never any extra OIDC-signed job.
    jobs.append({"id":900,"run_id":RUN,"run_attempt":1,"head_sha":SHA,
        "status":"completed","conclusion":"skipped",
        "name":"Prepare requested SHA-pinned Windows candidate (never Release)"})
    return run,{"total_count":len(jobs),"jobs":jobs}

def call(run,jobs,**kw):
    args={"repository":REPO,"sha":SHA,"run_id":RUN,"attempt":1,"majors":MAJORS}
    args.update(kw)
    return gate.verify(run,jobs,**args)

class StrictScheduledSource(unittest.TestCase):
    def test_positive_shape_mints_no_authorization(self):
        run,jobs=sample()
        result=call(run,jobs)
        self.assertEqual(result["sourceKind"],gate.SOURCE)
        self.assertEqual(len(result["authenticatedRequiredJobIds"]),10)
        self.assertEqual(result["scheduleAttempt"],1)
        self.assertFalse(result["signedArtifactsVerified"])
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["publisherSourceKindAuthorized"])
        self.assertEqual(result["independentSigstoreAudits"],0)

    def test_no_other_event_or_attempt_or_branch_or_status(self):
        for field,wrong in [
            ("event","push"),("event","workflow_dispatch"),
            ("event","workflow_run"),("run_attempt",2),
            ("head_branch","auto-candidate/1"),
            ("head_sha","b"*40),("path",".github/workflows/windows.yml"),
            ("status","in_progress"),("conclusion","failure"),
            ("repository",{"full_name":"pgextwin/hypopg"})]:
            run,jobs=sample()
            run[field]=wrong
            with self.subTest(field=field,wrong=wrong),self.assertRaises(gate.Denied):
                call(run,jobs)
        run,jobs=sample()
        for kw in [dict(repository="pgextwin/hypopg"),
                   dict(sha="b"*40),dict(run_id=RUN+1),
                   dict(attempt=2),dict(majors=[15,14,16,17,18]),
                   dict(majors=[14,15,16,17,17,18])]:
            with self.subTest(kwargs=kw),self.assertRaises(gate.Denied):
                call(run,jobs,**kw)

    def test_missing_skipped_extra_or_cross_run_jobs(self):
        mutations=[
            lambda r,j:j["jobs"].pop(1),
            lambda r,j:j["jobs"][0].update(conclusion="skipped"),
            lambda r,j:j["jobs"][1].update(conclusion="failure"),
            lambda r,j:j["jobs"][2].update(name="Forged auditor"),
            lambda r,j:j["jobs"][3].update(run_attempt=2),
            lambda r,j:j["jobs"][4].update(run_id=RUN+1),
            lambda r,j:j["jobs"][5].update(head_sha="b"*40),
            lambda r,j:j["jobs"][6].update(check_run_url="https://evil/forged"),
            lambda r,j:j["jobs"][7].update(html_url="https://github.com/evil"),
            lambda r,j:j["jobs"][8].update(id=j["jobs"][0]["id"]),
            lambda r,j:j["jobs"].append(dict(j["jobs"][2],id=999)),
            lambda r,j:j["jobs"].append(dict(j["jobs"][5],id=999,
                name=gate.SIGN+"PostgreSQL 19 / Windows x64")),
            lambda r,j:j.update(total_count=j["total_count"]+1),
            lambda r,j:j["jobs"][5].update(status="in_progress",conclusion=None),
        ]
        for n,fn in enumerate(mutations):
            run,jobs=sample()
            fn(run,jobs)
            with self.subTest(index=n),self.assertRaises(gate.Denied):
                call(run,jobs)

    def test_historical_manual_only_or_wrong_sourcetype_not_upgraded(self):
        run,jobs=sample()
        jobs["jobs"][0]["name"] = "Authenticate main merge and scheduled decision (NONPUBLISHING)"
        with self.assertRaises(gate.Denied):
            call(run,jobs)

if __name__=="__main__":
    unittest.main()
