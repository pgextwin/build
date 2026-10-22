#!/usr/bin/env python3
"""Adversarial native PR candidate-artifact checks; never publishes Release."""
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_candidate", ROOT / "scripts" / "verify-candidate.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)
HEAD, MERGE, UPSTREAM = "a" * 40, "b" * 40, "c" * 40
BRANCH = "auto-candidate/" + "d" * 20
RUN, PR = 39760879597, 28
EXT = {"name":"pg_ivm","postgresql":{"majors":[14,15]},
       "upstream":{"repository":"sraoss/pg_ivm","ref":"v1.17",
                   "version":"1.17","commit":UPSTREAM}}
LIFECYCLE = {"schemaVersion":1,"postgresql":[
    {"major":14,"eol":"2030-11-12"},{"major":15,"eol":"2030-11-11"}]}


def emit(folder, major, *, event="pull_request", packaging=MERGE,
         ref=None, upstream=UPSTREAM, run_id=RUN):
    folder.mkdir(parents=True)
    if ref is None:
        ref = "refs/pull/28/merge" if event == "pull_request" else "refs/heads/" + BRANCH
    pkg = {"schemaVersion":1,"buildMode":"normal",
           "package":{"name":"pg_ivm"},"postgresql":{"major":major},
           "upstream":{"repository":"sraoss/pg_ivm","ref":"v1.17",
                       "version":"1.17","commit":upstream},
           "source":{"packagingRepository":"pgextwin/pg_ivm",
                     "packagingCommit":packaging},
           "workflowRun":{"id":run_id,"event":event,"ref":ref}}
    with ZipFile(folder / "file.zip", "w") as z:
        z.writestr("PACKAGE-INFO.json",json.dumps(pkg))
    (folder / "file.spdx.json").write_text('{"spdxVersion":"SPDX-2.3"}')
    (folder / "file.vulnerabilities.json").write_text('{"matches":[]}')


class NativeCandidateAuditTests(unittest.TestCase):
    def test_existing_dispatch_mode_remains_strictly_compatible(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for m in (14,15):
                emit(root / f"pg_ivm-pg{m}-windows-x64",m,
                     event="workflow_dispatch",packaging=HEAD)
            result = lib.audit(root,EXT,LIFECYCLE,RUN,HEAD,BRANCH,
                               "success",date(2026,10,22))
            self.assertEqual(result["status"],"VERIFIED")
            self.assertEqual(result["originEvent"],"workflow_dispatch")
            for m in (14,15):
                with self.assertRaises(ValueError):
                    lib.one(root/f"pg_ivm-pg{m}-windows-x64",EXT,m,RUN,HEAD,BRANCH,
                            event="workflow_dispatch",merge_sha=MERGE)

    def test_realistic_native_pr_zip_exact_merged_sha_and_refs(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for m in (14,15):
                emit(root / f"pg_ivm-pg{m}-windows-x64",m)
            result = lib.audit(root,EXT,LIFECYCLE,RUN,HEAD,BRANCH,"success",
                               date(2026,10,22),event="pull_request",
                               merge_sha=MERGE,pr_number=PR)
            self.assertEqual(result["status"],"VERIFIED")
            self.assertEqual(result["originEvent"],"pull_request")
            self.assertEqual(len(result["majors"]),2)
            self.assertTrue(all(len(x["zipSha256"])==64 for x in result["majors"]))
            self.assertEqual(lib.audit(root,EXT,LIFECYCLE,RUN,HEAD,BRANCH,"failure",
                    date(2026,10,22),event="pull_request",
                    merge_sha=MERGE,pr_number=PR)["status"],"FAILED")
            for kw in (
                dict(merge_sha=None,pr_number=PR),dict(merge_sha=HEAD,pr_number=PR),
                dict(merge_sha=MERGE,pr_number=99),dict(merge_sha=MERGE,pr_number=0),
                dict(merge_sha=MERGE,pr_number=PR,event="workflow_dispatch"),
                dict(merge_sha=MERGE,pr_number=PR,event="schedule"),
            ):
                with self.subTest(kw=kw):
                    v = {"event":"pull_request","merge_sha":MERGE,"pr_number":PR}
                    v.update(kw)
                    with self.assertRaises(ValueError):
                        lib.one(root/"pg_ivm-pg14-windows-x64",EXT,14,RUN,HEAD,BRANCH,**v)

    def test_forged_zip_source_identity_and_run_fail_closed(self):
        for variant in ("wrong_sha","wrong_upstream","wrong_event","wrong_ref",
                        "wrong_run","missing_spdx","wrong_zip_major"):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as d:
                root = Path(d)
                kw = {}
                if variant=="wrong_sha":kw["packaging"]=HEAD
                if variant=="wrong_upstream":kw["upstream"]="f"*40
                if variant=="wrong_event":kw["event"]="workflow_dispatch"
                if variant=="wrong_ref":kw["ref"]="refs/heads/main"
                if variant=="wrong_run":kw["run_id"]=RUN+1
                emit(root/"pg_ivm-pg14-windows-x64",
                     15 if variant=="wrong_zip_major" else 14,**kw)
                emit(root/"pg_ivm-pg15-windows-x64",15)
                if variant=="missing_spdx":
                    (root/"pg_ivm-pg14-windows-x64"/"file.spdx.json").unlink()
                result=lib.audit(root,EXT,LIFECYCLE,RUN,HEAD,BRANCH,"success",
                                 date(2026,10,22),event="pull_request",
                                 merge_sha=MERGE,pr_number=PR)
                self.assertEqual(result["status"],"FAILED")


if __name__ == "__main__":
    unittest.main()
