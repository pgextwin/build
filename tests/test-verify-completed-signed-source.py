#!/usr/bin/env python3
"""Fail closed completed-source read-only Publisher proof tests.

Synthetic fixtures never count as real gh Sigstore or an authorization.
"""
import importlib.util
from pathlib import Path
from copy import deepcopy
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "verify_completed_source",ROOT/"scripts/verify-completed-signed-source.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
REPO="pgextwin/pg_ivm"
SHA="a"*40
RUN=314159
def fleet():
    return {"schemaVersion":1,"releasePolicy":"manual-only",
            "entries":[{"repository":REPO,"mode":"BUILD",
                        "candidateEnabled":True,"releasePolicy":"manual-only"}]}

class IndependentCompletedSource(unittest.TestCase):
    def test_read_only_cli_path_forbids_mutation_and_argument_injection(self):
        for cmd in (
            ("gh","api","-X","POST","repos/pgextwin/pg_ivm/releases"),
            ("gh","release","create","v1"),
            ("gh","api","--method","DELETE","repos/pgextwin/pg_ivm/releases"),
            ("sh","-c","echo fake"),
            ("gh","api","--method","GET","a","b")):
            with self.subTest(cmd=cmd),self.assertRaises(mod.Denied):
                mod.command(*cmd)
    def test_github_get_exact_allowlist(self):
        for route in (
            "releases", "git/refs", "actions/runs/0", "actions/runs/1/jobs",
            "actions/runs/1/attempts/2/jobs?per_page=100",
            "actions/runs/1/artifacts?per_page=999",
            "branches/other","branches/main?foo=bar",
            "../actions/runs/1","actions/runs/1%0aPOST"):
            with self.subTest(route=route),self.assertRaises(mod.Denied):
                mod.github(REPO,route)
        with self.assertRaises(mod.Denied):
            mod.github("pgextwin/evil?x=1","branches/main")
    def test_duplicate_or_linked_json_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"evidence.json"
            p.write_text('{"status":"safe","status":"forged"}')
            with self.assertRaises(mod.Denied):mod.read(p)
            p.write_text('{"safe":true}')
            self.assertEqual(mod.read(p),{"safe":True})
            linked=Path(d)/"symlink.json"
            linked.symlink_to(p)
            with self.assertRaises(mod.Denied):mod.read(linked)
    def test_unknown_repo_and_replay_fail_before_byte_verification(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            arguments=(folder,{"name":"pg_ivm"},{},{},{},fleet())
            for mutations in (
                {"repository":"pgextwin/unknown"},
                {"repository":"pgextwin/other"},
                {"sha":"bad"},
                {"run_id":0},
                {"run_id":True},
                {"attempt":2},
                {"attempt":True}):
                with self.subTest(mutations=mutations),self.assertRaises(
                        (mod.Denied,mod.scope.Denied)):
                    mod.verify_completed_source(*arguments,**{
                        "repository":REPO,"sha":SHA,"run_id":RUN,
                        **mutations},get=lambda *_:self.fail("GET attempted"))
    def test_protected_current_main_and_unsupported_source_policy(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            arguments=(folder,{"name":"pg_ivm"},{},{},{},fleet())
            for altered in (
                {"name":"main","protected":False,"commit":{"sha":SHA}},
                {"name":"main","protected":True,"commit":{"sha":"b"*40}},
                {"name":"wrong","protected":True,"commit":{"sha":SHA}},
                None):
                with self.subTest(altered=altered),self.assertRaises(mod.Denied):
                    mod.verify_completed_source(*arguments,repository=REPO,sha=SHA,
                        run_id=RUN,get=lambda *_:altered)
            wrong=fleet();wrong["entries"].append(deepcopy(wrong["entries"][0]))
            with self.assertRaises(mod.scope.Denied):
                mod.verify_completed_source(folder,{"name":"pg_ivm"},{},{},{},wrong,
                    repository=REPO,sha=SHA,run_id=RUN,
                    get=lambda *_:self.fail("GET attempted"))
    def test_only_readonly_status_is_exported_in_source(self):
        source=(ROOT/"scripts/verify-completed-signed-source.py").read_text()
        self.assertIn("REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING",source)
        self.assertIn('"publicationAuthorized":False',source)
        self.assertIn('"publisherTokenRequested":False',source)
        self.assertNotIn('gh","release","create',source)
        self.assertNotIn('gh","api","-X","POST',source)

if __name__=="__main__":
    unittest.main()
