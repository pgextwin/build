#!/usr/bin/env python3
"""Independent central scheduled native audit: fail-closed policy fixtures."""
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("audit_fleet",ROOT/"scripts"/"recover-native-pr-fleet.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class FleetRecoveryTests(TestCase):
    def test_roster_dynamic_no_fixed_repositories(self):
        live=mod.membership(ROOT/"metadata/automation-fleet.json")
        self.assertIn("pgextwin/hypopg",live)
        self.assertGreater(len(live),1)
        self.assertEqual(len(set(live)),len(live))

    def test_membership_rejects_duplicates_and_untrusted_repositories(self):
        data={"schemaVersion":1,"entries":[{"mode":"BUILD","candidateEnabled":True,
                                            "repository":"pgextwin/hypopg"}]}
        with TemporaryDirectory() as t:
            p=Path(t)/"fleet.json"
            p.write_text(json.dumps(data))
            self.assertEqual(mod.membership(p),["pgextwin/hypopg"])
            data["entries"].append(data["entries"][0])
            p.write_text(json.dumps(data))
            with self.assertRaises(mod.Denied): mod.membership(p)
            data["entries"][1]={"mode":"BUILD","candidateEnabled":True,
                                "repository":"rogue/hypopg"}
            p.write_text(json.dumps(data))
            with self.assertRaises(mod.Denied): mod.membership(p)

    def test_only_real_central_main_schedule_trusted(self):
        good={"GITHUB_EVENT_NAME":"schedule","GITHUB_REPOSITORY":"pgextwin/build",
              "GITHUB_REF":"refs/heads/main","GITHUB_SHA":"a"*40,"GH_TOKEN":"fixture"}
        with patch.dict(os.environ,good,clear=True),patch.object(mod,"gh_json",return_value={
              "name":"main","protected":True,"commit":{"sha":"a"*40}}):
            mod.central_schedule_gate()
        for key,invalid in (("GITHUB_EVENT_NAME","workflow_dispatch"),
                            ("GITHUB_EVENT_NAME","push"),
                            ("GITHUB_REPOSITORY","pgextwin/hypopg"),
                            ("GITHUB_REF","refs/heads/evil"),
                            ("GITHUB_SHA","b"*40),
                            ("GH_TOKEN","")):
            with self.subTest(key=key,value=invalid),patch.dict(os.environ,{**good,key:invalid},clear=True):
                with patch.object(mod,"gh_json",return_value={
                    "name":"main","protected":True,"commit":{"sha":"a"*40}}):
                    with self.assertRaises(mod.Denied): mod.central_schedule_gate()

    def test_no_candidate_is_empty_and_no_artifact_download(self):
        with patch.object(mod.recovery,"get_json",return_value=[]):
            self.assertIsNone(mod.recover_one("pgextwin/hypopg",{}))

    def test_workflow_is_exact_schedule_and_nonprivileged(self):
        src=(ROOT/".github/workflows/recover-native-pr-fleet.yml").read_text()
        self.assertIn('cron: "47 * * * *"',src)
        self.assertIn("github.event_name == 'schedule'",src)
        self.assertIn("actions: read",src)
        self.assertNotIn("workflow_dispatch:",src)
        self.assertNotIn("contents: write",src)
        self.assertNotIn("id-token: write",src)
        self.assertNotIn("attestations: write",src)
        # The first :47 schedule may be dropped by GitHub. Reuse the
        # established scanner's true schedule without granting any publish
        # rights or accepting its push/dispatch smoke as an audit.
        fallback=(ROOT/".github/workflows/fleet-upstream-watch.yml").read_text()
        self.assertIn("original-native-audit-fallback:",fallback)
        self.assertIn("github.event_name == 'schedule'",fallback)
        self.assertIn("python scripts/recover-native-pr-fleet.py",fallback)
        self.assertIn("registered-original-native-pr-audits",fallback)
        self.assertNotIn("contents: write",fallback)
        self.assertNotIn("id-token: write",fallback)
        code=(ROOT/"scripts/recover-native-pr-fleet.py").read_text()
        self.assertIn("recovery.reconcile(",code)
        self.assertIn("candidate.audit(",code)
        self.assertNotIn("gh pr merge",code)
        self.assertNotIn("gh workflow run",code)

if __name__=="__main__":main()
