#!/usr/bin/env python3
"""R11 frozen workflow source and conservative job-boundary checks."""
import importlib.util
import pathlib
import unittest

TARGET = pathlib.Path(__file__).resolve().parent.parent/"scripts"/"issue311-r11-functional-boundaries.py"
spec = importlib.util.spec_from_file_location("r11_boundaries", TARGET)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

YAML = b'''name: Original\non:\n  schedule:\n    - cron: "30 * * * *"\n  push:\n    branches: [main]\njobs:\n  inspect:\n    if: github.event_name == 'schedule'\n    runs-on: ubuntu-latest\n    steps:\n      - name: Inspect\n        run: echo noop\n'''

class Tests(unittest.TestCase):
    def test_success_does_not_authorize_removal(self):
        r = m.workflow_boundary(YAML, ["30 * * * *"])
        self.assertEqual(r["jobCount"], 1)
        self.assertEqual(r["jobs"][0]["id"], "inspect")
        self.assertEqual(r["jobs"][0]["scheduleEligibility"], "UNPROVEN_CONDITIONAL_JOB")
        self.assertFalse(r["replacementAccepted"])
        self.assertFalse(r["migrationAuthorized"])

    def test_mismatch_fails_closed(self):
        with self.assertRaises(m.Denied):
            m.workflow_boundary(YAML, ["41 * * * *"])

    def test_duplicate_yaml_key_fails(self):
        with self.assertRaises(m.Denied):
            m.workflow_boundary(YAML + b"on:\n  schedule: []\n", ["30 * * * *"])

    def test_all_28_are_source_pinned(self):
        original = {"extensions":[{"repository":"pgextwin/"+str(x),"mainSha":"a"*40} for x in range(17)],
                    "central":[{"repository":"pgextwin/"+x,"mainSha":"a"*40} for x in ("build","catalog","website")]}
        rows = [{"repository":repo["repository"],"workflow":".github/workflows/up%d.yml"%k,
                 "gitBlobSha":"b"*40,"legacyCron":["30 * * * *"],
                 "retirementAuthorized":False,"replacementAccepted":False}
                for k, repo in enumerate(original["extensions"]+original["central"])]
        rows += [{**rows[k],"workflow":".github/workflows/extra%d.yml"%k} for k in range(8)]
        crosswalk = {"repositoryCount":20,"scheduleCount":28,
                     "legacySchedulesRetained":True,"allRetirementDeniedUntilIndependentProof":True,
                     "rows":rows}
        with self.assertRaises(m.Denied):
            m.produce(original,crosswalk,lambda repo,path,head:("c"*40,YAML))

    def test_untrusted_blob_refused(self):
        with self.assertRaises(m.Denied):
            m.get_workflow("evil/other", ".github/workflows/test.yml", "a"*40, "token")

if __name__ == "__main__":
    unittest.main()
