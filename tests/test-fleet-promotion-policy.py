#!/usr/bin/env python3
"""Protected rollout: only locally ready BUILD extensions may be manual PUBLISH targets."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=["pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack",
          "pg_ivm","pg_qualstats","plpgsql_check"]
STAGED=["hypopg","wal2json","pg_partman","pg_stat_monitor","orafce"]

class PolicyTests(unittest.TestCase):
    def test_strict_manual_only_allowlist_before_wave2_cutover(self):
        p=json.loads((ROOT/"metadata/release-promotion.json").read_text())
        f=json.loads((ROOT/"metadata/automation-fleet.json").read_text())
        self.assertEqual(p["schemaVersion"],1)
        self.assertEqual(p["releasePolicy"],"manual-dispatch")
        self.assertEqual(set(p["allowedRepositories"]),{"pgextwin/"+x for x in ORIGINAL})
        self.assertEqual(len(p["allowedRepositories"]),len(set(p["allowedRepositories"])))
        self.assertEqual(f["releasePolicy"],"manual-only")
        entries={e["repository"]:e for e in f["entries"]}
        self.assertEqual(len(entries),14)
        for name in ORIGINAL:
            e=entries["pgextwin/"+name]
            self.assertEqual(e["mode"],"BUILD")
            self.assertIs(e["candidateEnabled"],True)
        for name in STAGED:
            e=entries["pgextwin/"+name]
            self.assertEqual(e["mode"],"OFF")
            self.assertIs(e["candidateEnabled"],False)
            self.assertNotIn("pgextwin/"+name,p["allowedRepositories"])

if __name__=="__main__":
    unittest.main()
