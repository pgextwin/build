#!/usr/bin/env python3
"""17-member operator-only formal Release; automatic publication remains DENY."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=["pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user","pg_repack",
          "pg_ivm","pg_qualstats","plpgsql_check"]
STAGED=["hypopg","wal2json","pg_partman","pg_stat_monitor","orafce"]
THIRD=["pgtap","pg_variables","pg_store_plans"]

class PolicyTests(unittest.TestCase):
    def test_exact_seventeen_repository_operator_publish_allowlist(self):
        p=json.loads((ROOT/"metadata/release-promotion.json").read_text())
        f=json.loads((ROOT/"metadata/automation-fleet.json").read_text())
        self.assertEqual(p["schemaVersion"],1)
        self.assertEqual(p["releasePolicy"],"manual-dispatch")
        self.assertEqual(set(p["allowedRepositories"]),{"pgextwin/"+x for x in ORIGINAL+STAGED+THIRD})
        self.assertEqual(len(p["allowedRepositories"]),len(set(p["allowedRepositories"])))
        self.assertEqual(f["releasePolicy"],"manual-only")
        entries={e["repository"]:e for e in f["entries"]}
        self.assertEqual(len(entries),17)
        self.assertEqual(set(entries),set(p["allowedRepositories"]))
        # This enablement admits only human-confirmed PUBLISH; build success alone
        # never authorizes publication, and automated Release remains prohibited.
        for name in ORIGINAL+STAGED:
            e=entries["pgextwin/"+name]
            self.assertEqual(e["mode"],"BUILD")
            self.assertIs(e["candidateEnabled"],True)
            self.assertEqual(e["releasePolicy"],"manual-only")
        for name in THIRD:
            e=entries["pgextwin/"+name]
            self.assertEqual(e["mode"],"BUILD")
            self.assertIs(e["candidateEnabled"],True)
            self.assertEqual(e["releasePolicy"],"manual-only")

    def test_operator_publish_allowlist_does_not_authorize_unattended_formal_release(self):
        unattended=json.loads((ROOT/"metadata/unattended-publication.json").read_text())
        downstream=json.loads((ROOT/"metadata/manual-release-downstream.json").read_text())
        self.assertEqual(unattended["mode"],"OBSERVE")
        self.assertEqual(unattended["defaultAction"],"DENY")
        self.assertIs(unattended["controls"]["automaticFormalRelease"],False)
        self.assertIs(unattended["controls"]["automaticCandidateMerge"],False)
        self.assertIs(unattended["controls"]["automaticCatalogMerge"],False)
        self.assertIs(downstream["enabled"],False)
        self.assertEqual(downstream["mode"],"POST_MANUAL_RELEASE_ONLY")
        self.assertIs(downstream["automaticFormalRelease"],False)
        self.assertIs(downstream["automaticCatalogMerge"],False)

if __name__=="__main__":
    unittest.main()
