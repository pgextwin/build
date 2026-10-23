#!/usr/bin/env python3
"""Adversarial offline Grype risk classifications: never a Release grant."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "vulnerability",root/"scripts"/"automatic-grype-publisher-policy.py")
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
STEM="pg_ivm-v1.0-pg18-windows-x64"


def report():
    return {
        "matches":[],"ignoredMatches":[],
        "descriptor":{
            "name":"grype","version":"0.120.1",
            "db":{"status":{"valid":True,"schemaVersion":"v6",
                            "built":"2026-10-23T00:00:00Z",
                            "from":"2026-10-23T00:00:00Z"},
                  "providers":{"nvd":{}}},
            "configuration":{"match-upstream-kernel-headers":True,
                             "ignore":[],"fail-on-severity":""}},
        "source":{"type":"file","target":STEM},
    }


def finding(severity="High"):
    return {"vulnerability":{"id":"CVE-2026-example","severity":severity},
            "artifact":{"name":"library.dll"},
            "matchDetails":[{"matcher":"dpkg","type":"exact-direct-match"}]}


class RiskRules(unittest.TestCase):
    def test_clean_and_nonblocking_findings_still_no_publish(self):
        x=policy.review(report(),asset_stem=STEM)
        self.assertEqual(x["status"],"NO_BLOCKING_FINDINGS")
        self.assertIs(x["publicationAuthorized"],False)
        r=report()
        r["matches"]=[finding("Medium"),finding("Low"),finding("Negligible")]
        x=policy.review(r,asset_stem=STEM)
        self.assertEqual(x["blockingFindingCount"],0)
        self.assertEqual(sum(x["findingCountBySeverity"].values()),3)
        self.assertIs(x["publicationAuthorized"],False)

    def test_high_critical_and_unknown_block(self):
        for severity in ("Critical","High","Unknown"):
            with self.subTest(severity=severity):
                r=report()
                r["matches"]=[finding(severity)]
                x=policy.review(r,asset_stem=STEM)
                self.assertEqual(x["status"],"BLOCKING_FINDINGS")
                self.assertEqual(x["blockingFindingCount"],1)
                self.assertIs(x["publicationAuthorized"],False)

    def test_missing_invalid_filtered_and_suppressed_data_denied(self):
        mutations=(
            lambda r:r.pop("matches"),
            lambda r:r.update(matches={}),
            lambda r:r.update(ignoredMatches=[finding()]),
            lambda r:r["descriptor"].update(name="not-grype"),
            lambda r:r["descriptor"].update(version="floating"),
            lambda r:r["descriptor"]["db"]["status"].update(valid=False),
            lambda r:r["descriptor"]["db"]["status"].pop("built"),
            lambda r:r["descriptor"]["db"].update(providers={}),
            lambda r:r["descriptor"].pop("configuration"),
            lambda r:r["descriptor"]["configuration"].update(ignore=[{"name":"x"}]),
            lambda r:r["descriptor"]["configuration"].update(**{"fail-on-severity":"high"}),
            lambda r:r["descriptor"]["configuration"].update(**{"match-upstream-kernel-headers":False}),
            lambda r:r["source"].update(target="other.zip"),
            lambda r:r["source"].update(type="image"),
            lambda r:r.update(matches=[{}]),
            lambda r:r.update(matches=[{"vulnerability":{"id":"x","severity":"High"}}]),
            lambda r:r.update(matches=[finding("Unclassified")]),
            lambda r:r.update(matches=[{**finding(),"matchDetails":[]}]),
            lambda r:r.update(matches=[{**finding(),"artifact":{"name":""}}]),
        )
        for index,change in enumerate(mutations):
            r=report()
            change(r)
            with self.subTest(index=index),self.assertRaises(policy.Denied):
                policy.review(r,asset_stem=STEM)
        for value in ("", "../escape", "path/evil", "unsafe\\path"):
            with self.subTest(stem=value),self.assertRaises(policy.Denied):
                policy.review(report(),asset_stem=value)


if __name__=="__main__":
    unittest.main()
