#!/usr/bin/env python3
"""No-network test: a downstream opt-in never authorizes unattended formal Release."""
import copy
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
P=ROOT/"metadata/manual-release-downstream.json"
FIELDS={"schemaVersion","enabled","mode","releasePolicy","automaticFormalRelease",
        "automaticCatalogMerge","allowedExtensions","requiredCatalogWorkflow",
        "requirePublishedPublicRelease","requireBuildProvenanceAttestation",
        "requireSbomAttestation","requireExactSHA256","requireExactHeadRequiredChecks",
        "requireDedicatedMergeApp","denyUnknownOrDuplicate","notes"}
SAFE_FLAGS={"requirePublishedPublicRelease","requireBuildProvenanceAttestation",
            "requireSbomAttestation","requireExactSHA256","requireExactHeadRequiredChecks",
            "requireDedicatedMergeApp","denyUnknownOrDuplicate"}

def validate(v):
    if (type(v) is not dict or set(v)!=FIELDS or v["schemaVersion"]!=1
        or v["mode"]!="POST_MANUAL_RELEASE_ONLY"
        or v["releasePolicy"]!="manual-dispatch"
        or v["automaticFormalRelease"] is not False
        or type(v["enabled"]) is not bool or type(v["automaticCatalogMerge"]) is not bool
        or v["requiredCatalogWorkflow"]!="validate.yml"
        or v["allowedExtensions"]!=["plpgsql_check"]
        or not all(v[k] is True for k in SAFE_FLAGS)
        or not isinstance(v["notes"],str) or not v["notes"]):
        raise ValueError("unsafe manual-only downstream policy")
    if v["automaticCatalogMerge"] is True and v["enabled"] is not True:
        raise ValueError("Catalog merge cannot activate without explicit enabled")
    return True

class Downstream(unittest.TestCase):
    def test_production_default_is_disabled(self):
        data=json.loads(P.read_text())
        validate(data)
        self.assertFalse(data["enabled"])
        self.assertFalse(data["automaticCatalogMerge"])
        self.assertFalse(data["automaticFormalRelease"])
    def test_manual_only_optin_never_grants_formal_publishing(self):
        current=json.loads(P.read_text())
        future=copy.deepcopy(current)
        future["enabled"]=True
        future["automaticCatalogMerge"]=True
        self.assertTrue(validate(future))
        for change in (
            lambda x:x.update(automaticFormalRelease=True),
            lambda x:x.update(releasePolicy="automatic"),
            lambda x:x.update(mode="UNATTENDED"),
            lambda x:x.update(allowedExtensions=["evil"]),
            lambda x:x.update(requiredCatalogWorkflow="unsafe.yml"),
            lambda x:x.update(requireExactSHA256=False),
            lambda x:x.update(requireDedicatedMergeApp=False),
            lambda x:x.update(denyUnknownOrDuplicate=False),
            lambda x:x.update(enabled=False),
        ):
            bad=copy.deepcopy(future)
            change(bad)
            with self.assertRaises(ValueError):validate(bad)

if __name__=="__main__":
    unittest.main()
