"""Focused adversarial contract for portalcorp one-asset owner-signed GET-only."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import copy
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
issuer=load("portalcorp_exact_issuer","external-direct-get-portalcorp-issuer.py")
proposer=load("portalcorp_exact_pin","external-direct-get-portalcorp-pin-pr.py")
NOW=datetime(2026,11,9,tzinfo=timezone.utc)

def record():
    d=dict(proposer.EXPECTED)
    d["targetEnvironment"]="EDB PostgreSQL 16.15.5 Windows x64; original third-party pgvector binary with exact version 0.8.0"
    d["noticeTreatment"]="MIT packaging license plus upstream PostgreSQL source license https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE; no pgextwin ZIP redistribution"
    d["dependencyTreatment"]="Real Windows PG16 runtime dependency tested, no general transitive deployment compatibility guaranteed."
    return d

class PortalcorpCohort(unittest.TestCase):
    def test_exact_manifest_and_denial(self):
        doc=issuer.manifest("a"*40,12345,"b"*40,record(),
             {"bytes":163732,"sha256":issuer.ASSET_SHA,"zipMembers":48},NOW)
        self.assertEqual(proposer.verify_portalcorp_manifest(
            doc,"a"*40,"b"*40,12345,NOW),
            NOW+timedelta(hours=6))
        self.assertEqual(proposer.path_for(12345,"attestation.json"),
                         "external/signed-direct-get/portalcorp_pgvector/run-12345/attestation.json")
        for field,value in (("originalSha256","0"*64),("sourceRepo","laurenz/oracle_fdw"),
                            ("pgMajor","18"),("assetId",1),("mirrorAuthorized",True),
                            ("noticeTreatment","no notice")):
            d=copy.deepcopy(doc)
            d["records"][0][field]=value
            with self.subTest(field=field),self.assertRaises(proposer.Denied if hasattr(proposer,"Denied") else proposer.old.Denied):
                proposer.verify_portalcorp_manifest(d,"a"*40,"b"*40,12345,NOW)
        with self.assertRaises(proposer.old.Denied):
            proposer.verify_portalcorp_manifest(doc,"a"*40,"b"*40,12345,
                                                NOW+timedelta(hours=7))
        with self.assertRaises(issuer.old.Denied):
            issuer.manifest("a"*40,12345,"b"*40,record(),
                {"bytes":163732,"sha256":"0"*64,"zipMembers":48},NOW)

    def test_workflow_owner_and_no_public_zip(self):
        workflow=(ROOT/".github/workflows/external-direct-get-issuer.yml").read_text()
        sh=(ROOT/"scripts/external-direct-get-originals.sh").read_text()
        self.assertIn("portalcorp_pgvector",workflow)
        self.assertIn("portalcorp_pgvector)",sh)
        self.assertIn("python3 scripts/external-direct-get-portalcorp-issuer.py",workflow)
        self.assertIn("python3 scripts/external-direct-get-portalcorp-pin-pr.py",workflow)
        self.assertNotIn("actions/upload-release-asset",workflow)
        self.assertNotIn("gh release create",workflow)
if __name__=="__main__":
    unittest.main()
