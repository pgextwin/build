"""Adversarial contract for a new exact HypoPG three-PG owner-signed cohort.

Synthetics are deliberately NOT authentic signed permission; no GitHub calls.
"""
import copy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

issuer = load("hypopg_cohort_subject", "external-direct-get-hypopg-issuer.py")
proposer = load("hypopg_cohort_pr", "external-direct-get-hypopg-pin-pr.py")
now = datetime(2026,11,8,9,0,0,tzinfo=timezone.utc)


def fake_subject():
    rows=[]
    for pg, (aid,size,sha) in issuer.PINS.items():
        rows.append(({
            "pgMajor":pg,"targetEnvironment":f"EDB PostgreSQL {pg}.15.5 Windows x64 exact original historical binary",
            "assetName":f"hypopg-1.4.1-pg{pg}-x64.zip","assetId":aid,
            "originalBytes":size,"originalSha256":sha,
            "originalProviderUrl":f"https://github.com/HypoPG/hypopg/releases/download/1.4.1/hypopg-1.4.1-pg{pg}-x64.zip",
            "licenseUrl":"https://github.com/HypoPG/hypopg/blob/1.4.1/LICENSE",
            "noticeTreatment":"Original source lacks bundled LICENSE; exact-tag LICENSE link is shown for end-user review and mirroring is denied.",
            "dependencyTreatment":"Source binary tested for its exact PG ABI on Windows; all prerequisites stay user-owned, with no redistribution."
        }, {"zipCrc":"PASS"}))
    return issuer.manifest("a"*40,1234,"b"*40,rows,now)


class Cohort(unittest.TestCase):
    def test_complete_source_shape_only_not_signed(self):
        d=fake_subject()
        self.assertEqual(len(d["records"]),3)
        result=proposer.verify_hypopg_manifest(
            d,"a"*40,"b"*40,1234,now+timedelta(minutes=1))
        self.assertEqual(result,now+timedelta(hours=6))
        self.assertFalse(d["mirrorAuthorized"])
        self.assertTrue(d["downloadAuthorized"])
        self.assertEqual(d["issuerEvent"],"workflow_dispatch")

    def test_adversarial_manifest_denied(self):
        for case in ("mirror","owner","asset","hash","source","missing","duplicate",
                     "expired","added","publisher","operation","pg"):
            d=copy.deepcopy(fake_subject())
            if case=="mirror":d["mirrorAuthorized"]=True
            elif case=="owner":d["ownerId"]=2
            elif case=="asset":d["records"][1]["assetId"]=1
            elif case=="hash":d["records"][2]["originalSha256"]="0"*64
            elif case=="source":d["records"][0]["sourceRepo"]="laurenz/oracle_fdw"
            elif case=="missing":d["records"]=d["records"][:2]
            elif case=="duplicate":d["records"].append(copy.deepcopy(d["records"][0]))
            elif case=="expired":d["expiresAt"]="2020-01-01T00:00:00Z"
            elif case=="added":d["untrustedAuthorization"]=True
            elif case=="publisher":d["publisherEnvironment"]="unreviewed"
            elif case=="operation":d["approvedOperation"]="MIRROR"
            elif case=="pg":d["records"][0]["pgMajor"]="17"
            with self.subTest(case=case), self.assertRaises(Exception):
                proposer.verify_hypopg_manifest(
                    d,"a"*40,"b"*40,1234,now+timedelta(minutes=1))

    def test_create_only_metadata_paths_not_zip(self):
        self.assertEqual(proposer.path_for(1234, "external-get-admission.json"),
                         "external/signed-direct-get/hypopg/run-1234/external-get-admission.json")
        for name in ("provider.zip", "../attestation.json", "setup.exe"):
            with self.assertRaises(Exception): proposer.path_for(1234,name)

    def test_workflow_requires_authentic_owner_and_independent_sigstore(self):
        import yaml
        doc=yaml.load((ROOT/".github/workflows/external-direct-get-issuer.yml").read_text(),
                      Loader=yaml.BaseLoader)
        self.assertEqual(set(doc["on"]),{"workflow_dispatch"})
        inputs=doc["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs["extension"]["options"]),{"pg_trickle","hypopg"})
        self.assertEqual(doc["jobs"]["issue-and-attest"]["environment"],
                         "external-direct-provider-publisher")
        self.assertEqual(doc["jobs"]["propose-public-pin-pr"]["environment"],
                         "external-direct-provider-publisher")
        self.assertNotIn("environment",doc["jobs"]["independent-verify"])
        self.assertIn("gh attestation verify",doc["jobs"]["independent-verify"]["steps"][1]["run"])
        self.assertIn("SOURCE_RECHECK", (ROOT/"scripts/external-direct-get-hypopg-issuer.py").read_text())

    def test_source_fetcher_has_no_upload_or_release_api(self):
        s=(ROOT/"scripts/external-direct-get-originals.sh").read_text()
        self.assertIn("refs/heads/main",s)
        self.assertIn("workflow_dispatch",s)
        self.assertIn("shasum" if "shasum" in s else "sha256sum",s)
        self.assertNotIn("gh release upload",s)
        self.assertNotIn("actions/upload-artifact",s)


if __name__ == "__main__":
    unittest.main()
