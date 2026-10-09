#!/usr/bin/env python3
"""No-network Stage 21 release publisher safety/denial matrix."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED

p=Path(__file__).resolve().parents[1]/"scripts"/"publish-release.py"
sp=importlib.util.spec_from_file_location("publisher",p)
pub=importlib.util.module_from_spec(sp)
sp.loader.exec_module(pub)

class Publisher(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.source="a"*40
        self.commit="b"*40
        self.runid=1009
        self.manifest={"name":"plpgsql_check","upstream":
                       {"version":"2.10.14","ref":"v2.10.14","commit":self.source}}
        self.receipt={"schemaVersion":1,"status":"VERIFIED_APPROVED",
                      "repository":pub.REPO,"trustedCommit":self.commit,
                      "extension":"plpgsql_check","version":"2.10.14",
                      "upstreamCommit":self.source,"upstreamRef":"v2.10.14",
                      "majors":[15,16,17,18]}
        for m in (15,16,17,18):
            stem="plpgsql_check-v2.10.14-pg"+str(m)+"-windows-x64"
            info={"buildMode":"release-attested","package":{"name":"plpgsql_check"},
                  "postgresql":{"major":m},"upstream":{"commit":self.source,"ref":"v2.10.14"},
                  "source":{"packagingRepository":pub.REPO,"packagingCommit":self.commit},
                  "workflowRun":{"id":self.runid,"event":"workflow_dispatch",
                                 "ref":"refs/heads/main"}}
            with ZipFile(self.folder/(stem+".zip"),"w",ZIP_DEFLATED) as z:
                z.writestr("PACKAGE-INFO.json",json.dumps(info))
            (self.folder/(stem+".spdx.json")).write_text('{"spdxVersion":"SPDX-2.3"}')
            (self.folder/(stem+".vulnerabilities.json")).write_text('{"matches":[]}')

    def verify(self,attest=False):
        return pub.check_assets(self.folder,self.manifest,self.receipt,self.commit,self.runid,
                                verify_signatures=attest)

    def test_all_four_major_assets_allowed_offline(self):
        self.assertEqual(len(self.verify()),12)

    def test_absent_asset_rejected(self):
        next(self.folder.glob("*pg16*.spdx.json")).unlink()
        with self.assertRaises(Exception):self.verify()

    def test_invalid_upstream_commit_rejected(self):
        self.receipt["upstreamCommit"]="c"*40
        with self.assertRaises(pub.Denied):self.verify()

    def test_unapproved_receipt_rejected(self):
        self.receipt["status"]="PENDING"
        with self.assertRaises(pub.Denied):self.verify()

    def test_pg_major_missing_rejected(self):
        self.receipt["majors"]=[15,16,17]
        with self.assertRaises(pub.Denied):self.verify()

    def test_wrong_package_source_rejected(self):
        self.receipt["trustedCommit"]="e"*40
        with self.assertRaises(pub.Denied):self.verify()

    def test_missing_attestation_verification_denies(self):
        with patch.object(pub,"run",side_effect=pub.Denied("fake invalid signature")):
            with self.assertRaises(pub.Denied):self.verify(attest=True)

    def test_release_already_exists_rejected(self):
        with patch.object(pub,"get",side_effect=lambda p:{"tag_name":"exists"}):
            with self.assertRaises(pub.Denied):pub.absent("v2.10.14-windows.1")

    def test_api_failure_denies_no_create(self):
        with patch.object(pub,"get",side_effect=pub.Denied("HTTP 503")):
            with self.assertRaises(pub.Denied):pub.absent("v2.10.14-windows.1")

    def test_partial_draft_asset_set_rejected(self):
        release={"tag_name":"v2.10.14-windows.1","draft":True,"assets":[]}
        with patch.object(pub,"get",return_value=release):
            with self.assertRaises(pub.Denied):
                pub.check_remote("v2.10.14-windows.1",{"x.zip":"f"*64},True)

if __name__=="__main__":unittest.main()
