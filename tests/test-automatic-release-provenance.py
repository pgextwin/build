#!/usr/bin/env python3
"""Hostile offline public locator and existing Publisher Release notes tests.

Neither a Release note nor these synthetic fixtures authorize publication.
"""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
import importlib.util

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

loc=load("auto_pub_locator","scripts/automatic-release-provenance.py")
auth_fixture=load("auto_pub_test_receipt","tests/test-release-authorization.py")
formal=load("auto_pub_formal","scripts/fleet-publish-release.py")
REPO="pgextwin/wal2json"
SHA="a"*40
TAG="v2.7-windows.2"

def receipt():
    r=auth_fixture.automatic_fixture()
    r["extension"]="wal2json"
    return r

class LocatorTests(TestCase):
    def test_public_locator_is_not_an_authorization(self):
        text=loc.encode(receipt())
        self.assertTrue(text.startswith(loc.PREFIX))
        self.assertEqual(loc.decode("release\n"+text+"\n"),loc.claim(receipt()))
        assert "synthetic" not in text
        for forbidden in ("operator","token","privateKey","publishableReceipt"):
            self.assertNotIn(forbidden,text)

    def test_manual_release_does_not_emit_automatic_locator(self):
        with self.assertRaises(loc.Denied):
            loc.encode(auth_fixture.fixture())
        with self.assertRaises(loc.Denied):
            loc.decode("normal manual release notes without new evidence")

    def test_duplicate_forged_and_replayed_locator_denied(self):
        r=receipt()
        bad=[
            lambda x:x.update(sourceRunAttempt=2),
            lambda x:x.update(sourceRunId=True),
            lambda x:x.update(sourceRunId=89753),
            lambda x:x.update(publisherRunId=0),
            lambda x:x.update(publisherRunAttempt=2),
            lambda x:x.update(publisherMainSha="not-sha"),
            lambda x:x.update(publisherAppId=15368),
            lambda x:x.update(repository="pgextwin/evil/xx"),
            lambda x:x.update(releaseTag="../test"),
            lambda x:x.update(approvalProvenance="USER_APPROVED"),
            lambda x:x.update(authorizationMode="manual-dispatch"),
            lambda x:x.update(unexpected=True),
        ]
        for n,mutate in enumerate(bad):
            with self.subTest(n=n):
                data=deepcopy(loc.claim(r))
                mutate(data)
                with self.assertRaises(loc.Denied):
                    loc.validate(data)
        marker=loc.encode(r)
        with self.assertRaises(loc.Denied):
            loc.decode(marker+"\n"+marker)
        with self.assertRaises(loc.Denied):
            loc.decode(marker.replace(',"repository"',',"repository"')) if False else loc.decode(
                marker.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'))
        with self.assertRaises(loc.Denied):
            loc.decode(marker+" trailing rubbish")

    def test_existing_formal_writer_includes_marker_only_for_auto(self):
        for auto in (False,True):
            with self.subTest(auto=auto),TemporaryDirectory() as d:
                folder=Path(d)
                (folder/"sample.zip").write_bytes(b"synthetic")
                expected={"sample.zip": formal.digest(folder/"sample.zip")}
                info=receipt() if auto else auth_fixture.fixture()
                with patch.object(formal,"REPO",REPO), \
                     patch.object(formal,"absent"), \
                     patch.object(formal,"run",return_value=""), \
                     patch.object(formal,"staged_release_id",return_value=123), \
                     patch.object(formal,"check_remote") as verify:
                    result=formal.publish_preverified(
                        folder,{"name":"wal2json"},info,SHA,
                        expected,folder/"state.json",publish_run_id=89753)
                    self.assertEqual(result,0)
                    notes=(folder/"state.md").read_text()
                    if auto:
                        self.assertEqual(loc.decode(notes),loc.claim(info))
                    else:
                        with self.assertRaises(loc.Denied):
                            loc.decode(notes)
                    self.assertEqual(verify.call_count,2)

if __name__=="__main__":main()
