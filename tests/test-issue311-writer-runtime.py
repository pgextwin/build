#!/usr/bin/env python3
"""Issue311 dedicated Writer: offline hostile CAS, fencing, claim and scope tests."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location(
    "issue311_writer", Path(__file__).resolve().parents[1] /
    "scripts" / "issue311-writer-runtime.py")
writer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)
HASH="9"*64
NOW=datetime(2026,10,29,tzinfo=timezone.utc)


class WriterTests(unittest.TestCase):
    def base(self):
        return writer.new_ledger(HASH)

    def test_exact_nonpublic_schema_and_lease_fencing(self):
        state=self.base()
        one=writer.lease_next(state,"run-1.1.lease",NOW,"LEASED")
        self.assertEqual(state["revision"],0)
        self.assertEqual(one["revision"],1)
        self.assertEqual(one["lease"]["generation"],1)
        self.assertEqual(one["lease"]["scope"],"READONLY")
        with self.assertRaises(writer.Denied):
            writer.lease_next(one,"run-2.1.recover",NOW+timedelta(seconds=119),"RECOVERED")
        two=writer.lease_next(one,"run-2.1.recover",
                              NOW+timedelta(seconds=120),"RECOVERED")
        self.assertEqual(two["lease"]["generation"],2)
        self.assertEqual(two["phase"],"RECOVERED")
        with self.assertRaises(writer.Denied):
            writer.lease_next(two,"run-3.1.recover",
                              NOW+timedelta(seconds=240),"RECOVERED")
        with self.assertRaises(writer.Denied):
            writer.lease_next(one,"run-1.1.lease",
                              NOW+timedelta(seconds=121),"RECOVERED")

    def test_same_global_ledger_conflicting_candidate_is_atomic(self):
        base=self.base()
        first=writer.claim_candidate(base,"r-20261029-aaaaaaaa",
                                     "pgextwin/orafce","a"*40)
        self.assertEqual(base["candidateClaims"],{})
        self.assertEqual(first["revision"],1)
        same=writer.claim_candidate(first,"r-20261029-aaaaaaaa",
                                    "pgextwin/orafce","a"*40)
        self.assertEqual(same,first)
        with self.assertRaises(writer.Denied):
            writer.claim_candidate(first,"r-20261029-bbbbbbbb",
                                   "pgextwin/orafce","a"*40)
        other=writer.claim_candidate(first,"r-20261029-bbbbbbbb",
                                     "pgextwin/pg_ivm","b"*40)
        self.assertEqual(other["revision"],2)

    def test_denies_privileged_schema_and_forged_lease(self):
        base=self.base()
        for change in (
            {"publisherAuthorized":True},
            {"writeOutcomeUnknown":True},
            {"scope":"PUBLISH"},
            {"candidateClaims":[]},
            {"revision":True},
            {"unknownPermission":True},
            {"requestSha256":"bad"},
        ):
            with self.subTest(change=change),self.assertRaises(writer.Denied):
                writer.validate_ledger(dict(base,**change))
        for bad_repo,bad_sha in (
            ("another/repo","a"*40),("../etc","a"*40),
            ("pgextwin/build","xyz")
        ):
            with self.assertRaises(writer.Denied):
                writer.claim_candidate(base,"r-20261029-aaaaaaaa",bad_repo,bad_sha)

    def test_cas_original_bytes_consistency(self):
        data=writer.canonical(self.base())
        self.assertEqual(data,writer.canonical(self.base()))
        self.assertIn(b'"publisherAuthorized":false',data)
        self.assertIn(b'"candidateClaims":{}',data)
        self.assertEqual(writer.STATE_BRANCH,"issue311-state")
        self.assertEqual(writer.STATE_PATH,"checkpoints/issue311-ledger-v1.json")
        self.assertEqual(writer.APP_ID,5517840)
        self.assertEqual(writer.INSTALLATION_ID,176347451)

    def test_revoke401_bounded_readonly_propagation_or_denial(self):
        def eventual(method,endpoint,token,payload=None):
            if method == "DELETE":
                self.assertEqual(endpoint,"installation/token")
                return {}
            if method == "GET":
                self.assertIn("README.md",endpoint)
                if eventual.count < 2:
                    eventual.count += 1
                    return {"notYetRevoked":True}
                raise writer.HTTPStatus(401)
            self.fail("unexpected API method")
        eventual.count=0
        with mock.patch.object(writer,"api",side_effect=eventual),mock.patch.object(writer.time,"sleep") as pause:
            writer.revoke_and_prove_401("masked-token")
            self.assertEqual(pause.call_count,2)
        def never(method,endpoint,token,payload=None):
            return {}
        with mock.patch.object(writer,"api",side_effect=never),mock.patch.object(writer.time,"sleep") as pause:
            with self.assertRaises(writer.Denied):
                writer.revoke_and_prove_401("masked-token")
            self.assertEqual(pause.call_count,9)

    def test_no_publisher_endpoints_in_runtime(self):
        source=Path(writer.__file__).read_text()
        for prohibited in ('/releases', '/git/refs/tags', '/dispatches',
                           'PUBLISH_ELIGIBLE', 'GH_TOKEN',
                           'PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY'):
            self.assertNotIn(prohibited,source)


if __name__=="__main__":
    unittest.main()
