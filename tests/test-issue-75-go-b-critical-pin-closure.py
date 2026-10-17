#!/usr/bin/env python3
"""Offline hostile tests of the pinned GO B dependency/permission snapshot.

No CI-issued credentials, GitHub network, Signed promotion or Publisher writes.
The 'PASS' boundary is only structure of a GitHub snapshot that was separately
GET-audited; structural tests never become new signatures or Release approval.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/issue-75/critical-pin-closure-20261017.json"

def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m = load("scripts/issue-75-go-b-critical-pin-closure.py", "issue75_closure")
recovery_fixture = load("tests/test-release-recovery-evidence.py",
                        "issue75_existing_v2_recovery_fixture")

def original():
    return m.read_record(EVIDENCE)

class CriticalPinBoundaryTests(TestCase):
    def assert_no_permission(self, out):
        self.assertIs(out["publicationAuthorized"], False)
        self.assertIs(out["publishableReceipt"], False)
        self.assertIs(out["mutationAuthorized"], False)
        self.assertEqual(out["goB"], "NO_GO")
        self.assertEqual(out["g4"], "NO_GO")
        self.assertEqual(out["g5"], "NO_GO")

    def test_observed_32_critical_blobs_are_structurally_complete_but_never_go_b(self):
        s = original()
        v = m.inspect(s)
        self.assertEqual(v["criticalPathsObserved"], 32)
        self.assertTrue(v["signerBlobShared"])
        self.assertEqual(v["publisherActualPin"], m.LEGACY)
        self.assertEqual(v["publisherCurrentReviewedSha"], m.BASE_CURRENT)
        self.assertEqual(v["signerPin"], m.SIGNER)
        self.assertEqual(v["recoveryV2Classification"], "NOT_OBSERVED")
        self.assertFalse(v["readerRuntimeCredentialsVerified"])
        self.assertFalse(v["writerIsolationRuntimeVerified"])
        self.assertFalse(v["realPositivePrewriteVerified"])
        self.assertFalse(v["recoveryV2WriterDeployed"])
        self.assert_no_permission(v)

    def test_historically_identical_signer_does_not_upgrade_deployed_publisher(self):
        s = original()
        hashes = [s["roots"][n]["blobs"][
            ".github/workflows/build-extension-attested.yml"]
            for n in ("legacy", "signer", "current")]
        self.assertEqual(hashes, [m.SIGNER_BLOB] * 3)
        self.assertNotEqual(s["roots"]["legacy"]["blobs"][
            "scripts/fleet-publish-release.py"],
            s["roots"]["current"]["blobs"]["scripts/fleet-publish-release.py"])
        self.assert_no_permission(m.inspect(s))

    def test_wrong_root_commit_repo_and_missing_or_added_critical_path_deny(self):
        cases = [
            lambda x: x["roots"]["pilot"].update(commit="f" * 40),
            lambda x: x["roots"]["legacy"].update(repository="evil/repo"),
            lambda x: x["roots"]["current"]["blobs"].pop(
                "scripts/release-recovery-evidence.py"),
            lambda x: x["roots"]["signer"]["blobs"].update(
                **{"unexpected.py": "f" * 40}),
            lambda x: x["roots"]["legacy"]["blobs"].update(
                **{"scripts/fleet-publish-release.py": "0" * 40}),
            lambda x: x["roots"]["current"]["blobs"].update(
                **{"scripts/fleet-promotion-gate.py": "f" * 40}),
            lambda x: x["roots"].pop("signer"),
            lambda x: x["roots"].update(forged={}),
            lambda x: x.update(schemaVersion=2),
        ]
        for i, change in enumerate(cases):
            with self.subTest(case=i):
                s = original()
                change(s)
                with self.assertRaises(m.Deny):
                    m.inspect(s)

    def test_source_signer_lifecycle_abi_contract_and_workflow_pin_mismatch_deny(self):
        cases = [
            lambda s: s["roots"]["signer"]["blobs"].update(
                **{".github/workflows/build-extension-attested.yml": "f"*40}),
            lambda s: s["roots"]["legacy"]["blobs"].update(
                **{"metadata/postgresql.json": "f"*40}),
            lambda s: s["roots"]["current"]["blobs"].update(
                **{"scripts/fleet-release-identity.py": "0"*40}),
            lambda s: s["pilotWorkflow"].update(signerReusableSha="f"*40),
            lambda s: s["pilotWorkflow"].update(authorizeCheckoutSha="f"*40),
            lambda s: s["pilotWorkflow"].update(publisherCheckoutSha=m.BASE_CURRENT),
            lambda s: s["pilotWorkflow"].update(trigger="push"),
            lambda s: s["pilotWorkflow"].update(persistCredentials=True),
        ]
        for i, change in enumerate(cases):
            with self.subTest(case=i):
                s = original()
                change(s)
                with self.assertRaises(m.Deny):
                    m.inspect(s)

    def test_token_separation_static_job_permission_changes_denied(self):
        cases = [
            lambda s: s["pilotWorkflow"]["authorizePermissions"].append(
                "contents:write"),
            lambda s: s["pilotWorkflow"]["buildPermissions"].append(
                "contents:write"),
            lambda s: s["pilotWorkflow"]["publishPermissions"].append(
                "id-token:write"),
            lambda s: s["pilotWorkflow"]["publishPermissions"].append(
                "catalog:actions:write"),
            lambda s: s["pilotWorkflow"]["catalogAppPermissions"].append(
                "contents:write"),
            lambda s: s["pilotWorkflow"]["authorizePermissions"].pop(),
            lambda s: s["pilotWorkflow"]["buildPermissions"].append(
                "id-token:write"),
            lambda s: s["pilotWorkflow"].update(
                catalogPermissions=["contents:write"]),
        ]
        for i, change in enumerate(cases):
            with self.subTest(case=i):
                s = original()
                change(s)
                with self.assertRaises(m.Deny):
                    m.inspect(s)

    def test_witness_gap_and_capability_claims_can_never_be_forged(self):
        cases = [
            lambda s: s["knownGaps"].remove("noRealSignedPublisherPositivePrewrite"),
            lambda s: s["knownGaps"].append("noRealSignedPublisherPositivePrewrite"),
            lambda s: s["knownGaps"].append("someFutureGap"),
            lambda s: s["acceptance"].update(signedArtifactsVerified=True),
            lambda s: s["acceptance"].update(writerTokenIsolationProven=True),
            lambda s: s["acceptance"].update(recoveryV2WriterDeployed=True),
            lambda s: s["acceptance"].update(pinCutoverAuthorized=True),
            lambda s: s["acceptance"].update(publicationAuthorized=True),
            lambda s: s["acceptance"].update(goB="GO"),
            lambda s: s["acceptance"].update(publishableReceipt="false"),
        ]
        for i, change in enumerate(cases):
            with self.subTest(case=i):
                s = original()
                change(s)
                with self.assertRaises(m.Deny):
                    m.inspect(s)

    def test_reuse_existing_recovery_v2_classifier_only_never_writer(self):
        s = original()
        record = recovery_fixture.evidence("DRAFT_VERIFIED")
        remote = recovery_fixture.snapshot("DRAFT_VERIFIED")
        result = m.inspect(s, v2=record, remote=[remote, copy.deepcopy(remote)])
        self.assertEqual(result["recoveryV2Classification"],
                         "CONSISTENT_READ_ONLY")
        self.assert_no_permission(result)
        v1 = {"schemaVersion": 1, "state": "DRAFT_STAGED", "runId": 123}
        result = m.inspect(s, v2=v1, remote=[remote, copy.deepcopy(remote)])
        self.assertEqual(result["recoveryV2Classification"],
                         "UNKNOWN_QUARANTINE")
        self.assert_no_permission(result)

    def test_partial_draft_lost_post_http_422_and_stale_get_never_resume(self):
        from copy import deepcopy
        record = recovery_fixture.evidence("DRAFT_STAGED")
        observed = recovery_fixture.snapshot("DRAFT_STAGED")
        mutations = [
            lambda r,a,b: r["reservation"].update(httpStatus=422),
            lambda r,a,b: r["reservation"].update(outcome="UNKNOWN"),
            lambda r,a,b: r.pop("releaseId"),
            lambda r,a,b: a["release"].update(id=456),
            lambda r,a,b: b["release"].update(draft=False),
            lambda r,a,b: b["release"]["assets"].pop(),
        ]
        for i, change in enumerate(mutations):
            with self.subTest(case=i):
                r,a,b = deepcopy(record),deepcopy(observed),deepcopy(observed)
                change(r,a,b)
                result=m.inspect(original(),v2=r,remote=[a,b])
                self.assertEqual(result["recoveryV2Classification"],
                                 "UNKNOWN_QUARANTINE")
                self.assert_no_permission(result)

    def test_duplicate_json_keys_and_missing_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "tampered.json"
            for content in ('{"a":1,"a":2}', '{"bad":true}', "garbage"):
                path.write_text(content, encoding="utf-8")
                with self.subTest(content=content), self.assertRaises(m.Deny):
                    m.inspect(m.read_record(path))
            with self.assertRaises(m.Deny):
                m.read_record(Path(d)/"missing")
            path.write_text("x" * 128000, encoding="utf-8")
            with self.assertRaises(m.Deny):
                m.read_record(path)

    def test_cli_reports_record_only_validation_and_never_publishing_permission(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = m.main(["--snapshot", str(EVIDENCE)])
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assert_no_permission(result)
        self.assertEqual(result["decision"], "PASS_READONLY_CRITICAL_PIN_CLOSURE_ONLY")

if __name__ == "__main__":
    main()
