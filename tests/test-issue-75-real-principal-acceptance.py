#!/usr/bin/env python3
"""Issue75 hostile offline acceptance: no positive runtime principals/credential."""
from __future__ import annotations
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_real_principal_deny", ROOT / "scripts/issue-75-real-principal-acceptance.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def good():
    return p.read_record(p.RECORD.read_bytes())

class PrincipalAcceptanceTests(TestCase):
    def test_actual_negative_run_is_admitted_but_no_positive_authorization(self):
        out = p.validate(good())
        self.assertEqual(out["decision"], "NEGATIVE_WITNESS_ACCEPTED_REAL_PRINCIPALS_NOT_PROVEN")
        self.assertEqual(out["negativeSourceRunId"], 39104746046)
        self.assertEqual((out["originalGitBlobsReused"], out["additionalGitBlobsReused"]), (32, 13))
        self.assertEqual(out["realPrincipalAcceptance"], "NOT_PROVEN")
        for field in ("actualSignerOIDCProven", "actualIndependentWriterProven",
                      "tokenNonPropagationRuntimeProven",
                      "actualPublisherPositivePrewriteProven", "publicationAuthorized",
                      "publishableReceipt"):
            self.assertIs(out[field], False)
        self.assertEqual((out["goB"],out["g4"],out["g5"]), ("NO_GO",)*3)

    def test_reuse_existing_ledgers_and_checkout_proposal_not_deployment(self):
        self.assertIs(p.verify_existing_roots(), True)
        self.assertEqual(p.hardening.EXPECTED_SIGNER,
                         "93a0a7641253735cf5adb845c768981c79f75b46")
        self.assertEqual(p.graph.EXTRA["signer:scripts/install-postgresql.ps1"],
                         "c40c7c59df30800d46d0cd4928b40ea0e715212f")

    def test_canonical_encoding_duplicate_keys_and_oversize_deny(self):
        inputs=(b"", b" " * (p.MAX_BYTES+1),
                b'{"schemaVersion":1,"schemaVersion":1}',
                b'{"kind":"a"}\x00', b"\xff\xfe", b"not-json", b"[]")
        for payload in inputs:
            with self.subTest(payload=payload[:16]):
                with self.assertRaises(p.Deny):
                    p.read_record(payload)

    def test_fixed_pins_no_credential_boundary_drift(self):
        changes=[
            ("baseline","pilotProtectedMain","f"*40),
            ("baseline","publisherGitBlob","f"*40),
            ("baseline","publisherPin","f"*40),
            ("baseline","signerPin","f"*40),
            ("baseline","reused32GitBlobLedger","0"*40),
            ("baseline","reused13GitBlobDelta","0"*40),
            ("baseline","buildMainBefore","f"*40),
            ("negativeRuntime","headSha","f"*40),
            ("negativeRuntime","runId",39102037076),
            ("negativeRuntime","attempt",2),
            ("negativeRuntime","event","workflow_dispatch"),
            ("negativeRuntime","parentConclusion","failure"),
        ]
        for root,k,v in changes:
            with self.subTest(root=root,key=k):
                doc=good()
                doc[root][k]=v
                with self.assertRaises(p.Deny):
                    p.validate(doc)

    def test_negative_job_must_be_exact_success_not_skipped_or_forged_positive(self):
        cases=[
            ("reader","jobId",117608071136),
            ("reader","sourceDecision","REAL_SIGNED_PUBLISHER_SUCCESS"),
            ("reader","identityDecision","UNRESTRICTED_ACCESS"),
            ("reader","effectiveTokenScopesProven",True),
            ("signer","jobId",117608071252),
            ("signer","conclusion","skipped"),
            ("signer","decision","OIDC_VERIFIED"),
            ("signer","oidcCertificateCryptographicallyVerified",True),
            ("signer","checkoutHardeningDeployed",True),
            ("writer","jobId",117608071136),
            ("writer","conclusion","failure"),
            ("writer","decision","WRITER_LIVE_SUCCESS"),
            ("writer","independentInstallationId",12345),
            ("writer","installationTokenMinted",True),
        ]
        for role,k,v in cases:
            with self.subTest(role=role,key=k):
                doc=good()
                doc["negativeRuntime"][role][k]=v
                with self.assertRaises(p.Deny):
                    p.validate(doc)

    def test_forged_certificate_oidc_workflow_run_and_verifier_denied(self):
        cases={
            "verifiedSigstoreCertificateSubject":"https://github.com/pgextwin/build/.github/workflows/build-extension-attested.yml",
            "verifiedOIDCIssuer":"https://token.actions.githubusercontent.com",
            "verifiedSignerWorkflow":"build-extension-attested.yml",
            "verifiedRunAttempt":1,
            "trustedVerifierProcess":"gh attestation verify simulated exit0",
        }
        for field,value in cases.items():
            with self.subTest(field=field):
                doc=good()
                doc["requiredFutureIndependentProofs"]["signer"][field]=value
                with self.assertRaises(p.Deny):p.validate(doc)

    def test_forged_writer_installation_scope_and_token_lifetime_denied(self):
        cases={
            "installationId":100, "installationOwner":"pgextwin",
            "installationRepository":"plpgsql_check",
            "grantContentsWriteVerified":True,
            "tokenLifetimeVerified":True,
            "separatePrincipalVerified":True,
            "trustedVerifierProcess":"self-asserted passed",
        }
        for field,value in cases.items():
            with self.subTest(field=field):
                doc=good()
                doc["requiredFutureIndependentProofs"]["writer"][field]=value
                with self.assertRaises(p.Deny):p.validate(doc)

    def test_credential_cross_job_and_checkout_self_attestation_denied(self):
        record=good()
        for field in record["requiredFutureIndependentProofs"]["custody"]:
            with self.subTest(field=field):
                doc=good()
                doc["requiredFutureIndependentProofs"]["custody"][field]=True
                with self.assertRaises(p.Deny):p.validate(doc)

    def test_any_claimed_positive_go_receipt_or_future_evidence_field_denied(self):
        acceptance=good()["acceptance"]
        for field,val in acceptance.items():
            with self.subTest(field=field):
                doc=good()
                doc["acceptance"][field] = "GO" if field in ("goB","g4","g5") else True
                with self.assertRaises(p.Deny):p.validate(doc)
        doc=good()
        doc["requiredFutureIndependentProofs"]["writer"]["token"]="SECRET"
        with self.assertRaises(p.Deny):p.validate(doc)
        doc=good()
        doc["acceptance"]["releaseTag"]="v2.10.15-windows.1"
        with self.assertRaises(p.Deny):p.validate(doc)
        doc=good()
        doc["negativeRuntime"]["reader"]["token"]="SYNTHETIC"
        with self.assertRaises(p.Deny):p.validate(doc)

    def test_noncanonical_top_level_or_conflicting_roles_deny(self):
        for change in (
            lambda d:d.update(schemaVersion=True),
            lambda d:d.update(sourceOnly=False),
            lambda d:d.update(evidenceKind="POSITIVE_AUTHORIZATION"),
            lambda d:d.pop("negativeRuntime"),
            lambda d:d.update(extra="PUBLISH"),
            lambda d:d["requiredFutureIndependentProofs"].pop("custody"),
            lambda d:d["negativeRuntime"]["reader"].update(jobId=117608071199),
        ):
            doc=good()
            change(doc)
            with self.assertRaises(p.Deny):p.validate(doc)

    def test_static_cli_success_is_not_release_go_and_require_real_fails(self):
        for mode,expected in (("static",0),("require-real",2)):
            cap=io.StringIO()
            with redirect_stdout(cap):rc=p.main(["--mode",mode])
            self.assertEqual(rc,expected)
            out=json.loads(cap.getvalue())
            self.assertFalse(out["publicationAuthorized"])
            self.assertEqual(out["realPrincipalAcceptance"],"NOT_PROVEN")
            self.assertEqual(out["goB"],"NO_GO")
            self.assertNotIn("Bearer ",cap.getvalue())
            self.assertNotIn("PRIVATE_SYNTHETIC_CREDENTIAL",cap.getvalue())

    def test_unreadable_evidence_does_not_print_sensitive_errors(self):
        cap=io.StringIO()
        with mock.patch.object(p,"verify_existing_roots",
                               side_effect=ValueError("PRIVATE_SYNTHETIC_CREDENTIAL")):
            with redirect_stdout(cap):
                rc=p.main(["--mode","require-real"])
        self.assertEqual(rc,2)
        self.assertNotIn("PRIVATE_SYNTHETIC_CREDENTIAL",cap.getvalue())
        self.assertEqual(json.loads(cap.getvalue())["decision"],
                         "DENY_REAL_PRINCIPAL_AUTHENTICATION")

    def test_validator_contains_no_privileged_network_or_publisher_calls(self):
        src=(ROOT/"scripts/issue-75-real-principal-acceptance.py").read_text()
        for forbidden in ("urllib.request", "urlopen(", "requests.", "subprocess.",
                          "create-github-app-token@", "gh release", "gh workflow run",
                          "git push", "secrets.", "token = os.environ"):
            self.assertNotIn(forbidden,src)
        workflow=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-real-principal-acceptance.py",workflow)
        self.assertIn("scripts/issue-75-real-principal-acceptance.py --mode static",workflow)

if __name__=="__main__":
    main()
