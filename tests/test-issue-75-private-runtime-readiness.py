#!/usr/bin/env python3
"""Issue 75 hostile scope/visibility and private runner gate assertions."""
from __future__ import annotations
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "readiness",ROOT/"scripts/issue-75-private-runtime-readiness.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def good():return p.read(p.RECORD.read_bytes())

class ReadinessTests(TestCase):
    def test_actual_connected_inventory_passes_only_negative_baseline(self):
        out=p.validate(good())
        self.assertEqual(out["decision"],
                         "CONNECTED_SCOPE_ASSESSED_PRIVATE_EXECUTOR_NOT_PROVEN")
        self.assertEqual(out["observedConnectedOrgRepos"],18)
        self.assertEqual(out["observedConnectedOrgPrivateRepos"],0)
        self.assertEqual(out["privateRuntimeReadiness"],"NOT_PROVEN")
        for k in ("privateEnvironmentProven","writerSignerIdentitySeparationProven",
                  "realSignerOIDCProven","realWriterInstallationProven",
                  "realCredentialNonPropagationProven",
                  "permittedLiveMint","publicationAuthorized"):
            self.assertFalse(out[k])
        self.assertEqual((out["goB"],out["g4"],out["g5"]),("NO_GO",)*3)

    def test_connected_public_inventory_is_not_global_private_nonexistence(self):
        d=good()
        self.assertEqual(d["connectedInstallations"]["completeness"],
                         "CONNECTED_INSTALLATION_VISIBILITY_ONLY")
        self.assertEqual(d["repositorySnapshots"]["build"]["visibility"],"public")
        self.assertNotIn("ALL_GITHUB",json.dumps(d))
        self.assertNotIn("PRIVATE_EXECUTOR_PROVEN",json.dumps(d))

    def test_oversize_duplicate_key_null_and_type_confusion_deny(self):
        for b in (b"",b"\0",b"{}"*p.MAX_BYTES,
                  b'{"schemaVersion":1,"schemaVersion":1}',
                  b'{"foo":"bar"}\0',b'\xff',b'[]',b"not-json"):
            with self.subTest(b=b[:25]):
                with self.assertRaises(p.Deny):p.read(b)

    def test_fixed_immutable_source_replay_and_blobs_deny(self):
        cases=[
            ("fixedIdentities","buildMain","0"*40),
            ("fixedIdentities","pilotMain","0"*40),
            ("fixedIdentities","publisherPin","0"*40),
            ("fixedIdentities","signerPin","0"*40),
            ("fixedIdentities","priorNegativeRun",39102037076),
            ("fixedIdentities","priorAcceptanceMerge","0"*40),
            ("repositorySnapshots","plpgsql_check",{"visibility":"private"}),
        ]
        for root,key,value in cases:
            with self.subTest(root=root,key=key):
                d=good();d[root][key]=value
                with self.assertRaises(p.Deny):p.validate(d)

    def test_forged_invisible_private_repo_denied_without_authenticated_get(self):
        for field,value in (
            ("pgextwinVisiblePrivate",1),
            ("pgextwinVisiblePublic",17),
            ("pgextwinRepositoriesVisible",19),
            ("count",1),
            ("otherConnectedPrivateRepositories",1),
            ("allRepositoriesSelected",False),
            ("completeness","GLOBAL_ORGANIZATION_COMPLETE"),
        ):
            with self.subTest(field=field):
                d=good();d["connectedInstallations"][field]=value
                with self.assertRaises(p.Deny):p.validate(d)

    def test_ui_settings_denied_not_promoted_to_env_credential_proof(self):
        cases={
            "environmentListing":"HTTP200_FOUND",
            "actionsPolicyListing":"HTTP200_FOUND",
            "orgActionsPolicy":"HTTP200_FOUND",
            "buildBranchProtectionDetails":"OK",
            "buildRulesetListing":"PRESENT",
            "orgMembershipListing":"OWNER_VERIFIED",
            "privateEnvironmentPoliciesAuthenticated":True,
            "privateRunnerIsolationAuthenticated":True,
            "secretsExistenceOrAccessAuthenticated":True,
            "separateSignerWriterCredentialStoresAuthenticated":True,
            "gitHubAppWriterInstallationAuthenticated":True,
        }
        for field,value in cases.items():
            with self.subTest(field=field):
                d=good();d["readOnlySettings"][field]=value
                with self.assertRaises(p.Deny):p.validate(d)

    def test_no_unsigned_admin_metadata_or_oidc_permission_as_proof(self):
        doc=good()
        doc["repositorySnapshots"]["build"]["reportedCallerAdmin"]=False
        with self.assertRaises(p.Deny):p.validate(doc)
        doc=good()
        doc["repositorySnapshots"]["plpgsql_check"]["productionSignerOIDCDeclared"]=False
        with self.assertRaises(p.Deny):p.validate(doc)
        doc=good()
        doc["repositorySnapshots"]["plpgsql_check"]["productionWriterUsesGithubToken"]=False
        with self.assertRaises(p.Deny):p.validate(doc)

    def test_fake_ready_and_all_go_fields_denied(self):
        for field in good()["riskAssessment"]:
            d=good()
            current=d["riskAssessment"][field]
            d["riskAssessment"][field]=(False if current is True else
                                       True if current is False else
                                       "GO" if "go" in field.lower() else "PROVEN")
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.validate(d)

    def test_no_extra_authorizations_or_secret_fields(self):
        for field in ("privateAppKey","actualToken","githubSecret","privateWorkRunner"):
            d=good()
            d[field]="SYNTHETIC_PRIVATE_SECRET"
            with self.assertRaises(p.Deny):p.validate(d)
            d=good()
            d["readOnlySettings"][field]="SYNTHETIC_PRIVATE_SECRET"
            with self.assertRaises(p.Deny):p.validate(d)

    def test_entrypoints_static_only_and_require_private_returns_deny(self):
        for mode,expect in (("static",0),("require-private",2)):
            cap=io.StringIO()
            with redirect_stdout(cap):
                rc=p.main(["--mode",mode])
            self.assertEqual(rc,expect)
            result=json.loads(cap.getvalue())
            self.assertFalse(result["publicationAuthorized"])
            self.assertEqual(result["privateRuntimeReadiness"],"NOT_PROVEN")
            self.assertFalse(result["permittedLiveMint"])

    def test_exception_cannot_leak_secret(self):
        cap=io.StringIO()
        with mock.patch.object(p.old,"verify_existing_roots",
             side_effect=RuntimeError("SECRET_SAUCE_NEVER_LOG")):
            with redirect_stdout(cap):
                rc=p.main(["--mode","static"])
        self.assertEqual(rc,2)
        self.assertNotIn("SECRET_SAUCE_NEVER_LOG",cap.getvalue())
        self.assertEqual(json.loads(cap.getvalue())["decision"],
                         "DENY_UNKNOWN_PRIVATE_RUNTIME_ISOLATION")

    def test_opaque_stateless_app_token_format_no_short_token_assumption(self):
        # October 2 2026 GitHub rollout: installation tokens may be about
        # 520 bytes. This adapter treats them opaquely, never parses JWT body.
        src=(ROOT/"scripts/issue-75-private-writer-app-probe.py").read_text()
        for forbidden in ("ghs_[A-Za-z0-9]{36}", "len(token)==40",
                          "token.split('.')", "jwt.decode(token)",
                          "startswith('ghs_')"):
            self.assertNotIn(forbidden,src)

    def test_public_ci_only_invokes_inert_unit_tests(self):
        workflow=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-private-runtime-readiness.py",workflow)
        self.assertIn("scripts/issue-75-private-runtime-readiness.py --mode static",
                      workflow)
        self.assertNotIn("private-runtime-readiness.py --mode require-private",workflow)
        src=(ROOT/"scripts/issue-75-private-runtime-readiness.py").read_text()
        for forbidden in ("urllib.request", "requests.get(", "subprocess",
                          "create-github-app-token", "gh release", "workflow_dispatch"):
            self.assertNotIn(forbidden,src)
if __name__=="__main__":
    main()
