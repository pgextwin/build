#!/usr/bin/env python3
"""Hostile offline tests; no real Signer, Publisher, GitHub POST or credential."""
import copy
import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from unittest import mock
from pathlib import Path
import tempfile
from unittest import TestCase, main

ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

h=load("scripts/issue-75-signer-checkout-hardening.py","issue75_signer_proposal")
s=load("scripts/issue-75-signer-sandbox-probe.py","issue75_sandbox")
def record():return h.record(h.EVIDENCE.read_bytes())
def signer():return h.SIGNER.read_bytes()
def check(e):return h.inspect(e,signer())
class HardeningTests(TestCase):
    def test_inert_five_checkout_patch_and_six_action_roots(self):
        x=check(record())
        self.assertEqual(x["decision"],"PROPOSED_SIGNER_PATCH_OFFLINE_ONLY")
        self.assertEqual(x["checkoutHardeningProposed"],5)
        self.assertEqual(x["checkoutHardeningDeployed"],0)
        self.assertEqual(x["actionRootsObserved"],6)
        self.assertNotEqual(x["proposedSignerBlob"],x["activeSignerBlob"])
        for k in ("actionRuntimeDependencyClosure","chocolateyDigestsVerified",
                  "pythonWheelHashesVerified","runnerImageDigestVerified",
                  "writerTokenIsolationProven","publicationAuthorized"):
            self.assertIs(x[k],False)
        self.assertEqual((x["goB"],x["g4"],x["g5"]),
                         ("NO_GO","NO_GO","NO_GO"))
        proposed=h.hardened_signer(signer())
        self.assertEqual(proposed.count(b"persist-credentials: false"),5)
        self.assertEqual(h.blob(signer()),h.EXPECTED_SIGNER)
    def test_signed_workflow_root_and_checkout_tamper_denied(self):
        raw=signer()
        cases=[
          raw.replace(b"actions/checkout@3d3c42e5",b"actions/checkout@0d3c42e5",1),
          raw.replace(b"        uses: actions/checkout@",b"        uses: actions/checkout@bad",1),
          raw.replace(b"        uses: actions/checkout@",b"        uses: evil/checkout@",1),
          raw.replace(b"        uses: actions/checkout@",b"        persist-credentials: false\n        uses: actions/checkout@",1),
        ]
        for data in cases:
            with self.subTest(case=len(data)):
                with self.assertRaises(h.Deny):h.hardened_signer(data)
    def test_external_action_git_roots_corruption_and_forged_positive(self):
        for key,field,value in [
            ("actions/checkout","commit","v7"),
            ("actions/checkout","manifestBlob","a"*40),
            ("actions/attest","lockBlob","a"*40),
            ("actions/setup-python","distTree","a"*40),
            ("actions/create-github-app-token","fullTransitiveClosureProven",True),
            ("actions/upload-artifact","observation","verified_bytes"),
        ]:
            e=record()
            e["actions"][key][field]=value
            with self.subTest(key=key,field=field):
                with self.assertRaises(h.Deny):check(e)
        for change in (
            lambda e: e["actions"].pop("actions/checkout"),
            lambda e: e["actions"].update({"attacker/action":{}}),
            lambda e: e["signer"].update(checkoutOccurrences=4),
            lambda e: e["signer"].update(persistCredentialsDisabledOccurrences=5),
            lambda e: e["decision"].update(actualSignerDeployedHardening=True),
            lambda e: e["decision"].update(goB="GO"),
            lambda e: e["decision"].update(publicationAuthorized=True),
            lambda e: e["unresolved"].pop("python"),
        ):
            e=record();change(e)
            with self.assertRaises(h.Deny):check(e)
    def test_duplicate_json_keys_and_oversize_denied(self):
        with self.assertRaises(h.Deny):
            h.record(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaises(h.Deny):
            h.record(b" "*40000)
    def test_synthetic_git_config_credential_leaks_rejected_without_printing(self):
        for val in (b'[http "https://github.com/"]\nextraheader = AUTHORIZATION: basic deadbeef',
                    b'url = https://x-access-token:synthetic@github.com/o/r',
                    b'[credential]\nhelper = store',
                    b'GH_TOKEN=synthetic', b'github_pat_SYNTHETIC',
                    b'ACTIONS_RUNTIME_TOKEN=synthetic'):
            with self.subTest(payload=val[:10]):
                with self.assertRaises(s.Deny):s.inspect_bytes(val)
        self.assertTrue(s.inspect_bytes(b'[remote "origin"]\nurl = https://github.com/o/r\n'))
    def test_sandbox_workspace_checks_config_and_no_revealing_bytes(self):
        with tempfile.TemporaryDirectory() as path:
            repo=Path(path)
            git=repo/".git"
            git.mkdir()
            (git/"config").write_text('[remote "origin"]\nurl = https://github.com/o/r\n')
            self.assertEqual(s.inspect_workspace(repo),1)
            (git/"config").write_text('[http]\nextraheader = auth synthetic')
            with self.assertRaises(s.Deny):s.inspect_workspace(repo)
            (git/"config").unlink()
            with self.assertRaises(s.Deny):s.inspect_workspace(repo)
    def test_pr_only_windows_and_ubuntu_probe_cannot_claim_signer_fix(self):
        content=(ROOT/".github/workflows/validate.yml").read_text()
        start=content.index("  issue75_sandbox_probe:")
        end=content.index("\n  existing_signed_release_readonly:",start)
        job=content[start:end]
        for needed in ("github.event_name == 'pull_request'",
                       "github.head_ref == 'issue-75-signer-credential-external-proof'",
                       "windows-latest", "ubuntu-latest", "contents: read",
                       "persist-credentials: false",
                       "scripts/issue-75-signer-sandbox-probe.py"):
            self.assertIn(needed,job)
        for forbidden in ("contents: write","id-token: write","attestations: write",
                          "secrets.","create-github-app-token","upload-artifact",
                          "download-artifact","GH_TOKEN:", "GITHUB_TOKEN:",
                          "gh release","gh workflow run","workflow_dispatch"):
            self.assertNotIn(forbidden,job)
    def test_missing_sandbox_identity_is_ci_failure_without_token_echo(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            buf=io.StringIO()
            with redirect_stdout(buf):
                result=s.main()
        self.assertEqual(result,2)
        output=json.loads(buf.getvalue())
        self.assertEqual(output["decision"],"SANDBOX_NOT_PROVEN")
        self.assertEqual(output["goB"],"NO_GO")
        self.assertFalse(output["publicationAuthorized"])
        self.assertNotIn("Bearer",buf.getvalue())

    def test_pinned_external_gaps_remain_explicit(self):
        v=record()
        for gap in ("runnerImages","chocolatey","python","syftGrype",
                    "actionBundles","signerCheckout","token"):
            self.assertTrue(v["unresolved"][gap])
        self.assertFalse(v["decision"]["actualSignerDeployedHardening"])
        self.assertFalse(v["decision"]["signedPublisherPositivePrewriteProven"])

if __name__=="__main__":main()
