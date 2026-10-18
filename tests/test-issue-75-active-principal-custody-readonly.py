#!/usr/bin/env python3
"""Issue75 hostile fixtures; a synthetic source never proves live principals."""
import base64
import copy
import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("custody",ROOT/"scripts/issue-75-active-principal-custody-readonly.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SRC="""name: Promote verified upstream candidate to attested Release
on:
  workflow_dispatch:
jobs:
  authorize:
    permissions:
      contents: read
      actions: read
      pull-requests: read
    steps:
      - ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977
        persist-credentials: false
      - persist-credentials: false
      - env:
          GH_TOKEN: __E__ github.token }}
  release_build:
    needs: authorize
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    uses: pgextwin/build/.github/workflows/build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d
  publish:
    needs: [authorize, release_build]
    permissions:
      contents: write
      actions: read
      attestations: read
    steps:
      - ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977
        persist-credentials: false
      - persist-credentials: false
      - env:
          GH_TOKEN: __E__ github.token }}
  catalog_sync:
    needs: publish
    permissions:
      contents: read
    steps:
      - private-key: __E__ secrets.PGEXTWIN_CATALOG_APP_PRIVATE_KEY }}
      - repositories: catalog
        permission-actions: write
      - env:
          GH_TOKEN: __E__ steps.app-token.outputs.token }}
  catalog_not_configured:
    needs: publish
""".replace("__E__", "$"+"{{")
def fake():
    obj={"sha":m.PUBLISHER_SOURCE_BLOB,"encoding":"base64",
         "content":base64.b64encode(SRC.encode()).decode()}
    branch={"protected":True,"commit":{"sha":m.PILOT_SHA}}
    return obj,branch
class ContractTests(TestCase):
    def test_bounded_synthetic_topology_still_not_real_identity(self):
        v=m.classify_source(SRC)
        self.assertEqual(v["writerCredentialSource"],"github.token")
        self.assertTrue(v["signerOIDCPermissionDeclared"])
        self.assertTrue(v["productionCheckoutPersistenceGap"])
        self.assertFalse(v["distinctWriterInstallationPrincipalVerified"])
        self.assertFalse(v["signerOIDCIdentityVerified"])
        r=m.report("DENY",v)
        self.assertEqual(r["runtimePrincipalSeparation"],"NOT_PROVEN")
        self.assertFalse(r["releaseAuthorized"])
        self.assertEqual((r["goB"],r["g4"],r["g5"]),("NO_GO","NO_GO","NO_GO"))
    def test_adversarial_job_permission_secret_pin_and_checkout(self):
        template=[
            ("pull-requests: read","pull-requests: write"),
            ("contents: read\n      id-token: write","contents: write\n      id-token: write"),
            ("id-token: write","id-token: read"),
            ("attestations: write","attestations: read"),
            ("needs: [authorize, release_build]","needs: publish"),
            ("persist-credentials: false","persist-credentials: true"),
            ("ref: "+m.PUBLISHER_PIN,"ref: "+"f"*40),
            ("@"+m.SIGNER_PIN,"@"+"f"*40),
            ("repositories: catalog","repositories: plpgsql_check"),
            ("permission-actions: write","permission-contents: write"),
            ("needs: publish","needs: authorize"),
            ("GH_TOKEN: "+"$"+"{{ github.token }}","GH_TOKEN: "+"$"+"{{ secrets.PRODUCTION_TOKEN }}"),
        ]
        for before,after in template:
            with self.subTest(entry=before[:40]):
                self.assertIn(before,SRC)
                with self.assertRaises(m.Deny):
                    m.classify_source(SRC.replace(before,after,1))
        for changed in (
            SRC.replace("  catalog_sync:\n","  extra:\n    permissions:\n      contents: write\n  catalog_sync:\n"),
            SRC.replace("  release_build:\n","  release_build:\n    env:\n      GH_TOKEN: SECRET\n"),
            SRC.replace("  publish:\n","  publish:\n    permissions:\n      id-token: write\n"),
            SRC.replace("  workflow_dispatch:\n","  pull_request_target:\n"),
        ):
            with self.assertRaises(m.Deny):m.classify_source(changed)
    def test_double_get_with_mocked_pin_never_becomes_positive(self):
        obj,branch=fake();calls=[]
        def get(path):
            calls.append(path)
            return copy.deepcopy(branch if path=="branches/main" else obj)
        with mock.patch.object(m.transport,"workflow_pins",
              return_value={"publisherPin":m.PUBLISHER_PIN,
                            "signerPin":m.SIGNER_PIN,
                            "workflowBlob":m.PUBLISHER_SOURCE_BLOB}):
            v=m.inspect(get,signer_raw=m.hardening.SIGNER.read_bytes())
        self.assertEqual(calls,["branches/main",m.PROMOTE_PATH]*2)
        self.assertFalse(v["distinctWriterInstallationPrincipalVerified"])
        self.assertFalse(v["signerOIDCIdentityVerified"])
    def test_get_race_source_tamper_and_signer_bytes_deny(self):
        with mock.patch.object(m.transport,"workflow_pins",
              return_value={"publisherPin":m.PUBLISHER_PIN,
                            "signerPin":m.SIGNER_PIN,
                            "workflowBlob":m.PUBLISHER_SOURCE_BLOB}):
            for case in ("changedblob","changedhead","unprotected","race","truncated","signer"):
                obj,branch=fake();count=[0]
                if case=="changedblob":obj["sha"]="f"*40
                if case=="changedhead":branch["commit"]["sha"]="f"*40
                if case=="unprotected":branch["protected"]=False
                if case=="truncated":obj["content"]="%%%notbase64%%%"
                signed=bytearray(m.hardening.SIGNER.read_bytes())
                if case=="signer":signed[0]^=1
                def get(path):
                    count[0]+=1
                    if path=="branches/main":
                        v=copy.deepcopy(branch)
                        if case=="race" and count[0]==3:v["commit"]["sha"]="0"*40
                        return v
                    return copy.deepcopy(obj)
                with self.subTest(case=case):
                    with self.assertRaises((m.Deny,m.hardening.Deny,ValueError)):
                        m.inspect(get,signer_raw=bytes(signed))
    def test_denied_live_http_never_prints_secrets(self):
        env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_EVENT_NAME":"push",
             "GITHUB_REF":"refs/heads/main","GITHUB_JOB":"reader",
             "GITHUB_WORKFLOW_REF":"pgextwin/build/.github/workflows/issue-75-principal-boundaries.yml@refs/heads/main",
             "GITHUB_SHA":"2ccd6138406433f83cbc74c02b4a19b5317866e1",
             "GITHUB_RUN_ID":"39102037076","GITHUB_RUN_ATTEMPT":"1",
             "GH_TOKEN":"SYNTHETIC_PRIVATE_TEST_SECRET"}
        with mock.patch.dict(os.environ,env,clear=True), \
             mock.patch.object(m.transport,"get_json",side_effect=RuntimeError("SYNTHETIC_PRIVATE_TEST_SECRET")):
            capture=io.StringIO()
            with redirect_stdout(capture):code=m.main()
        self.assertEqual(code,2)
        self.assertNotIn("SYNTHETIC_PRIVATE_TEST_SECRET",capture.getvalue())
        self.assertEqual(json.loads(capture.getvalue())["decision"],
                         "DENY_UNPROVEN_ACTIVE_PINNED_PRINCIPALS")
    def test_no_grants_or_new_credentials_in_trusted_main(self):
        src=(ROOT/".github/workflows/issue-75-principal-boundaries.yml").read_text()
        reader=src.split("  reader:\n",1)[1].split("  signer_denied:\n",1)[0]
        self.assertIn("issue-75-active-principal-custody-readonly.py",reader)
        self.assertIn("persist-credentials: false",reader)
        for forbidden in ("secrets.","contents: write","id-token: write",
                          "attestations: write","create-github-app-token","upload-artifact"):
            self.assertNotIn(forbidden,reader)
        self.assertEqual(src.count("GH_TOKEN:"),1)
        self.assertNotIn("pull_request_target:",src)
        self.assertNotIn("workflow_dispatch:",src)
if __name__=="__main__":main()
