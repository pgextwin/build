#!/usr/bin/env python3
"""Hostile offline tests for PR-only unsigned public dependency byte probe."""
import copy
import hashlib
import io
import importlib.util
from pathlib import Path
import tempfile
from unittest import TestCase,main,mock
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "issue75_external",ROOT/"tests/fixtures/historical-scripts/issue-75-external-byte-probe.py")
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
def records():
    return p.load(p.PLAN),p.load(p.ROOT_RECORD),p.load(p.PG)
def check(a=None):
    x,r,pg=records()
    return p.inspect(x if a is None else a,r,pg)
class PublicByteHostileTests(TestCase):
    def test_unchanged_source_is_only_a_plan_not_acceptance(self):
        z=check()
        self.assertEqual(z["decision"],"BOUNDED_PUBLIC_BYTE_PLAN_ONLY")
        self.assertEqual((z["actionRoots"],z["actionBundles"],z["actionLockfiles"]),(6,7,6))
        for k in ("pipDependencyHashesPinned","chocolateyPackageHashesPinned",
                  "runnerImagePinned","publicationAuthorized"):
            self.assertFalse(z[k])
        self.assertEqual(z["goB"],"NO_GO")
    def test_action_file_wrong_blob_size_or_path_deny(self):
        for change in (
            lambda j:j["actions"]["actions/attest"]["files"][0].update(gitBlob="a"*40),
            lambda j:j["actions"]["actions/checkout"]["files"][0].update(size=1),
            lambda j:j["actions"]["actions/setup-python"]["files"][0].update(path="dist/evil.js"),
            lambda j:j["actions"]["actions/checkout"]["files"].pop(),
            lambda j:j["actions"].pop("actions/attest"),
            lambda j:j["actions"]["actions/attest"].update(commit="a"*40),
            lambda j:j["actions"]["actions/attest"]["files"].append({"kind":"lockfile","path":"lock","gitBlob":"f"*40}),
        ):
            j=records()[0];change(j)
            with self.assertRaises(p.Deny):check(j)
    def test_wrong_runtime_versions_python_package_and_package_digest_deny(self):
        for change in (
            lambda j:j["python"]["requirements"].append("arbitrary>=0"),
            lambda j:j["python"].update(wheelHashesPinnedInSigner=True),
            lambda j:j["python"]["platforms"][1].update(pipPlatform="linux_x86_64"),
            lambda j:j["chocolatey"]["packages"][2].update(version="latest"),
            lambda j:j["chocolatey"].update(installerBinaryHashesVerified=True),
            lambda j:j["baseline"].update(signerPin="0"*40),
            lambda j:j["classification"].update(signerRuntimeDependenciesLocked=True),
            lambda j:j["classification"].update(goB="GO"),
            lambda j:j["classification"].update(publicationAuthorized=True),
        ):
            j=records()[0];change(j)
            with self.assertRaises(p.Deny):check(j)
    def test_git_blob_byte_hash_exact_and_size_enforced(self):
        raw=b"example immutable javascript"
        gitid=p.gitblob(raw)
        self.assertEqual(p.verify_gitblob(raw,gitid,len(raw)),
                         hashlib.sha256(raw).hexdigest())
        for value,sha,size in ((b"tampered",gitid,None),(raw,gitid,5),
                               (raw,"v7",None)):
            with self.assertRaises(p.Deny):p.verify_gitblob(value,sha,size)
    def test_cross_host_http_or_auth_redirect_denied(self):
        for url in ("http://raw.githubusercontent.com/x","https://evil.invalid/f",
                    "https://u:p@raw.githubusercontent.com/x",
                    "https://raw.githubusercontent.com:444/x",
                    "https://raw.githubusercontent.com/x#fragment",
                    "file:///etc/passwd"):
            with self.subTest(url=url):
                with self.assertRaises(p.Deny):p.allow_url(url)
        self.assertEqual(p.allow_url("https://raw.githubusercontent.com/x"),
                         "https://raw.githubusercontent.com/x")
    def test_nupkg_identity_requires_matching_id_and_version(self):
        def fake_zip(name="postgresql14",version="14.24.0"):
            f=io.BytesIO()
            with ZipFile(f,"w") as z:
                z.writestr("postgresql14.nuspec",
                           f'<package><metadata><id>{name}</id><version>{version}</version></metadata></package>')
            return f.getvalue()
        self.assertFalse(p.inspect_nupkg(fake_zip(),"postgresql14","14.24.0"))
        with self.assertRaises(p.Deny):
            p.inspect_nupkg(fake_zip(version="0.0.0"),"postgresql14","14.24.0")
        with self.assertRaises(p.Deny):
            p.inspect_nupkg(b"not a zip","postgresql14","14.24.0")
    def test_two_downloads_different_choco_bytes_fail_closed(self):
        j=records()[0]
        j["chocolatey"]["packages"]=j["chocolatey"]["packages"][:1]
        def fake_get(url,max_size):
            return b"PK" + (b"1" if fake_get.counter%2==0 else b"2")
        fake_get.counter=0
        def changes(url,max_size):
            fake_get.counter+=1
            return b"PK" + str(fake_get.counter).encode()
        with mock.patch.object(p,"fetch_bytes",side_effect=changes):
            with self.assertRaises(p.Deny):p.download_chocolatey(j)
    def test_wheel_inventory_rejects_scripts_and_nonwheels(self):
        with tempfile.TemporaryDirectory() as path:
            (Path(path)/"fake_setup.py").write_text("print('must never execute')")
            with self.assertRaises(p.Deny):p.wheel_inventory(path)
    def test_pr_isolation_no_tokens_no_writer_no_artifacts(self):
        y=(ROOT/"tests/fixtures/historical-workflows/validate-issue75-pr-oneoffs.yml").read_text()
        part=y.split("  issue75_public_byte_probe:",1)[1].split("\n  existing_signed_release_readonly:",1)[0]
        for required in ("github.event_name == 'pull_request'",
                         "github.head_ref == 'issue-75-external-byte-closure-probe'",
                         "ubuntu-latest","windows-latest","contents: read",
                         "persist-credentials: false","--mode ${{ matrix.mode }}",
                         "issue-75-external-byte-probe.py"):
            self.assertIn(required,part)
        for forbidden in ("contents: write","id-token: write","secrets.",
                          "GH_TOKEN:","GITHUB_TOKEN:","upload-artifact",
                          "download-artifact","gh workflow run",
                          "gh release","create-github-app-token"):
            self.assertNotIn(forbidden,part)
    def test_exact_original_successful_pr_byte_observation_is_no_go(self):
        ledger=p.load(p.OBSERVED)
        result=p.inspect_observed(ledger,records()[0])
        self.assertEqual((result["ActionFilesSHA256"],result["LinuxWheelsSHA256"],
                          result["WindowsWheelsSHA256"],
                          result["ChocolateyArchivesSHA256"]),(13,8,8,5))
        self.assertFalse(result["realRuntimeClosureAuthenticated"])
        self.assertFalse(result["publicationAuthorized"])
        self.assertEqual(result["goB"],"NO_GO")
    def test_prior_observation_immutable_provenance_and_digest_tamper_deny(self):
        changes=[
          lambda j:j["source"].update(headSha="0"*40),
          lambda j:j["source"].update(runAttempt=2),
          lambda j:j["observations"]["ubuntu"]["actionFiles"][0].update(sha256="f"*64),
          lambda j:j["observations"]["ubuntu"]["actionFiles"].pop(),
          lambda j:j["observations"]["windows"]["chocolateyArchives"][0].update(
              postgresqlInstallerSHA256Verified=True),
          lambda j:j["observations"]["windows"]["chocolateyArchives"][0].update(
              nupkgIdentityVerified=False),
          lambda j:j["observations"]["ubuntu"]["wheelInventory"]["wheels"].pop(
              "jsonschema-4.26.0-py3-none-any.whl"),
          lambda j:j["observations"]["windows"]["runner"].update(
              changedSincePriorProbe=True),
          lambda j:j["boundaries"].update(signedPublisherPositivePrewriteProven=True),
          lambda j:j["boundaries"].update(goB="GO"),
        ]
        for c in changes:
            ledger=p.load(p.OBSERVED)
            c(ledger)
            with self.subTest(mutation=str(c)):
                with self.assertRaises(p.Deny):
                    p.inspect_observed(ledger,records()[0])
    def test_reproducibility_comparator_rejects_different_bytes(self):
        ledger=p.load(p.OBSERVED)
        for mode,key in (("action-python","actionFiles"),
                         ("chocolatey-python","chocolateyArchives")):
            role="ubuntu" if mode=="action-python" else "windows"
            original=ledger["observations"][role]
            current={key:copy.deepcopy(original[key]),
                     "wheelInventory":copy.deepcopy(original["wheelInventory"])}
            self.assertTrue(p.compare_against_record(mode,current,ledger))
            current[key][0]["GETs"]=1
            with self.assertRaises(p.Deny):
                p.compare_against_record(mode,current,ledger)
            current={key:copy.deepcopy(original[key]),
                     "wheelInventory":copy.deepcopy(original["wheelInventory"])}
            k=next(iter(current["wheelInventory"]["wheels"]))
            current["wheelInventory"]["wheels"][k]="0"*64
            with self.assertRaises(p.Deny):
                p.compare_against_record(mode,current,ledger)
    def test_bounded_download_simulation_and_no_go(self):
        plan=records()[0]
        # Scope to an inert one-file fake Git object; real manifests never changed.
        fake=copy.deepcopy(plan)
        fake["actions"]={"actions/checkout":{
            "commit":"3d3c42e5aac5ba805825da76410c181273ba90b1",
            "files":[{"kind":"action_bundle","path":"dist/index.js",
                      "gitBlob":p.gitblob(b"source"),"size":6}]}}
        with mock.patch.object(p,"fetch_bytes",return_value=b"source") as get:
            result=p.download_actions(fake)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["GETs"],2)
        self.assertTrue(result[0]["gitBlobVerified"])
        self.assertFalse(result[0]["executableAttestation"])
        self.assertEqual(get.call_count,2)
if __name__=="__main__":main()
