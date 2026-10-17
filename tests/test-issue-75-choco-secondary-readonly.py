#!/usr/bin/env python3
"""Hostile offline fixtures for Chocolatey transitive dependencies; no execution."""
from __future__ import annotations
import hashlib
import importlib.util
import io
from pathlib import Path
from unittest import TestCase,main,mock
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "issue75_secondary",ROOT/"scripts/issue-75-choco-secondary-readonly.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def archive(name="vcredist140",version="14.23.27820",script=None,deps=()):
    data=io.BytesIO()
    with ZipFile(data,"w") as f:
        children="".join('<dependency id="%s" version="%s"/>'%e for e in deps)
        f.writestr(name+".nuspec",
           '<package><metadata><id>'+name+'</id><version>'+version+
           '</version><dependencies>'+children+'</dependencies></metadata></package>')
        if script is not None:
            f.writestr("tools/data.ps1",script)
    return data.getvalue()

def literal(url=None,digest="a"*64):
    url=url or ("https://download.visualstudio.microsoft.com/download/pr/"
                "something/VC_redist.x64.exe")
    return ("\nUrl64 = '"+url+"'\nChecksum64 = '"+digest+
            "'\nChecksumType64 = 'sha256'\n").encode()

class HostileFixtureTests(TestCase):
    def test_parent_exact_five_verified_exes_and_declared_package_roots(self):
        j=p.immutable_parent()
        self.assertEqual(j["verifiedInstallerCount"],5)
        self.assertFalse(j["acceptance"]["chocolateyDependencyBytesClosed"])
        self.assertFalse(j["acceptance"]["releaseAuthorized"])
    def test_full_byte_double_download_and_declared_dependency(self):
        raw=archive(script=literal(),deps=[("another.extension","1.0")])
        def getter(*args):return raw
        d=p.double_read_package("vcredist140","14.23.27820",getter)
        self.assertEqual(d["independentGETs"],2)
        self.assertEqual(d["archiveSHA256"],hashlib.sha256(raw).hexdigest())
        self.assertEqual(d["dependencies"],[{"id":"another.extension","version":"1.0"}])
        self.assertTrue(d["scriptInspectionIsNotExecution"])
        self.assertFalse(d["fullPackageRuntimeDependencyClosure"])
        self.assertEqual(d["scriptLiteralExternalDownloads"][0]["literalDownloadURLs"]["url64"]["sha256"],"a"*64)
    def test_mismatched_source_identity_rejected(self):
        raw=archive()
        with self.assertRaises(p.Deny):
            p.archive_inventory(raw,"chocolatey-core.extension","1.3.3")
    def test_different_double_get_bytes_denied(self):
        x=iter([archive(),archive(script=literal())])
        with self.assertRaises(p.Deny):
            p.double_read_package("vcredist140","14.23.27820",
                                  lambda *args:next(x))
    def test_malformed_checksum_or_malicious_url_denied(self):
        for t in (literal(digest="0"*40),
                  literal(url="https://evil.example/VC_redist.x64.exe"),
                  literal(url="http://download.visualstudio.microsoft.com/VC_redist.x64.exe"),
                  literal()+literal(),
                  literal().replace(b"'sha256'",b"'sha1'")):
            with self.subTest(source=t[:25]):
                with self.assertRaises(p.Deny):p.parse_literals(t.decode())
    def test_unpinned_dependent_package_never_allowed(self):
        with self.assertRaises(p.Deny):
            p.double_read_package("vcredist140","latest",lambda *args:b"")
    def test_crafted_zip_path_traversal_denied(self):
        x=io.BytesIO()
        with ZipFile(x,"w") as z:
            z.writestr("vcredist140.nuspec",
                       "<package><metadata><id>vcredist140</id><version>14.23.27820</version></metadata></package>")
            z.writestr("../attack.ps1","write-host never")
        with self.assertRaises(p.Deny):
            p.archive_inventory(x.getvalue(),"vcredist140","14.23.27820")
    def test_reject_remote_untrusted_redirect_hosts(self):
        for u in ("https://evil.invalid/archive.nupkg","http://community.chocolatey.org/a",
                  "https://u:p@community.chocolatey.org/a",
                  "https://community.chocolatey.org:999/x"):
            with self.assertRaises(p.Deny):p.host_allowed(u,"nupkg")
    def test_original_two_packages_immutable_run_and_kb_refs(self):
        ledger=p.original_observation()
        self.assertEqual(ledger["source"]["runId"],39039052934)
        self.assertEqual(ledger["packages"][0]["archiveSHA256"],
                         "ed7a281f45a61150df0e1414651bca8501004c56deb43439c075f1ba58aff70a")
        self.assertEqual(ledger["packages"][1]["archiveSHA256"],
                         "aec3e2fa9a92dd7c158f8ecf51a541f13bcbe95933ace4ace5ec1d1681e9c9dd")
        self.assertEqual(len(ledger["packages"][1]["dependencies"]),4)
        self.assertFalse(ledger["boundary"]["allRuntimeDependencyBytesVerified"])
    def test_microsoft_x86_x64_byte_mismatch_fails(self):
        pck=p.original_observation()["packages"][1]
        with mock.patch.object(p,"get",return_value=b"F"*1_200_000):
            with self.assertRaises(p.Deny):
                p.actual_vcredist_bytes(pck)
    def test_no_forged_double_get_receipt_or_mutable_runtime(self):
        base=p.original_observation()
        self.assertEqual(len(base["packages"]),2)
        self.assertFalse(base["boundary"]["scriptExecuted"])
        with self.assertRaises(p.Deny):
            p.double_read_package("kb2999226","latest",lambda *args:b"")
    def test_static_job_includes_microsoft_and_kb_without_execution(self):
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        start=wf.index("  issue75_secondary_chocolatey_readonly:")
        end=wf.index("\n  existing_signed_release_readonly:",start)
        sec=wf[start:end]
        self.assertIn(" --mode closure",sec)
        self.assertNotIn("pip install",sec)
        self.assertNotIn("choco install",sec)

    def test_workflow_job_isolated_and_no_write(self):
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        start=wf.index("  issue75_secondary_chocolatey_readonly:")
        end=wf.index("\n  existing_signed_release_readonly:",start)
        job=wf[start:end]
        for required in ("github.event_name == 'pull_request'",
                         "github.head_ref == 'issue-75-choco-secondary-closure'",
                         "persist-credentials: false","contents: read",
                         "issue-75-choco-secondary-readonly.py --mode closure"):
            self.assertIn(required,job)
        for prohibited in ("contents: write","id-token: write","secrets.",
                           "GH_TOKEN:","GITHUB_TOKEN:","upload-artifact",
                           "download-artifact","gh release","create-github-app-token"):
            self.assertNotIn(prohibited,job)
if __name__=="__main__":main()
