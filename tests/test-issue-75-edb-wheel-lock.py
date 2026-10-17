#!/usr/bin/env python3
"""Adversarial, offline source/lock checks. Zero installer or wheel execution."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
from unittest import TestCase,main,mock
from zipfile import ZipFile
ROOT=Path(__file__).resolve().parents[1]
def mod(name,path):
    sp=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
w=mod("issue75_wheel","scripts/issue-75-wheel-lock-candidate.py")
e=mod("issue75_edb","scripts/issue-75-choco-edb-nonexec.py")
def lock():return w.load(w.LOCK)
def source():return w.SOURCE.read_bytes()
def synthetic_nupkg(text,expected="postgresql14",version="14.24.0"):
    f=io.BytesIO()
    with ZipFile(f,"w") as z:
        z.writestr(expected+".nuspec",
                   f'<package><metadata><id>{expected}</id><version>{version}</version>'
                   '<dependencies><dependency id="vcredist140" version="14.0" /></dependencies>'
                   '</metadata></package>')
        z.writestr("tools/chocolateyInstall.ps1",text)
    return f.getvalue()
def clean_script(url="https://get.enterprisedb.com/postgresql/postgresql-14.24-1-windows-x64.exe",
                 digest="a"*64):
    return (f"$packageArgs = @{{\n fileType = 'exe'\n "
            f"url64 = '{url}'\n checksum64 = '{digest}'\n"
            " checksumType64 = 'sha256'\n}\n"
            "Install-ChocolateyPackage @packageArgs\n").encode()
class AdversarialTests(TestCase):
    def test_wheel_candidate_matches_both_original_wheel_sets(self):
        x=w.validated(lock(),source())
        self.assertEqual(len(x["ubuntu"]),8)
        self.assertEqual(len(x["windows"]),8)
        for os in x:
            req=w.requirements(lock(),os)
            self.assertEqual(req.count("--hash=sha256:"),8)
            self.assertIn("jsonschema==4.26.0",req)
            self.assertIn("meson==1.8.3",req)
            self.assertIn("ninja==1.11.1.4",req)
            self.assertNotIn("git+",req)
    def test_wheel_digest_and_os_scope_forgery_denied(self):
        cases=[
           lambda d:d["packages"]["ninja"]["platforms"]["windows"].update(sha256="f"*64),
           lambda d:d["packages"]["ninja"]["platforms"]["ubuntu"].update(filename="x.whl"),
           lambda d:d["packages"]["attrs"].update(version="99.0"),
           lambda d:d["packages"].pop("rpds-py"),
           lambda d:d["boundary"].update(wheelHashesPinnedInSigner=True),
           lambda d:d["boundary"].update(goB="GO"),
           lambda d:d["boundary"].update(publicationAuthorized=True),
           lambda d:d["source"].update(runAttempt=2)]
        for c in cases:
            d=lock();c(d)
            with self.assertRaises(w.Deny):w.validated(d,source())
    def test_corrupt_immutable_original_receipt_denied(self):
        with self.assertRaises(w.Deny):w.validated(lock(),source()+b"\n")
    def test_local_wheelhouse_exact_set_and_byte_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)
            (p/"test-1.0-py3-none-any.whl").write_bytes(b"synthetic")
            expected={"test-1.0-py3-none-any.whl":hashlib.sha256(b"synthetic").hexdigest()}
            with self.assertRaises(w.Deny):w.check_wheelhouse(p,expected) # requires 8
    def test_literal_64bit_checksum_and_edb_url_validated(self):
        v=e.inspect_installer_script(clean_script(),"postgresql14","14.24.0")
        self.assertEqual(v["checksum64"],"a"*64)
        self.assertFalse(v["installerBytesSHA256Verified"])
        self.assertFalse(v["scriptWasExecuted"])
        for raw in (
           clean_script(url="http://get.enterprisedb.com/x.exe"),
           clean_script(url="https://attacker.invalid/postgresql-14.24-1-windows-x64.exe"),
           clean_script(url="https://get.enterprisedb.com/postgresql/postgresql-15.19-1-windows-x64.exe"),
           clean_script(digest="not-sha256"),
           clean_script()+b"\nurl64='https://evil.example.invalid'\n",
           clean_script().replace(b"Install-ChocolateyPackage",b"Invoke-Expression")):
            with self.subTest(case=raw[-40:]):
                with self.assertRaises(e.Deny):e.inspect_installer_script(raw,"postgresql14","14.24.0")
    def test_package_zip_identity_and_dependency_inventory(self):
        raw=synthetic_nupkg(clean_script())
        row=e.package_data(raw,"postgresql14","14.24.0",hashlib.sha256(raw).hexdigest())
        self.assertEqual(row["declaredChocolateyDependencies"],
                         [{"id":"vcredist140","version":"14.0"}])
        self.assertFalse(row["installerBytesSHA256Verified"])
        with self.assertRaises(e.Deny):
            e.package_data(raw,"postgresql14","14.24.0","0"*64)
    def test_duplicate_properties_and_dynamic_checksum_denied(self):
        script=clean_script()+b"checksum64 = 'b'\n"
        with self.assertRaises(e.Deny):
            e.inspect_installer_script(script,"postgresql14","14.24.0")
        with self.assertRaises(e.Deny):
            e.inspect_installer_script(clean_script().replace(b"'sha256'",b"$dynamic"),
                                      "postgresql14","14.24.0")
    def test_download_canary_only_with_expected_checksum_and_no_execution(self):
        with self.assertRaises(e.Deny):
            e.bounded_installer_get({"package":"postgresql14","checksumType64":"sha256",
                "checksum64":"0"*64,"url64":"https://attacker.invalid/a.exe"})
    def test_pr_only_workflow_no_writer_scope(self):
        text=(ROOT/".github/workflows/validate.yml").read_text()
        for job in ("issue75_choco_script_probe","issue75_wheel_lock_probe"):
            self.assertIn("  "+job+":",text)
            sec=text.split("  "+job+":",1)[1].split("\n  existing_signed_release_readonly:",1)[0]
            self.assertIn("github.event_name == 'pull_request'",sec)
            self.assertIn("issue-75-edb-installer-wheel-lock",sec)
        for token in ("secrets.PGEXTWIN", "gh release create","gh workflow run"):
            self.assertNotIn(token, "\n".join(
                line for line in text.splitlines() if "issue75_choco" in line or
                "issue75_wheel" in line))
if __name__=="__main__":main()
