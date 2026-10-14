#!/usr/bin/env python3
"""Issue #75 isolated positive/hostile fixtures: never accepts a mock as live proof."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
from zipfile import ZipFile

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fixed_existing_signed_release_probe",
    HERE / "scripts/verify-public-signed-release-readonly.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


class PublicReleaseFixtures(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.packages = {}
        for major in lib.MAJORS:
            stem = lib.STEM.format(major)
            pkg = {
                "buildMode": "release-attested",
                "package": {"name": "plpgsql_check", "platform": "windows",
                            "architecture": "x64"},
                "postgresql": {"major": major},
                "upstream": {"repository": "okbob/plpgsql_check",
                             "ref": "v2.10.14", "version": "2.10.14",
                             "commit": lib.UPSTREAM_SHA},
                "source": {"packagingRepository": lib.REPO,
                           "packagingCommit": lib.TAG_SHA},
                "buildInfrastructure": {"repository": "pgextwin/build",
                                        "commit": "a" * 40,
                                        "workflow": ".github/workflows/build-extension-attested.yml"},
                "workflowRun": {"id": 38128142145, "attempt": 1,
                                "event": "workflow_dispatch", "ref": "refs/heads/main"},
            }
            self.packages[major] = pkg
            self.write_zip(major, pkg)
            (self.dir / (stem + ".spdx.json")).write_text(json.dumps({"spdxVersion":"SPDX-2.3"}))
            (self.dir / (stem + ".vulnerabilities.json")).write_text(json.dumps({"matches":[]}))
        self.refresh()

    def write_zip(self, major, pkg):
        z = self.dir / (lib.STEM.format(major) + ".zip")
        with ZipFile(z, "w") as a:
            a.writestr("PACKAGE-INFO.json", json.dumps(pkg))

    def refresh(self):
        self.hashes = {p.name:lib.sha256(p) for p in self.dir.iterdir() if p.is_file()
                       and p.name != "SHA256SUMS.txt"}
        (self.dir / "SHA256SUMS.txt").write_text("".join(
            digest + "  " + name + "\n" for name,digest in sorted(self.hashes.items())))
        self.hashes["SHA256SUMS.txt"] = lib.sha256(self.dir / "SHA256SUMS.txt")
        self.release = {"id":lib.RELEASE_ID,"tag_name":lib.TAG,"draft":False,
                        "prerelease":False,"target_commitish":lib.TAG_SHA,
                        "assets":[{"name":p.name, "id":i+1, "state":"uploaded",
                                   "size":p.stat().st_size,
                                   "digest":"sha256:"+self.hashes[p.name]}
                                  for i,p in enumerate(sorted(self.dir.iterdir()))]}
        self.run = {"id":38128142145, "head_sha":lib.TAG_SHA, "head_branch":"main",
                    "event":"workflow_dispatch", "path":".github/workflows/promote.yml",
                    "status":"completed", "conclusion":"failure"}

    def check(self, *, run=None, local=None, attest=None):
        return lib.check_packages(
            self.dir, self.hashes, lib.TAG_SHA,
            get_run=lambda p: self.run if run is None else run,
            local_validator=lambda *a: None if local is None else local(*a),
            attest=lambda *a: None if attest is None else attest(*a))

    def test_inert_positive_metadata_and_all_five_major_signed_verifier_calls(self):
        checks = []
        result = lib.inventory(self.dir, self.release)
        self.assertEqual(result, self.hashes)
        got = self.check(attest=lambda z,s,h: checks.append((z.name,s.name,h)))
        self.assertEqual(got["runConclusion"], "failure")
        self.assertEqual(set(got["zipSha256ByMajor"]), {"14","15","16","17","18"})
        self.assertEqual(len(checks),5)
        self.assertEqual({z for z,_,_ in checks}, {lib.STEM.format(i)+".zip" for i in lib.MAJORS})

    def test_tampered_zip_checksum_and_renamed_assets_deny(self):
        with (self.dir / (lib.STEM.format(14)+".zip")).open("ab") as out:
            out.write(b"tamper")
        with self.assertRaises(lib.Deny):
            lib.inventory(self.dir,self.release)
        self.refresh()
        self.release["assets"][0]["name"]="unexpected.exe"
        with self.assertRaises(lib.Deny):
            lib.inventory(self.dir,self.release)

    def test_wrong_source_major_builder_and_run_id_denied(self):
        for field,bad in (("buildMode","normal"),("postgresql",{"major":99}),
                          ("upstream",{"commit":"0"*40}),
                          ("source",{"packagingRepository":"different/repo"}),
                          ("buildInfrastructure",{"workflow":".github/workflows/build-extension.yml"}),
                          ("workflowRun",{"id":38356899464})):
            with self.subTest(field=field):
                pkg=deepcopy(self.packages[14])
                if isinstance(bad,dict):
                    pkg[field].update(bad)
                else:
                    pkg[field]=bad
                self.write_zip(14,pkg)
                self.refresh()
                with self.assertRaises(lib.Deny):
                    self.check()
                self.write_zip(14,self.packages[14])
                self.refresh()

    def test_wrong_promotion_run_or_unsigned_origin_denied(self):
        for update in ({"path":".github/workflows/windows.yml"},
                       {"head_sha":"0"*40},
                       {"event":"push"},
                       {"status":"in_progress"}):
            bad={**self.run,**update}
            with self.subTest(update=update),self.assertRaises(lib.Deny):
                self.check(run=bad)

    def test_provenance_and_spdx_subject_must_match_real_digest(self):
        name=lib.STEM.format(15)+".zip"
        digest=self.hashes[name]
        statement=lambda predicate, n=name, d=digest:[{
            "verificationResult":{"statement":{"predicateType":predicate,
                                                 "subject":[{"name":n,"digest":{"sha256":d}}],
                                                 "predicate":{"spdxVersion":"SPDX-2.3"}}}}]
        lib.subject_proof(statement(lib.PROVENANCE),lib.PROVENANCE,name,digest)
        lib.subject_proof(statement(lib.SPDX),lib.SPDX,name,digest)
        for data,predicate in (([],lib.SPDX),
                               (statement(lib.PROVENANCE),lib.SPDX),
                               (statement(lib.SPDX,d="0"*64),lib.SPDX),
                               (statement(lib.SPDX,n="swapped.zip"),lib.SPDX)):
            with self.subTest(predicate=predicate),self.assertRaises(lib.Deny):
                lib.subject_proof(data,predicate,name,digest)

    def test_only_allow_fixed_read_commands(self):
        for argv in (("workflow","run","promote.yml"),("release","create",lib.TAG),
                     ("api","-X","POST"),("api","repos/pgextwin/plpgsql_check/git/refs"),
                     ("api","repos/pgextwin/build/releases"),
                     ("api","repos/pgextwin/plpgsql_check/actions/workflows/promote.yml/dispatches"),
                     ("pr","create"),("auth","login")):
            with self.subTest(argv=argv), self.assertRaises(lib.Deny):
                lib.gh(*argv)
        with mock.patch.object(lib.subprocess,"run",side_effect=OSError("offline")):
            with self.assertRaises(lib.Unavailable):
                lib.gh("api","repos/pgextwin/plpgsql_check/releases/tags/"+lib.TAG)


if __name__ == "__main__":
    main()
