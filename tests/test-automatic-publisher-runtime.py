#!/usr/bin/env python3
"""Nonpublishing Publisher automatic readiness and signed-source download tests."""
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase,main
from unittest.mock import patch
import json
import os
import subprocess

from publication_policy_fixtures import manual_policy
ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m
gate=load("issuer_readiness","automatic-publisher-readiness.py")
artifacts=load("original_signed_download","download-original-signed-source.py")
runtime=load("dedicated_publisher_runtime","automatic-publisher-run.py")

def policies():
    names=["automation-fleet.json","release-promotion.json",
           "unattended-publication.json","publisher-write-boundary.json"]
    return [manual_policy(x) for x in names]

class PublisherRuntimeOffline(TestCase):
    def test_historical_manual_policy_denies_before_private_key(self):
        x=policies()
        self.assertFalse(gate.ready(*x))
        self.assertNotIn("PUBLISHER_PRIVATE_KEY",runtime.__dict__)
        for item,field,value in (
            (0,"releasePolicy","automatic-signed-schedule"),
            (1,"releasePolicy","automatic-signed-schedule"),
            (2,"mode","UNATTENDED"),
            (3,"mode","ENFORCE"),
        ):
            copied=[json.loads(json.dumps(v)) for v in x]
            copied[item][field]=value
            with self.assertRaises(gate.issuer.Denied):
                gate.ready(*copied)

    def test_unsigned_run_download_requires_strict_repo_and_runner_scratch(self):
        with TemporaryDirectory() as t,patch.dict(os.environ,{
            "RUNNER_TEMP":t,"GH_TOKEN":"offline-unit-test-read-only-token"}):
            target=Path(t)/"signed"
            for repository,run in (
                ("pgextwin/evil\n",123),("other/repo",123),
                ("pgextwin/pg_ivm",0),("pgextwin/pg_ivm",True),
            ):
                with self.subTest(repository=repository,run=run):
                    with self.assertRaises(artifacts.Denied):
                        artifacts.download(repository,run,target)
            with self.assertRaises(artifacts.Denied):
                artifacts.download("pgextwin/pg_ivm",123,Path(t).parent/"outside")

    def test_download_is_read_only_and_old_artifact_replay_denied(self):
        with TemporaryDirectory() as t,patch.dict(os.environ,{
            "RUNNER_TEMP":t,"GH_TOKEN":"offline-unit-test-read-only-token"}):
            target=Path(t)/"signed"
            commands=[]
            def fake(command,**kwargs):
                commands.append(command)
                folder=Path(command[command.index("--dir")+1])
                if command[6]=="--name":
                    if command[7]=="automatic-signed-candidate-audit-nonpublishing":
                        (folder/"automatic-signed-candidate-audit.json").write_text("{}")
                    else:
                        (folder/"independent-signed-candidate-audit.json").write_text("{}")
                else:
                    (folder/"pg_ivm-v1.1-pg18-windows-x64.zip").write_bytes(b"zip-bytes")
                    (folder/"pg_ivm-v1.1-pg18-windows-x64.spdx.json").write_text("{}")
                    (folder/"pg_ivm-v1.1-pg18-windows-x64.vulnerabilities.json").write_text("{}")
                return subprocess.CompletedProcess(command,0,stdout="")
            obj=artifacts.download("pgextwin/pg_ivm",123,target,call=fake)
            self.assertEqual(len(commands),3)
            self.assertTrue(all(c[:3]==["gh","run","download"] and
                                c[3]=="123" and "--repo" in c and
                                c[c.index("--repo")+1]=="pgextwin/pg_ivm"
                                for c in commands))
            self.assertEqual(len(list(obj["signed-dist"].iterdir())),3)
            with self.assertRaises(artifacts.Denied):
                artifacts.download("pgextwin/pg_ivm",123,target,call=fake)
            self.assertEqual(len(commands),3)

    def test_no_untrusted_authorization_artifact_is_imported_by_runtime(self):
        s=(ROOT/"scripts/automatic-publisher-run.py").read_text()
        self.assertIn("issuer.issue(",s)
        self.assertIn("source.verify_completed_source(",s)
        self.assertIn("scope.single_repository_token(",s)
        self.assertIn("formal.check_assets(",s)
        self.assertIn("formal.publish_preverified(",s)
        self.assertNotIn("--receipt",s)
        self.assertIn('os.environ["GH_TOKEN"]=original_read_token',s)

if __name__=="__main__":main()
