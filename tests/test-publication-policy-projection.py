#!/usr/bin/env python3
"""Offline future-policy projection CI against a full temporary repository copy.

Separated from normal CI (validate.yml) and triggered on publication policy /
migration implementation changes or manually via workflow_dispatch before
cutover. No GitHub access, signing, token issuance, policy activation or
Release writes.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from publication_policy_fixtures import POLICY_FILES, automatic_policy

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("migration_issuer",ROOT/"scripts/automatic-publisher-receipt-issuer.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
spec=importlib.util.spec_from_file_location("projected_catalog_contract",ROOT/"scripts/catalog-downstream-policy.py")
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)


class ProjectionTests(unittest.TestCase):
    def test_projected_activation_passes_existing_python_ci_without_changing_source(self):
        """Run existing Python test suites and readiness check on a projected policy copy."""
        paths=POLICY_FILES+("manual-release-downstream.json",)
        original={name:(ROOT/"metadata"/name).read_bytes() for name in paths}
        objects=automatic_policy([json.loads(original[name]) for name in POLICY_FILES],
                                 gate.MODE,gate.APP,gate.INSTALLATION)
        with TemporaryDirectory(prefix="pgextwin-policy-projection-") as tmp:
            projected=Path(tmp)/"build"
            shutil.copytree(ROOT,projected,ignore=shutil.ignore_patterns(".git","__pycache__"))
            for name,value in zip(POLICY_FILES,objects):
                (projected/"metadata"/name).write_text(json.dumps(value,indent=2)+"\n")
            downstream=catalog.automatic_template(json.loads(original["manual-release-downstream.json"]),*objects[:2])
            (projected/"metadata/manual-release-downstream.json").write_text(json.dumps(downstream,indent=2)+"\n")
            suites=sorted(p.name for p in (projected/"tests").glob("test-*.py")
                          if p.name!=Path(__file__).name)
            self.assertTrue(suites)
            def check(name):
                run=subprocess.run([sys.executable,"tests/"+name],cwd=projected,
                    capture_output=True,text=True,timeout=90)
                return name,run.returncode,(run.stdout+run.stderr)[-1800:]
            with ThreadPoolExecutor(max_workers=4) as pool:
                results=list(pool.map(check,suites))
            failed={name:output for name,code,output in results if code}
            self.assertEqual(failed,{},json.dumps(failed,indent=2))
            # Check the same read-only deployment entrypoint used by required CI against the projected copy.
            run=subprocess.run([sys.executable,"scripts/automatic-publisher-readiness.py",
                "--fleet","metadata/automation-fleet.json",
                "--central-policy","metadata/release-promotion.json",
                "--unattended","metadata/unattended-publication.json",
                "--publisher-boundary","metadata/publisher-write-boundary.json"],
                cwd=projected,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            decision=json.loads(run.stdout.splitlines()[0])
            self.assertIs(decision["staticPublisherReady"],True)
            self.assertIs(decision["publicationAuthorized"],False)
            self.assertIs(decision["publishableReceipt"],False)
        self.assertEqual(original,{name:(ROOT/"metadata"/name).read_bytes() for name in paths})
        print("PROJECTED_AUTOMATIC_PYTHON_CI="+str(len(suites))+"; no activation, signing or Release")


if __name__=="__main__":unittest.main()
