#!/usr/bin/env python3
"""Offline migration acceptance: real declarations and future-copy Python CI.

No GitHub access, signing, token issuance, policy activation or Release writes.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import importlib.util
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from publication_policy_fixtures import manual_policy

ROOT=Path(__file__).resolve().parents[1]
FILES=("automation-fleet.json","release-promotion.json",
       "unattended-publication.json","publisher-write-boundary.json")
spec=importlib.util.spec_from_file_location("migration_issuer",ROOT/"scripts/automatic-publisher-receipt-issuer.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

def automatic(objects):
    f,c,u,b=deepcopy(objects)
    f["releasePolicy"]=gate.MODE
    for row in f["entries"]:row["releasePolicy"]=gate.MODE
    c["releasePolicy"]=gate.MODE
    u["mode"]="UNATTENDED"
    u["controls"]={name:True for name in u["controls"]}
    b.update(mode="ENFORCE",publisherAppId=gate.APP,
             publisherInstallationId=gate.INSTALLATION)
    return [f,c,u,b]

class TransitionTests(unittest.TestCase):
    def test_partial_policy_transitions_are_rejected(self):
        old=[manual_policy(n) for n in FILES]
        new=automatic(old)
        for choices in itertools.product((0,1),repeat=4):
            objects=[deepcopy(new[i] if choice else old[i]) for i,choice in enumerate(choices)]
            if len(set(choices))==1:
                result=gate.deployment_policy(*objects)
                self.assertIs(result["staticPublisherReady"],bool(choices[0]))
                self.assertIs(result["publicationAuthorized"],False)
            else:
                with self.subTest(choices=choices),self.assertRaises(gate.Denied):
                    gate.deployment_policy(*objects)

    def test_registered_growth_and_unknown_controls_do_not_grant_authority(self):
        objects=automatic([manual_policy(n) for n in FILES])
        row=deepcopy(objects[0]["entries"][0]);row["repository"]="pgextwin/future_extension"
        objects[0]["entries"].append(row)
        objects[1]["allowedRepositories"].append(row["repository"])
        result=gate.deployment_policy(*objects)
        self.assertIn(row["repository"],result["registeredRepositories"])
        self.assertIs(result["publicationAuthorized"],False)
        self.assertIs(result["publishableReceipt"],False)
        objects[2]["controls"]["unrecognized"]=True
        with self.assertRaises(gate.Denied):gate.deployment_policy(*objects)

    def test_shared_workflow_flag_has_a_real_newline_in_both_modes(self):
        old=[manual_policy(n) for n in FILES]
        with TemporaryDirectory() as tmp:
            for objects,expected in ((old,b"manual_only=true\n"),
                                     (automatic(old),b"manual_only=false\n")):
                path=Path(tmp)/"fleet.json";out=Path(tmp)/"output"
                path.write_text(json.dumps(objects[0]));out.unlink(missing_ok=True)
                run=subprocess.run([sys.executable,str(ROOT/"scripts/fleet-policy.py"),
                    "--fleet",str(path),"--github-output",str(out)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                self.assertEqual(out.read_bytes(),expected)
            bad=deepcopy(old[0]);bad["entries"][0]["releasePolicy"]=gate.MODE
            path.write_text(json.dumps(bad));out.unlink()
            run=subprocess.run([sys.executable,str(ROOT/"scripts/fleet-policy.py"),
                "--fleet",str(path),"--github-output",str(out)],capture_output=True)
            self.assertNotEqual(run.returncode,0)
            self.assertFalse(out.exists())

    def test_scope_cli_is_nonpublishing_in_both_modes(self):
        old=[manual_policy(n) for n in FILES]
        with TemporaryDirectory() as tmp:
            for objects in (old,automatic(old)):
                f,b=Path(tmp)/"fleet.json",Path(tmp)/"boundary.json"
                f.write_text(json.dumps(objects[0]));b.write_text(json.dumps(objects[3]))
                run=subprocess.run([sys.executable,str(ROOT/"scripts/independent-publisher-write-scope.py"),
                    "--policy",str(b),"--fleet",str(f),"--repository","pgextwin/plpgsql_check"],
                    capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                result=json.loads(run.stdout)
                self.assertIs(result["publicationAuthorized"],False)
                self.assertIs(result["publisherWriteAuthorized"],False)

    def test_readonly_scanner_covers_dynamic_registry_in_both_modes(self):
        sys.path.insert(0,str(ROOT/"scripts"))
        try:
            spec=importlib.util.spec_from_file_location("projected_fleet_watch",ROOT/"scripts/fleet-upstream-watch.py")
            watch=importlib.util.module_from_spec(spec);spec.loader.exec_module(watch)
        finally:
            sys.path.pop(0)
        old=[manual_policy(n) for n in FILES]
        for objects in (old,automatic(old)):
            registry=deepcopy(objects[0])
            extra=deepcopy(registry["entries"][0]);extra["repository"]="pgextwin/future_extension"
            registry["entries"].append(extra)
            def observed(repo,entry,fetch):
                return {"repository":repo,"mainSha":"a"*40,"status":"up-to-date","updates":[]}
            with patch.object(watch,"bounded_snapshot",side_effect=observed):
                result=watch.scan(registry,fetch=lambda _:self.fail("no network expected"))
            self.assertEqual(result["fleetSize"],len(registry["entries"]))
            self.assertEqual({r["repository"] for r in result["extensions"]},
                             {r["repository"] for r in registry["entries"]})
            self.assertEqual(result["indeterminate"],0)
            self.assertEqual(result["publication"],"DENY")
            self.assertIs(result["candidatePrCreated"],False)

    def test_projected_activation_passes_existing_python_ci_without_changing_source(self):
        original={name:(ROOT/"metadata"/name).read_bytes() for name in FILES}
        objects=automatic([json.loads(original[name]) for name in FILES])
        with TemporaryDirectory(prefix="pgextwin-policy-projection-") as tmp:
            projected=Path(tmp)/"build"
            shutil.copytree(ROOT,projected,ignore=shutil.ignore_patterns(".git","__pycache__"))
            for name,value in zip(FILES,objects):
                (projected/"metadata"/name).write_text(json.dumps(value,indent=2)+"\n")
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
            # Check the same read-only deployment entrypoint used by required CI.
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
        self.assertEqual(original,{name:(ROOT/"metadata"/name).read_bytes() for name in FILES})
        print("PROJECTED_AUTOMATIC_PYTHON_CI="+str(len(suites))+"; no activation, signing or Release")

if __name__=="__main__":unittest.main()
