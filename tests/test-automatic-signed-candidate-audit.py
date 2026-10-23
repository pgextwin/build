#!/usr/bin/env python3
"""Hostile signed-build-only audit tests; mock proofs are NEVER crypto trust."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]

def load(label, rel):
    spec = importlib.util.spec_from_file_location(label, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

audit = load("signed_audit", "scripts/automatic-signed-candidate-audit.py")
base = load("signed_fixtures", "tests/test-fleet-publish-release.py")
REPO = base.REPO
SHA = base.COMMIT
RUN = 515
MAJORS = list(range(14,19))

def example():
    ext, lifecycle, receipt = base.fixture()
    intent = {"schemaVersion":1, "status":"ELIGIBLE_FOR_FURTHER_SIGNED_BUILD_AUDIT_NONPUBLISHING",
              "repository":REPO,"mainMergeSha":SHA,"candidatePr":12,
              "maintainedMajors":MAJORS,
              "releaseTagStem":audit.ident.tag_stem(ext),
              "signedArtifactsVerified":False,"publishableReceipt":False,
              "publicationAuthorized":False,"automaticReleaseEnabled":False}
    run = {"id":RUN, "run_attempt":1, "repository":{"full_name":REPO},
           "head_sha":SHA,"head_branch":"main","event":"push",
           "path":audit.CALLER,"status":"in_progress","conclusion":None}
    return ext,lifecycle,intent,run

def create_assets(path,ext):
    base.make_assets(path,ext,run=RUN,workflow_event="push")
    for m in MAJORS:
        zip_path=path/(audit.ident.asset_stem(ext,m)+".zip")
        with ZipFile(zip_path) as z:
            obj=json.loads(z.read("PACKAGE-INFO.json"))
        obj["package"]["platform"]="windows"
        obj["package"]["architecture"]="x64"
        with ZipFile(zip_path,"w") as z:
            z.writestr("PACKAGE-INFO.json",json.dumps(obj))
        stem=audit.ident.asset_stem(ext,m)
        scan={"matches":[], "ignoredMatches":[],
              "descriptor":{"name":"grype","version":"0.120.1",
                            "db":{"status":{"valid":True,"schemaVersion":"v6",
                                            "built":"2026-10-23T00:00:00Z",
                                            "from":"2026-10-23T00:00:00Z"},
                                  "providers":{"nvd":{}}},
                            "configuration":{"ignore":[],
                                             "match-upstream-kernel-headers":True}},
              "source":{"type":"file","target":stem}}
        (path/(stem+".vulnerabilities.json")).write_text(json.dumps(scan))

def signed_result(path,kind,repo,sha,*,tamper=None):
    d=sha256(path.read_bytes()).hexdigest()
    sbom=json.loads(path.with_suffix(".spdx.json").read_text()) if False else None
    # The sidecar has the full stem before .zip.
    stem=path.name[:-4]
    sbom=json.loads((path.parent/(stem+".spdx.json")).read_text())
    uri=f"https://github.com/{repo}/actions/runs/{RUN}/attempts/1"
    signer=f"https://github.com/pgextwin/build/{audit.pin.offline.SIGNER_PATH}@{audit.pin.SIGNER_SHA}"
    cert={"issuer":audit.pin.offline.ISSUER,
          "runInvocationURI":uri,"buildSignerURI":signer,
          "subjectAlternativeName":signer,"buildSignerDigest":audit.pin.SIGNER_SHA,
          "sourceRepositoryURI":f"https://github.com/{repo}",
          "sourceRepositoryDigest":sha,"sourceRepositoryRef":"refs/heads/main",
          "buildConfigURI":f"https://github.com/{repo}/{audit.CALLER}@refs/heads/main",
          "buildConfigDigest":sha,"githubWorkflowSHA":sha,
          "githubWorkflowRef":"refs/heads/main","buildTrigger":"push"}
    predicate=(sbom if kind==audit.pin.SPDX else
        {"buildDefinition":{"buildType":"mock-not-cryptographic"},
         "runDetails":{"builder":{"id":"mock"},
                       "metadata":{"invocationId":uri}}})
    item={"verificationResult":{
        "statement":{"predicateType":kind,
                     "subject":[{"name":path.name,"digest":{"sha256":d}}],
                     "predicate":predicate},
        "signature":{"certificate":cert},
        "verifiedTimestamps":[{"timestamp":"offline-fixture"}]}}
    if tamper:
        tamper(item)
    return [item]

class SignedCandidateReadOnly(unittest.TestCase):
    def run_audit(self, mutate=None, proof=None):
        ext,lc,intent,run=example()
        with TemporaryDirectory() as td:
            folder=Path(td)
            create_assets(folder,ext)
            if mutate:
                mutate(ext,lc,intent,run,folder)
            callback=proof or signed_result
            return audit.audit(folder,ext,lc,intent,run,deepcopy(run),
                               repo=REPO,sha=SHA,run_id=RUN,
                               attempt=1,verify=callback)

    def test_complete_real_shape_is_never_a_release_receipt(self):
        result=self.run_audit()
        self.assertEqual(result["status"],audit.SIGNED)
        for kind in ("zip", "spdx", "grype"):
            values = result[kind + "Sha256ByMajor"]
            self.assertEqual(set(values), set(map(str, MAJORS)))
            self.assertTrue(all(len(v) == 64 for v in values.values()))
        self.assertEqual(set(result["grypePolicyByMajor"]),set(map(str,MAJORS)))
        self.assertTrue(all(v["status"]=="NO_BLOCKING_FINDINGS"
                            for v in result["grypePolicyByMajor"].values()))
        self.assertIs(result["signedArtifactsVerified"],True)
        for field in ("publishableReceipt","publicationAuthorized","automaticReleaseEnabled"):
            self.assertIs(result[field],False)

    def test_real_report_blocking_findings_never_grant_release(self):
        def critical(e,l,i,r,f):
            path=f/(audit.ident.asset_stem(e,14)+".vulnerabilities.json")
            doc=json.loads(path.read_text())
            doc["matches"]=[{"vulnerability":{"id":"CVE-example","severity":"High"},
                             "artifact":{"name":"example.dll"},
                             "matchDetails":[{"matcher":"package"}]}]
            path.write_text(json.dumps(doc))
        result=self.run_audit(critical)
        self.assertEqual(result["grypePolicyByMajor"]["14"]["status"],"BLOCKING_FINDINGS")
        self.assertEqual(result["grypePolicyByMajor"]["14"]["blockingFindingCount"],1)
        self.assertIs(result["publicationAuthorized"],False)

    def test_original_intent_and_root_identity_hostile_denials(self):
        cases=[
            lambda e,l,i,r,f:i.update(status="PUBLISH"),
            lambda e,l,i,r,f:i.update(mainMergeSha="f"*40),
            lambda e,l,i,r,f:i.update(maintainedMajors=[14,15,16,17]),
            lambda e,l,i,r,f:i.update(publicationAuthorized=True),
            lambda e,l,i,r,f:i.update(signedArtifactsVerified=True),
            lambda e,l,i,r,f:r.update(event="workflow_dispatch"),
            lambda e,l,i,r,f:r.update(path=".github/workflows/promote.yml"),
            lambda e,l,i,r,f:r.update(run_attempt=2),
            lambda e,l,i,r,f:r.update(head_sha="f"*40),
            lambda e,l,i,r,f:r.update(status="completed",conclusion="success"),
            lambda e,l,i,r,f:(f/"extra.zip").write_bytes(b"untrusted"),
            lambda e,l,i,r,f:(f/(audit.ident.asset_stem(e,16)+".spdx.json")).unlink(),
            lambda e,l,i,r,f:(f/(audit.ident.asset_stem(e,15)+".vulnerabilities.json")).write_text("{}"),
        ]
        for index,change in enumerate(cases):
            with self.subTest(index=index),self.assertRaises(
                    (audit.Denied,audit.ident.Denied,KeyError,ValueError)):
                self.run_audit(change)

    def test_corrupt_zip_source_signer_event_denied(self):
        for section,key,val in (
            ("upstream","commit","e"*40),
            ("source","packagingCommit","e"*40),
            ("buildInfrastructure","commit","e"*40),
            ("workflowRun","event","workflow_dispatch"),
            ("workflowRun","attempt",2),
        ):
            def bad(e,l,i,r,f):
                z=f/(audit.ident.asset_stem(e,14)+".zip")
                with ZipFile(z) as arc:
                    pkg=json.loads(arc.read("PACKAGE-INFO.json"))
                pkg[section][key]=val
                with ZipFile(z,"w") as arc:
                    arc.writestr("PACKAGE-INFO.json",json.dumps(pkg))
            with self.subTest(section=section,key=key),self.assertRaises(audit.Denied):
                self.run_audit(bad)

    def test_forged_proof_subject_signer_source_caller_or_event_denied(self):
        for field,val in (
            ("buildTrigger","workflow_dispatch"),
            ("sourceRepositoryDigest","c"*40),
            ("runInvocationURI","forged"),
            ("buildConfigURI","https://github.com/evil/other.yml@main"),
            ("buildSignerDigest","d"*40),
        ):
            def bad(z,k,r,s):
                return signed_result(z,k,r,s,tamper=lambda proof:
                    proof["verificationResult"]["signature"]["certificate"].__setitem__(field,val))
            with self.subTest(field=field),self.assertRaises(audit.Denied):
                self.run_audit(proof=bad)
        def wrong_subject(z,k,r,s):
            return signed_result(z,k,r,s,tamper=lambda item:
                item["verificationResult"]["statement"]["subject"][0]["digest"].__setitem__("sha256","0"*64))
        with self.assertRaises(audit.Denied):
            self.run_audit(proof=wrong_subject)

    def test_fail_closed_on_broken_gh_verified_json_and_no_post(self):
        for case in ([],[{}],[{"verificationResult":"synthetic"}]):
            with self.subTest(case=case),self.assertRaises(
                    (audit.Denied,KeyError,TypeError)):
                self.run_audit(proof=lambda z,k,r,s: case)
        with self.assertRaises(audit.Denied):
            audit.run_readonly("gh","api","--method","POST","repos/pgextwin/pgaudit/releases")

if __name__=="__main__":
    unittest.main()
