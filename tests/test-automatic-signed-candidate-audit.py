#!/usr/bin/env python3
"""Hostile signed-build-only audit tests; mock proofs are NEVER crypto trust."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
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

def create_assets(path,ext,majors=MAJORS):
    base.make_assets(path,ext,run=RUN,workflow_event="push")
    for m in majors:
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

def signed_result(path,kind,repo,sha,*,tamper=None,signer_sha=audit.pin.SIGNER_SHA):
    d=sha256(path.read_bytes()).hexdigest()
    sbom=json.loads(path.with_suffix(".spdx.json").read_text()) if False else None
    # The sidecar has the full stem before .zip.
    stem=path.name[:-4]
    sbom=json.loads((path.parent/(stem+".spdx.json")).read_text())
    uri=f"https://github.com/{repo}/actions/runs/{RUN}/attempts/1"
    signer=f"https://github.com/pgextwin/build/{audit.pin.offline.SIGNER_PATH}@{signer_sha}"
    cert={"issuer":audit.pin.offline.ISSUER,
          "runInvocationURI":uri,"buildSignerURI":signer,
          "subjectAlternativeName":signer,"buildSignerDigest":signer_sha,
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

def fixed_candidate(folder, name, version, ref):
    _, lifecycle, intent, run = example()
    repo = f"pgextwin/{name}"
    majors = [15, 16, 17, 18, 19]
    ext = {"schemaVersion": 1, "name": name,
           "upstream": {"repository": audit.ident.UPSTREAMS[name],
                        "version": version, "ref": ref, "commit": base.UPSTREAM},
           "postgresql": {"majors": majors}}
    lifecycle["postgresql"].append({"major": 19, "eol": "2031-12-31"})
    policy = audit.routes.repository_policy(audit.routes.read_policy(), repo)
    signer, verifier = policy["candidateSigner"], policy["candidateAudit"]
    intent.update(repository=repo, maintainedMajors=majors, releaseTagStem=f"v{version}")
    run.update(repository={"full_name": repo}, referenced_workflows=[
        {"path": audit.routes.workflow_ref(path, pin), "sha": pin}
        for path, pin in ((audit.routes.SIGNER, signer), (audit.routes.CANDIDATE_AUDIT, verifier))
    ])
    create_assets(folder, ext, majors)
    for path in folder.glob("*.zip"):
        with ZipFile(path) as archive:
            pkg = json.loads(archive.read("PACKAGE-INFO.json"))
        pkg["package"]["name"] = ext["name"]
        pkg["source"]["packagingRepository"] = repo
        pkg["workflowRun"]["url"] = f"https://github.com/{repo}/actions/runs/{RUN}"
        pkg["buildInfrastructure"]["commit"] = signer
        with ZipFile(path, "w") as archive:
            archive.writestr("PACKAGE-INFO.json", json.dumps(pkg))
    return repo, ext, lifecycle, intent, run, signer, verifier


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

    def test_fixed_pilot_signer_and_audit_require_original_run_bytes(self):
        self.check_fixed_signer_and_audit("pg_profile", "4.16", "4.16")

    def test_fixed_pg_ivm_signer_and_audit_require_original_run_bytes(self):
        self.check_fixed_signer_and_audit("pg_ivm", "1.17", "v1.17")

    def check_fixed_signer_and_audit(self, name, version, ref):
        with TemporaryDirectory() as td:
            folder = Path(td)
            repo, ext, lifecycle, intent, run, signer, verifier = fixed_candidate(folder, name, version, ref)

            def exact(path, kind, repository, sha):
                return signed_result(path, kind, repository, sha, signer_sha=signer)

            def run_pilot(source=run, verify=exact, audit_pin=verifier):
                return audit.audit(folder, ext, lifecycle, intent, source, deepcopy(source),
                                   repo=repo, sha=SHA, run_id=RUN, attempt=1, verify=verify,
                                   signer_sha=signer, verifier_sha=audit_pin)

            self.assertEqual(run_pilot()["maintainedMajors"], [15, 16, 17, 18, 19])
            with self.assertRaisesRegex(audit.Denied, "cryptographic proof binding"):
                run_pilot(verify=signed_result)
            with self.assertRaisesRegex(audit.routes.Denied, "approved workflow"):
                run_pilot(audit_pin="0" * 40)
            for override in ({"event": "issue_comment"}, {"run_attempt": 2}):
                with self.assertRaises(audit.Denied):
                    run_pilot(source={**run, **override})

            def changed_zip(path, *args):
                proof = exact(path, *args)
                with ZipFile(path, "a") as archive:
                    archive.writestr("changed.txt", "replacement after download")
                return proof

            with self.assertRaisesRegex(audit.Denied, "changed while verifying"):
                run_pilot(verify=changed_zip)

    def test_new_candidate_signer_denied_outside_pilot(self):
        extension, lifecycle, intent, run = example()
        policy = audit.routes.read_policy()
        with self.assertRaisesRegex(audit.Denied, "outside the shared candidate signing route"):
            audit.audit(None, extension, lifecycle, intent, run, deepcopy(run),
                        repo=REPO, sha=SHA, run_id=RUN, attempt=1, verify=None,
                        signer_sha=policy["candidateSigner"], verifier_sha=policy["candidateAudit"])

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

    def test_opted_in_pg19_requires_the_exact_signed_subject_and_assets(self):
        ext, lifecycle, intent, run = example()
        majors = [*MAJORS, 19]
        ext["postgresql"]["majors"] = majors
        ext["upstream"]["perPostgresql"]["19"] = {
            "ref": "19.1", "version": "19.1", "commit": base.UPSTREAM}
        lifecycle["postgresql"].append({"major": 19, "eol": "2031-11-19"})
        intent.update(maintainedMajors=majors, releaseTagStem="v19.1")
        opt_in = frozenset({ext["name"]})
        with TemporaryDirectory() as td, \
                patch.object(audit.ident, "PG19_ADMISSION_OPT_IN", opt_in), \
                patch.object(base.p.ident, "PG19_ADMISSION_OPT_IN", opt_in):
            folder = Path(td)
            create_assets(folder, ext, majors)

            def verify_candidate(proof=signed_result):
                return audit.audit(folder, ext, lifecycle, intent, run, deepcopy(run),
                                   repo=REPO, sha=SHA, run_id=RUN, attempt=1, verify=proof)

            result = verify_candidate()
            stem = audit.ident.asset_stem(ext, 19)
            self.assertEqual(result["zipSha256ByMajor"]["19"],
                             sha256((folder / (stem + ".zip")).read_bytes()).hexdigest())
            self.assertIs(result["publicationAuthorized"], False)

            def wrong_pg19_subject(path, kind, repo, sha):
                def tamper(item):
                    item["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
                return signed_result(path, kind, repo, sha,
                                     tamper=tamper if path.name == stem + ".zip" else None)

            with self.assertRaises(audit.Denied):
                verify_candidate(wrong_pg19_subject)
            (folder / (stem + ".spdx.json")).unlink()
            with self.assertRaises(audit.Denied):
                verify_candidate()

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
