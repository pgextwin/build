#!/usr/bin/env python3
"""Offline structural receipt-issuer tests; no network, key, real signature or WRITE."""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m
issuer=load("issuer_under_test","scripts/automatic-publisher-receipt-issuer.py")
old=load("issuer_test_package","tests/test-fleet-publish-release.py")
REPO="pgextwin/pgaudit"
SHA="a"*40
CENTRAL_SHA="c"*40
SOURCE_RUN=73451
SCHEDULE_RUN=93451

def inputs():
    ext,lifecycle,_=old.fixture()
    fleet=json.loads((ROOT/"metadata/automation-fleet.json").read_text())
    central=json.loads((ROOT/"metadata/release-promotion.json").read_text())
    unattended=json.loads((ROOT/"metadata/unattended-publication.json").read_text())
    boundary=json.loads((ROOT/"metadata/publisher-write-boundary.json").read_text())
    return dict(
        proof={"schemaVersion":1,"status":"REAL_COMPLETED_SIGNED_SOURCE_VERIFIED_NONPUBLISHING",
               "repository":REPO,"mainMergeSha":SHA,
               "sourceRunId":SOURCE_RUN,"sourceRunAttempt":1,
               "maintainedMajors":[14,15,16,17,18],
               "realSigstoreRechecked":True,"blockingGrypeFindings":0,
               "publisherTokenRequested":False,"publishableReceipt":False,
               "publicationAuthorized":False,"automaticReleaseEnabled":False,
               **{kind+"Sha256ByMajor":{str(m):"b"*64 for m in range(14,19)}
                  for kind in ("zip","spdx","grype")}},
        lifecycle=lifecycle,manifest=ext,fleet=fleet,central=central,
        local={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-dispatch"},
        unattended=unattended,boundary=boundary,
        schedule_run={"id":SCHEDULE_RUN,"run_attempt":1,
                      "repository":{"full_name":"pgextwin/build"},
                      "event":"schedule","path":issuer.SCHEDULE,
                      "head_sha":CENTRAL_SHA,"head_branch":"main",
                      "status":"in_progress","conclusion":None},
        central_branch={"name":"main","protected":True,"commit":{"sha":CENTRAL_SHA}},
        signed_branch={"name":"main","protected":True,"commit":{"sha":SHA}},
        app_identity={"id":5451798,"slug":"pgextwin-publisher"},
        installation_identity={
            "id":174720074,"app_id":5451798,
            "account":{"login":"pgextwin"},"repository_selection":"all",
            "permissions":{"contents":"write","metadata":"read"},
            "suspended_at":None},
        minted={"token":"synthetic-unit-test-token-no-privilege",
                "repository_selection":"selected",
                "permissions":{"contents":"write","metadata":"read"}},
        scoped={"total_count":1,"repositories":[{"full_name":REPO}]},
        repository=REPO,sha=SHA,source_run=SOURCE_RUN,
        central_sha=CENTRAL_SHA,publisher_run=SCHEDULE_RUN,
        event="schedule",ref="refs/heads/main",attempt=1,
        tag="v18.1-windows.3",tag_absent=True,release_absent=True,
        actor="scheduled-workflow-editor")

def switched():
    x=inputs()
    x["fleet"]["releasePolicy"]=issuer.MODE
    for row in x["fleet"]["entries"]:
        row["releasePolicy"]=issuer.MODE
    x["central"]["releasePolicy"]=issuer.MODE
    x["local"]["releasePolicy"]=issuer.MODE
    x["unattended"]["mode"]="UNATTENDED"
    for name in x["unattended"]["controls"]:
        x["unattended"]["controls"][name]=True
    x["boundary"]={"schemaVersion":1,"mode":"ENFORCE",
                   "publisherAppId":5451798,
                   "publisherInstallationId":174720074,
                   "signerAppId":15368}
    return x

def independent_jobs():
    return {"total_count":2,"jobs":[
        {"id":111,"run_id":SCHEDULE_RUN,"run_attempt":1,"head_sha":CENTRAL_SHA,
         "name":"Fresh independent ZIP/SPDX/Grype/Sigstore GET for signed original (pgaudit)",
         "status":"completed","conclusion":"success"},
        {"id":112,"name":"Fresh independent ZIP/SPDX/Grype/Sigstore GET for signed original (other)",
         "status":"completed","conclusion":"failure"}]}

class IssuerTests(unittest.TestCase):
    def test_repository_proof_succeeds_despite_failed_peer(self):
        self.assertEqual(issuer.independent_source_job(independent_jobs(),
            repository=REPO,run_id=SCHEDULE_RUN,central_sha=CENTRAL_SHA),111)

    def test_separate_proof_rejects_failure_replay_and_incomplete_inventory(self):
        for change in (
            lambda j:j.update(total_count=100),
            lambda j:j.update(total_count=3),
            lambda j:j["jobs"].append(deepcopy(j["jobs"][0])),
            lambda j:j["jobs"][0].update(name="unrelated"),
            lambda j:j["jobs"][0].update(run_id=SOURCE_RUN),
            lambda j:j["jobs"][0].update(run_attempt=2),
            lambda j:j["jobs"][0].update(head_sha="d"*40),
            lambda j:j["jobs"][0].update(conclusion="failure"),
            lambda j:j["jobs"][0].update(conclusion="skipped"),
            lambda j:j["jobs"][0].update(status="in_progress"),
            lambda j:j["jobs"][0].update(id=True),
        ):
            jobs=independent_jobs()
            change(jobs)
            with self.subTest(jobs=jobs),self.assertRaises(issuer.Denied):
                issuer.independent_source_job(jobs,repository=REPO,
                    run_id=SCHEDULE_RUN,central_sha=CENTRAL_SHA)

    def test_actual_deployed_modes_never_issue_a_receipt(self):
        with self.assertRaises(issuer.Denied):
            issuer.issue(**inputs())

    def test_all_independent_gates_synthetic_structure(self):
        # An all-green synthetic fixture tests ONLY the pure conditional code.
        result=issuer.issue(**switched())
        self.assertEqual(result["authorizationMode"],"automatic-schedule")
        self.assertTrue(result["publicationAuthorized"])
        self.assertEqual(result["trustedCommit"],SHA)
        self.assertNotEqual(result["sourceRunId"],result["publisherRunId"])
        self.assertNotIn("token",result)
        self.assertNotIn("operator",result)
        self.assertEqual(result["sources"],[old.p.ident.sources(inputs()["manifest"])[m]
                                             for m in range(14,19)])

    def deny(self,mutations):
        for n,mutate in enumerate(mutations):
            with self.subTest(case=n),self.assertRaises(issuer.Denied):
                data=switched()
                mutate(data)
                issuer.issue(**data)

    def test_policy_and_dynamic_roster_forgery_denied(self):
        self.deny([
            lambda x:x["fleet"].update(releasePolicy="manual-only"),
            lambda x:x["fleet"]["entries"][0].update(releasePolicy="manual-only"),
            lambda x:x["fleet"]["entries"].append(deepcopy(x["fleet"]["entries"][0])),
            lambda x:x["fleet"]["entries"].pop(),
            lambda x:x["central"].update(releasePolicy="manual-dispatch"),
            lambda x:x["central"]["allowedRepositories"].pop(),
            lambda x:x["local"].update(releasePolicy="manual-dispatch"),
            lambda x:x["unattended"].update(mode="OBSERVE"),
            lambda x:x["unattended"].update(defaultAction="ALLOW"),
            lambda x:x["unattended"]["controls"].update(automaticFormalRelease=False),
            lambda x:x["boundary"].update(mode="DENY"),
            lambda x:x["boundary"].update(publisherAppId=15368),
            lambda x:x["boundary"].update(publisherInstallationId=999),
        ])

    def test_incomplete_or_unknown_controls_cannot_issue_receipt(self):
        for name in switched()["unattended"]["controls"]:
            with self.subTest(missing=name), self.assertRaises(issuer.Denied):
                data=switched()
                del data["unattended"]["controls"][name]
                issuer.issue(**data)
        self.deny([
            lambda x:x["unattended"].update(controls={"automaticFormalRelease":True}),
            lambda x:x["unattended"]["controls"].update(unknownGuard=True),
            lambda x:x["unattended"].update(schemaVersion=True),
            lambda x:x["unattended"].update(scheduleUtc="0 0 * * *"),
            lambda x:x["unattended"].update(unrecognized=True),
            lambda x:x["central"].update(schemaVersion=True),
            lambda x:x["local"].update(schemaVersion=True),
            lambda x:x["local"].update(enabled=1),
            lambda x:x["boundary"].update(schemaVersion=True),
        ])

    def test_future_registered_member_uses_same_policy_without_count_change(self):
        data=switched()
        row=deepcopy(data["fleet"]["entries"][0])
        row["repository"]="pgextwin/future_extension"
        data["fleet"]["entries"].append(row)
        data["central"]["allowedRepositories"].append(row["repository"])
        # Roster growth is a static configuration fact, never source proof.
        issuer.policy_gate(data["fleet"],data["central"],data["local"],
                           data["unattended"],data["boundary"],row["repository"])
        result=issuer.issue(**data)
        self.assertEqual(result["repository"],REPO)
        data["central"]["allowedRepositories"].pop()
        with self.assertRaises(issuer.Denied):
            issuer.issue(**data)

    def test_static_readiness_uses_the_same_complete_policy(self):
        readiness=load("shared_issuer_readiness","scripts/automatic-publisher-readiness.py")
        data=switched()
        self.assertIs(readiness.ready(data["fleet"],data["central"],
                                     data["unattended"],data["boundary"]),True)
        for control in data["unattended"]["controls"]:
            bad=deepcopy(data)
            del bad["unattended"]["controls"][control]
            with self.subTest(control=control),self.assertRaises(readiness.issuer.Denied):
                readiness.ready(bad["fleet"],bad["central"],
                                bad["unattended"],bad["boundary"])

    def test_forged_signer_source_scheduler_replay_denied(self):
        self.deny([
            lambda x:x.update(event="workflow_dispatch"),
            lambda x:x.update(event="push"),
            lambda x:x.update(ref="refs/heads/bad"),
            lambda x:x.update(attempt=2),
            lambda x:x.update(attempt=True),
            lambda x:x.update(source_run=SCHEDULE_RUN),
            lambda x:x.update(source_run=True),
            lambda x:x["schedule_run"].update(event="push"),
            lambda x:x["schedule_run"].update(path=".github/workflows/validate.yml"),
            lambda x:x["schedule_run"].update(run_attempt=2),
            lambda x:x["schedule_run"].update(status="completed",conclusion="success"),
            lambda x:x["schedule_run"].update(head_sha="d"*40),
            lambda x:x["schedule_run"].update(repository={"full_name":REPO}),
            lambda x:x["central_branch"].update(protected=False),
            lambda x:x["signed_branch"]["commit"].update(sha="d"*40),
            lambda x:x["proof"].update(realSigstoreRechecked=False),
            lambda x:x["proof"].update(blockingGrypeFindings=1),
            lambda x:x["proof"].update(publicationAuthorized=True),
            lambda x:x["proof"].update(sourceRunAttempt=2),
            lambda x:x["proof"].update(sourceRunId=123),
            lambda x:x["proof"].update(mainMergeSha="d"*40),
            lambda x:x["proof"].update(maintainedMajors=[14,15,16,18]),
            lambda x:x["proof"]["zipSha256ByMajor"].pop("18"),
            lambda x:x["proof"]["grypeSha256ByMajor"].update({"18":"x"*64}),
            lambda x:x.update(repository="pgextwin/evil"),
            lambda x:x.update(tag="v19.3-windows.1"),
            lambda x:x.update(tag_absent=False),
            lambda x:x.update(release_absent=False),
        ])

    def test_issuer_app_or_privilege_expansion_denied(self):
        self.deny([
            lambda x:x["app_identity"].update(id=15368),
            lambda x:x["app_identity"].update(slug="fake"),
            lambda x:x["installation_identity"].update(id=0),
            lambda x:x["installation_identity"].update(app_id=15368),
            lambda x:x["installation_identity"].update(repository_selection="selected"),
            lambda x:x["installation_identity"].update(suspended_at="suspended"),
            lambda x:x["minted"].update(token="too-short"),
            lambda x:x["minted"].update(repository_selection="all"),
            lambda x:x["minted"]["permissions"].update(actions="write"),
            lambda x:x["scoped"].update(total_count=2),
            lambda x:x["scoped"]["repositories"].append({"full_name":"pgextwin/evil"}),
            lambda x:x["scoped"]["repositories"][0].update(full_name="pgextwin/evil"),
        ])

    def test_module_has_no_side_effects_or_token_leak(self):
        src=(ROOT/"scripts/automatic-publisher-receipt-issuer.py").read_text()
        for value in ("import subprocess","from subprocess","urlopen","import requests","gh release create",
                      "gh api -X POST","GH_TOKEN","PUBLISHER_PRIVATE_KEY"):
            self.assertNotIn(value,src)

if __name__=="__main__":
    unittest.main()
