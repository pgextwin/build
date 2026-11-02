#!/usr/bin/env python3
"""Fail-closed independent Publisher-side owner-signed source admission tests."""
import copy
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "publisher_owner_source_admission",
    ROOT / "scripts/publisher-owner-source-admission.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "a" * 40
REPO = "pgextwin/plpgsql_check"
USER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}
COMMAND = "/pgextwin admit-owner-source " + REPO + " 41486380278"

def env():
    return {"GITHUB_REPOSITORY": "pgextwin/build",
            "GITHUB_EVENT_NAME": "issue_comment", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "ShutenOishi",
            "GITHUB_TRIGGERING_ACTOR": "ShutenOishi", "GITHUB_ACTOR_ID": "27071164",
            "GITHUB_RUN_ID": "5555", "GITHUB_SHA": SHA}

def event():
    return {"action": "created", "sender": dict(USER),
            "repository": {"full_name": "pgextwin/build"},
            "issue": {"number": 311},
            "comment": {"id": 3333, "body": COMMAND, "user": dict(USER),
                        "issue_url": "https://api.github.com/repos/pgextwin/build/issues/311",
                        "created_at": "2026-11-03T00:00:00Z",
                        "updated_at": "2026-11-03T00:00:00Z"}}

def run():
    return {"id": 5555, "run_attempt": 1, "event": "issue_comment",
            "path": mod.CENTRAL_WORKFLOW, "head_branch": "main", "head_sha": SHA,
            "status": "in_progress", "repository": {"full_name": "pgextwin/build"},
            "actor": dict(USER), "triggering_actor": dict(USER)}

def branch():
    return {"name": "main", "protected": True, "commit": {"sha": SHA}}

def intent():
    return {"schemaVersion": 1, "sourceKind": mod.SOURCE_KIND,
            "sourceEvent": "issue_comment", "repository": REPO, "mainSha": SHA,
            "runId": 41486380278, "runAttempt": 1, "issueNumber": 78,
            "commentId": 4444, "signingEligible": True,
            "publisherEligible": False, "publicationAuthorized": False,
            "PUBLISH": "DENY"}

def signed_run():
    r = run()
    r.update(id=41486380278, status="completed", conclusion="success",
             path=mod.SOURCE_WORKFLOW,
             repository={"full_name": REPO})
    return r

def original_jobs():
    names = (["Original authenticated owner/main/comment source (DENY Publisher)",
              "Resolve extension and PostgreSQL matrix",
              "Independent original Sigstore/ZIP/SPDX/Grype audit (first)",
              "Independent original Sigstore/ZIP/SPDX/Grype audit (second)",
              "Require exact independent real-signature byte agreement (NO PUBLISH)"]
             + [f"PostgreSQL {m} / Windows x64" for m in (14,15,16,17,18)])
    return {"total_count": len(names), "jobs": [
        {"name": n, "id": 100+i, "run_id": 41486380278, "run_attempt": 1,
         "head_sha": SHA, "status": "completed", "conclusion": "success"}
        for i, n in enumerate(names)]}

def source_artifacts():
    names = ["chat-main-source-intent-nonpublishing",
             "chat-owner-sigstore-first-nonpublishing",
             "chat-owner-sigstore-second-nonpublishing",
             "chat-owner-dual-sigstore-nonpublishing"]
    return {"total_count": 4, "artifacts": [
        {"name": n, "id": i+1, "size_in_bytes": 40, "expired": False}
        for i, n in enumerate(names)]}

def live_signing():
    return {"id": 4444, "body": "/pgextwin sign-main",
            "issue_url": "https://api.github.com/repos/" + REPO + "/issues/78",
            "created_at": "2026-11-03T00:00:00Z",
            "updated_at": "2026-11-03T00:00:00Z", "user": dict(USER)}

def source_check(**overrides):
    x = {"repo": REPO, "sha": SHA, "run_id": 41486380278,
         "run": signed_run(), "jobs": original_jobs(),
         "artifacts": source_artifacts(), "intent": intent(),
         "live": live_signing(), "majors": [14,15,16,17,18]}
    x.update(overrides)
    return mod.source_metadata(**x)

class AdmissionTests(TestCase):
    def test_genuine_original_owner_source_and_no_publication(self):
        self.assertEqual(mod.authenticate_request(
            event(), event()["comment"], run(), branch(), env()),
            (REPO, 41486380278))
        self.assertIsNone(source_check())
        self.assertEqual(mod.SOURCE_KIND, "OWNER_ISSUE_COMMENT_MAIN_SIGNING")

    def test_wrong_central_run_actor_replay_and_ref_denied(self):
        for field, value in (("GITHUB_RUN_ATTEMPT", "2"),
                             ("GITHUB_REF", "refs/heads/fake"),
                             ("GITHUB_EVENT_NAME", "push"),
                             ("GITHUB_ACTOR", "other"),
                             ("GITHUB_TRIGGERING_ACTOR", "other"),
                             ("GITHUB_SHA", "b"*40)):
            with self.subTest(field=field):
                e=env();e[field]=value
                with self.assertRaises(mod.Denied):
                    mod.authenticate_request(event(),event()["comment"],
                                             run(),branch(),e)
        for field,value in (("event","schedule"), ("path",mod.SOURCE_WORKFLOW),
                            ("run_attempt",2), ("status","completed")):
            r=run();r[field]=value
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(event(),event()["comment"],
                                         r,branch(),env())

    def test_wrong_owner_command_or_edited_comment_denied(self):
        for bad in ("/pgextwin publish "+REPO,
                    "/pgextwin admit-owner-source "+REPO+" 0",
                    COMMAND+"\\n", COMMAND+" extra", COMMAND.replace(REPO,"pgextwin/fake;rm")):
            e=event();e["comment"]["body"]=bad
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(e,e["comment"],run(),branch(),env())
        for field,value in (("updated_at","2026-11-03T01:00:00Z"),
                            ("user",{"login":"attacker","id":1}),
                            ("issue_url","https://evil.invalid")):
            e=event();e["comment"][field]=value
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(e,e["comment"],run(),branch(),env())

    def test_source_run_wrong_kind_edited_or_replayed_denied(self):
        for key, value in (("event","push"), ("path",".github/workflows/update-watch.yml"),
                           ("run_attempt",2), ("status","in_progress"),
                           ("head_sha","b"*40),("conclusion","failure")):
            with self.subTest(key=key):
                r=signed_run();r[key]=value
                with self.assertRaises(mod.Denied):
                    source_check(run=r)
        for key,value in (("sourceKind","PUSH"),("publisherEligible",True),
                          ("publicationAuthorized",True),("PUBLISH","ALLOW"),
                          ("runAttempt",2),("mainSha","b"*40)):
            with self.subTest(key=key):
                i=intent();i[key]=value
                with self.assertRaises(mod.Denied):
                    source_check(intent=i)

    def test_failed_second_dual_or_missing_artifact_denied(self):
        jobs=original_jobs()
        for n in (2,3):
            altered=copy.deepcopy(jobs)
            altered["jobs"][n]["conclusion"]="failure"
            with self.assertRaises(mod.Denied):
                source_check(jobs=altered)
        for name in ("chat-owner-sigstore-second-nonpublishing",
                     "chat-owner-dual-sigstore-nonpublishing"):
            a=source_artifacts()
            a["artifacts"]=[x for x in a["artifacts"] if x["name"]!=name]
            a["total_count"]=len(a["artifacts"])
            with self.assertRaises(mod.Denied):
                source_check(artifacts=a)
        x=live_signing();x["body"]="/pgextwin publish "+REPO
        with self.assertRaises(mod.Denied):
            source_check(live=x)

    def test_source_must_not_enable_formal_publisher(self):
        path=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        self.assertIn("independent_owner_source_admission:",path)
        job=path.split("  independent_owner_source_admission:",1)[1].split(
            "  independent_real_signed_source:",1)[0]
        self.assertIn("publisher-owner-source-admission.py",job)
        self.assertIn("github.event_name == 'issue_comment'",job)
        self.assertIn("admit-owner-source",job)
        for denied in ("environment: publisher","contents: write",
                       "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",
                       "gh release create","secrets.","schedule:"):
            self.assertNotIn(denied,job)
        self.assertIn("PUBLISH_DENY",job)

if __name__ == "__main__":
    main()
