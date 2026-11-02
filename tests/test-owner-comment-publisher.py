#!/usr/bin/env python3
"""Hostile offline regressions for a genuine owner Issue #311 Publisher event."""
import importlib.util
import json
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from unittest import TestCase,main
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod
trigger=load("issue_comment_trigger","scripts/publisher-trigger-auth.py")
issuer=load("issue_comment_issuer","scripts/automatic-publisher-receipt-issuer.py")
fixture=load("issue_comment_fixture","tests/test-automatic-publisher-receipt-issuer.py")
REPO="pgextwin/hypopg"
CID=6578723847
IDENTITY={"login":"ShutenOishi","id":27071164,"type":"User"}
def inputs(root):
    path=root/"event.json"
    content={"action":"created","issue":{"number":311},
             "comment":{"id":CID,"user":dict(IDENTITY),
                        "issue_url":"https://api.github.com/repos/pgextwin/build/issues/311",
                        "body":"/pgextwin publish "+REPO,
                        "created_at":"2026-11-02T13:44:34Z",
                        "updated_at":"2026-11-02T13:44:34Z"},
             "sender":dict(IDENTITY)}
    path.write_text(json.dumps(content))
    env={"GITHUB_EVENT_NAME":"issue_comment",
         "GITHUB_REPOSITORY":"pgextwin/build",
         "GITHUB_REF":"refs/heads/main","GITHUB_RUN_ATTEMPT":"1",
         "GITHUB_ACTOR":"ShutenOishi","GITHUB_TRIGGERING_ACTOR":"ShutenOishi",
         "GITHUB_ACTOR_ID":"27071164","GITHUB_EVENT_PATH":str(path)}
    return env,path,content
class CommentPublisher(TestCase):
    def test_original_event_scoped_to_one_registered_target(self):
        with tempfile.TemporaryDirectory() as d:
            env,path,obj=inputs(Path(d))
            self.assertEqual(trigger.issue_request(env),(REPO,CID))
            self.assertEqual(trigger.request(env),(REPO,False,CID))
            self.assertEqual(trigger.live_comment(
                env,lambda repo,route:{"id":CID,"user":dict(IDENTITY),
                    "body":"/pgextwin publish "+REPO,
                    "issue_url":"https://api.github.com/repos/pgextwin/build/issues/311",
                    "created_at":"2026-11-02T13:44:34Z",
                    "updated_at":"2026-11-02T13:44:34Z"},
                repository=REPO),CID)
            with self.assertRaises(trigger.Denied):
                trigger.issue_request(env,repository="pgextwin/evil")
            for field,val in (("GITHUB_ACTOR","attacker"),
                              ("GITHUB_ACTOR_ID","1"),
                              ("GITHUB_TRIGGERING_ACTOR","attacker"),
                              ("GITHUB_RUN_ATTEMPT","2"),
                              ("GITHUB_REF","refs/heads/other")):
                with self.subTest(field=field),self.assertRaises(trigger.Denied):
                    trigger.issue_request(dict(env,**{field:val}))
            for field,val in (("action","edited"),):
                bad=deepcopy(obj);bad[field]=val;path.write_text(json.dumps(bad))
                with self.assertRaises(trigger.Denied):trigger.issue_request(env)
            for field,val in (("body","/pgextwin publish pgextwin/*"),
                              ("body","/pgextwin publish pgextwin/hypopg\\n"),
                              ("updated_at","2026-11-02T13:44:35Z")):
                with self.subTest(field=field):
                    bad=deepcopy(obj);bad["comment"][field]=val
                    path.write_text(json.dumps(bad))
                    with self.assertRaises(trigger.Denied):trigger.issue_request(env)
            bad=deepcopy(obj);bad["issue"]["number"]=75
            path.write_text(json.dumps(bad))
            with self.assertRaises(trigger.Denied):trigger.issue_request(env)
    def test_typed_live_issuer_and_replay_negative(self):
        item=fixture.owner_dispatch()
        item.update(event="issue_comment",request_comment_id=CID)
        item["schedule_run"].update(event="issue_comment",
            display_title=f"Publisher-issue_comment-comment-{CID}")
        receipt=issuer.issue(**item)
        self.assertEqual(receipt["authorizationMode"],"owner-issue-comment")
        self.assertEqual(receipt["requestCommentId"],CID)
        self.assertEqual(receipt["approvalProvenance"],
                         "INDEPENDENT_LIVE_OWNER_COMMENT_AND_SIGNED_SOURCE")
        for mutate in (
            lambda x:x.update(request_comment_id=None),
            lambda x:x["schedule_run"].update(display_title="Publisher-issue_comment-comment-0"),
            lambda x:x["schedule_run"].update(event="workflow_dispatch"),
            lambda x:x["schedule_run"]["triggering_actor"].update(id=1),
            lambda x:x["schedule_run"].update(run_attempt=2),
            lambda x:x["owner_policy"].update(defaultDryRun=False),
        ):
            with self.subTest(mutate=repr(mutate)),self.assertRaises(issuer.Denied):
                bad=deepcopy(item);mutate(bad);issuer.issue(**bad)
if __name__=="__main__":main()
