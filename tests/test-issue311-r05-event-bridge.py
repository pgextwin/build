#!/usr/bin/env python3
"""R05 live completed-event bridge hostile proof: reject absent children, ZIPs and privilege."""
from pathlib import Path
import copy
import importlib.util
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("bridge","scripts/issue311-r05-event-bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def source_event():
    source = {"id": 42, "workflow_id": 111, "run_attempt": 1,
              "head_sha": "a"*40, "path": bridge.SOURCE_WORKFLOW,
              "head_branch": "main", "event": "push", "conclusion": "success",
              "status": "completed", "actor": {"login": "ShutenOishi"},
              "name": "Issue 311 R05 verified 17-target source event (NONPUBLISHING)"}
    return {"action":"completed", "repository":{"full_name":"pgextwin/build"},
            "workflow_run": source}


class Tests(unittest.TestCase):
    def test_original_event_and_independent_rest_binding(self):
        original=source_event()
        self.assertEqual(bridge.validate_source_metadata(original, copy.deepcopy(
            original["workflow_run"]))["id"],42)
        for field, val in (("event","workflow_dispatch"),
                           ("path",".github/workflows/other.yml"),
                           ("run_attempt",2),("head_branch","evil"),
                           ("conclusion","failure")):
            with self.subTest(field=field):
                wrong=copy.deepcopy(original["workflow_run"])
                wrong[field]=val
                with self.assertRaises(ValueError):
                    bridge.validate_source_metadata(original,wrong)
        event=source_event()
        event["workflow_run"]["actor"]["login"]="unknown-actor"
        with self.assertRaises(ValueError):
            bridge.validate_source_metadata(event,event["workflow_run"])

    def test_child_fail_missing_skipped_not_terminal_success(self):
        jobs=[{"name":"GET "+x,"run_id":42,"status":"completed",
               "conclusion":"success"} for x in bridge.aggregate.REPOS]
        jobs.append({"name":"Always aggregate original 17 target jobs even when skipped or failed",
                     "run_id":42,"status":"completed","conclusion":"success"})
        full={"total_count":18,"jobs":jobs}
        self.assertEqual(len(bridge.require_jobs(full,42,"success")),17)
        for result in ("failure","cancelled","skipped",None):
            altered=copy.deepcopy(full)
            altered["jobs"][0]["conclusion"]=result
            with self.assertRaises(ValueError):
                bridge.require_jobs(altered,42,"success")
        for altered in ({"total_count":17,"jobs":jobs},
                        {"total_count":17,"jobs":jobs[:17]},
                        {"total_count":18,"jobs":jobs[:-1] + jobs[:1]}):
            with self.assertRaises(ValueError):
                bridge.require_jobs(altered,42,"success")
        with self.assertRaises(ValueError):
            bridge.require_jobs(full,42,"failure")

    def test_missing_and_expired_original_ZIP_denied(self):
        expected={bridge.ZIP_PREFIX+x.removeprefix("pgextwin/")
                  for x in bridge.aggregate.REPOS}
        expected.add(bridge.ZIP_TERMINAL)
        vals=[{"name":n,"id":idx+1,"workflow_run":{"id":42},
               "expired":False,"digest":"sha256:"+"a"*64}
              for idx,n in enumerate(sorted(expected))]
        self.assertEqual(set(bridge.parse_artifacts({"total_count":18,
                         "artifacts":vals},42)),expected)
        for update in ("missing","expired","foreign","duplicate"):
            changed=copy.deepcopy(vals)
            if update=="missing": changed.pop()
            elif update=="expired": changed[0]["expired"]=True
            elif update=="foreign": changed[0]["workflow_run"]["id"]=99
            elif update=="duplicate": changed.append(copy.deepcopy(changed[0]))
            with self.subTest(update=update),self.assertRaises(ValueError):
                bridge.parse_artifacts({"total_count":len(changed),
                                         "artifacts":changed},42)

    def test_original_receipt_wrong_run_or_request_denied(self):
        repo=sorted(bridge.aggregate.REPOS)[0]
        good={"requestId":bridge.REQUEST,"repository":repo,"runId":42,
              "runAttempt":1,"result":"SUCCESS","publicationAuthorized":False,
              "protected":True,"rawSha256":"b"*64,"mainSha":"a"*40}
        terminal={"requestId":bridge.REQUEST,"runId":42,"runAttempt":1,
                  "terminal":"NO_UPDATE","publishAuthorized":False,
                  "persistenceAccepted":False,
                  "perTarget":{x:"success" for x in bridge.aggregate.REPOS}}
        def original(entry,name):
            if name=="issue311-r05-17-terminal.json":
                return terminal,"c"*64
            item=dict(good,repository=entry["repo"])
            if entry["repo"]==repo:item["runAttempt"]=2
            return item,"c"*64
        entries={bridge.ZIP_PREFIX+x.removeprefix("pgextwin/"):{"repo":x}
                 for x in bridge.aggregate.REPOS}
        entries[bridge.ZIP_TERMINAL]={}
        with mock.patch.object(bridge,"original_zip",side_effect=original):
            with self.assertRaises(ValueError):
                bridge.check_receipts(entries,42,1,"b"*64,
                    {x:"a"*40 for x in bridge.aggregate.REPOS},
                    {x:"success" for x in bridge.aggregate.REPOS})

    def test_no_publisher_permissions_or_second_stage_trigger(self):
        y=Path(".github/workflows/issue311-r05-event-bridge.yml").read_text()
        src=Path(".github/workflows/issue311-r05-event-source.yml").read_text()
        for forbidden in ("contents: write","id-token: write","workflow_dispatch",
                          "repository_dispatch","schedule:","pull_request_target"):
            self.assertNotIn(forbidden,y)
            self.assertNotIn(forbidden,src)
        self.assertIn("workflow_run:",y)
        self.assertIn("types: [completed]",y)
        self.assertIn("if: always()",src)
        self.assertIn("max-parallel: 4",src)


if __name__ == "__main__":
    unittest.main()
