#!/usr/bin/env python3
"""First-release candidate CI observation is GET-only, never PUBLISH authority."""
from copy import deepcopy
import base64
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
sp = importlib.util.spec_from_file_location("readonly_observer", ROOT / "scripts/chat-publication-readonly.py")
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
REPO = "pgextwin/pgtap"
BOT = {"login": "github-actions[bot]", "type": "Bot"}
USER = {"login": "ShutenOishi", "type": "User"}
BASE, HEAD, MERGE = "a"*40, "b"*40, "c"*40
DIGEST = "d2988a25e59025d4764a"
NAME = "auto-candidate/" + DIGEST
SOURCE = {"repository": "theory/pgtap", "ref": "v1.3.4",
          "version": "1.3.4", "commit": "d"*40}


def encode(path, sha, content):
    raw = json.dumps(content).encode("utf-8")
    return {"type": "file", "path": path, "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode("ascii"), "sha": m.auth.git_blob_sha(raw)}


def fixture(mode="pull_request", attempt=2):
    assert mode in ("pull_request", "workflow_dispatch")
    env = {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_NAME": mode,
           "GITHUB_SHA": MERGE if mode == "pull_request" else HEAD,
           "GITHUB_REF": "refs/pull/7/merge" if mode == "pull_request" else "refs/heads/" + NAME,
           "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": str(attempt),
           "GITHUB_ACTOR": BOT["login"]}
    event = {"repository": {"full_name": REPO}, "sender": dict(BOT)}
    if mode == "pull_request":
        event.update(number=7, pull_request={"head": {"sha": HEAD}})
    pr = {"number": 7, "state": "open", "merged": False, "draft": True, "changed_files": 1,
          "user": dict(BOT), "head": {"sha": HEAD, "ref": NAME, "repo": {"full_name": REPO}},
          "base": {"sha": BASE, "ref": "main", "repo": {"full_name": REPO}}}
    intent = {"schemaVersion": 1, "kind": "FIRST_RELEASE_PINNED_SOURCE",
              "repository": REPO, "extension": "pgtap", "releasePolicy": "manual-only",
              "candidateId": DIGEST, "source": dict(SOURCE)}
    ip = "contents/config/initial-release-candidate.json?ref=" + HEAD
    ep = "contents/config/extension.json?ref=" + BASE
    data = {"actions/runs/123": {"id": 123, "run_attempt": attempt, "event": mode,
                "path": ".github/workflows/windows.yml", "repository": {"full_name": REPO},
                "actor": dict(BOT), "triggering_actor": dict(USER if attempt == 2 else BOT),
                "head_sha": HEAD, "head_branch": NAME},
            "branches/main": {"protected": True, "commit": {"sha": BASE}},
            "pulls/7": pr, "pulls/7/files?per_page=100": [],
            "commits/" + HEAD: {"sha": HEAD, "author": dict(BOT),
                 "commit": {"message": "chore: propose upstream candidate\n\n<!-- pgextwin-candidate:v1:" + DIGEST + " -->"}},
            "commits/" + HEAD + "/pulls?per_page=100": [pr],
            ip: encode("config/initial-release-candidate.json", HEAD, intent),
            ep: encode("config/extension.json", BASE, {"name": "pgtap", "upstream": dict(SOURCE)})}
    data["pulls/7/files?per_page=100"] = [{"filename": "config/initial-release-candidate.json",
                                               "sha": data[ip]["sha"], "status": "added"}]
    return env, event, data


class Reader:
    def __init__(self, data):
        self.data = data
    def get(self, path):
        m.Reader.allowed(path)
        return deepcopy(self.data[path])


class SafeCandidate(TestCase):
    def inspect(self, f):
        e, v, d = f
        return m.inspect(e, v, Reader(d))

    def denied(self, change, mode="pull_request", attempt=2):
        e, v, d = fixture(mode, attempt)
        change(e, v, d)
        with self.assertRaises((m.Denied, ValueError, KeyError, TypeError)):
            self.inspect((e, v, d))

    def test_real_candidate_dispatch_and_bot_pr_approval_are_nonpublishing(self):
        for mode, attempt in (("workflow_dispatch", 1), ("pull_request", 1), ("pull_request", 2)):
            with self.subTest(mode=mode, attempt=attempt):
                output = self.inspect(fixture(mode, attempt))
                self.assertEqual(output["status"], "VALID_FIRST_CANDIDATE_CI_PUBLICATION_DENIED")
                self.assertEqual(output["candidateId"], DIGEST)
                self.assertEqual(output["candidateHeadSha"], HEAD)
                for key in ("publishableReceipt", "publicationAuthorized",
                            "catalogProposalAuthorized", "independentWriterVerified",
                            "effectiveClassicProtectionVerified", "mutationsEnabled"):
                    self.assertIs(output[key], False)
                self.assertEqual((output["publication"], output["goB"], output["g4"], output["g5"]),
                                 ("DENY", "NO_GO", "NO_GO", "NO_GO"))

    def test_denies_spoof_replay_stale_branch_and_changed_candidate(self):
        cases = [
          lambda e,v,d: e.update(GITHUB_ACTOR="ShutenOishi"),
          lambda e,v,d: e.update(GITHUB_REF="refs/heads/main"),
          lambda e,v,d: d["actions/runs/123"]["actor"].update(type="User"),
          lambda e,v,d: d["actions/runs/123"]["triggering_actor"].update(login="attacker"),
          lambda e,v,d: d["actions/runs/123"].update(head_sha=BASE),
          lambda e,v,d: d["actions/runs/123"].update(path=".github/workflows/promote.yml"),
          lambda e,v,d: d["actions/runs/123"].update(run_attempt=3),
          lambda e,v,d: d["branches/main"].update(protected=False),
          lambda e,v,d: d["branches/main"]["commit"].update(sha=MERGE),
          lambda e,v,d: d["pulls/7"]["user"].update(type="User"),
          lambda e,v,d: d["pulls/7"]["head"].update(sha=BASE),
          lambda e,v,d: d["pulls/7"]["head"]["repo"].update(full_name="evil/fork"),
          lambda e,v,d: d["pulls/7"].update(merged=True),
          lambda e,v,d: d["pulls/7"].update(changed_files=2),
          lambda e,v,d: d["pulls/7/files?per_page=100"][0].update(status="modified"),
          lambda e,v,d: d["pulls/7/files?per_page=100"][0].update(filename="config/extension.json"),
          lambda e,v,d: d["commits/"+HEAD]["author"].update(login="attacker"),
          lambda e,v,d: d["commits/"+HEAD]["commit"].update(message="forged"),
          lambda e,v,d: d["contents/config/initial-release-candidate.json?ref="+HEAD].update(sha=MERGE),
          lambda e,v,d: d["contents/config/extension.json?ref="+BASE].update(content="%%%")
        ]
        for i, fn in enumerate(cases):
            with self.subTest(case=i):
                self.denied(fn)

    def test_denies_unapproved_retry_and_wrong_dispatch(self):
        self.denied(lambda e,v,d:d["actions/runs/123"]["triggering_actor"].update(type="Bot"),
                    "pull_request", 2)
        self.denied(lambda e,v,d:e.update(GITHUB_RUN_ATTEMPT="3"), "pull_request", 2)
        self.denied(lambda e,v,d:e.update(GITHUB_RUN_ATTEMPT="2"), "workflow_dispatch", 1)
        self.denied(lambda e,v,d:d["actions/runs/123"]["triggering_actor"].update(login="ShutenOishi"),
                    "workflow_dispatch", 1)


if __name__ == "__main__":
    main()
