#!/usr/bin/env python3
"""G2 hostile offline fixtures; ONLY protected-main live job can prove real evidence."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("g2_test", ROOT / "scripts/chat-pr-g2-live-negative.py")
assert spec and spec.loader
g2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g2)
SHA = "a" * 40

def env():
    return {"GITHUB_SHA": SHA, "GITHUB_REPOSITORY": g2.REPO,
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR": "ShutenOishi"}

def event():
    return {"ref": "refs/heads/main", "after": SHA,
            "repository": {"full_name": g2.REPO},
            "sender": {"login": "ShutenOishi", "type": "User"}}

def data():
    b = g2.BASE
    return {
        "installation/repositories?per_page=100":
            {"total_count": 1, "repositories": [{"full_name": g2.REPO}]},
        b + "branches/main": {"name": "main", "protected": True, "commit": {"sha": SHA}},
        b + "contents/.github/release-authorizations?ref=" + SHA: None,
        b + "commits/" + SHA: {"sha": SHA, "files": [{"filename": "normal.md"}]},
        b + "pulls/29": {"number": 29, "state": "open", "draft": True,
                        "merged": False, "head": {"ref": g2.CANDIDATE_BRANCH,
                                                  "sha": g2.CANDIDATE_HEAD}},
        b + "actions/runs/38356899464": {
            "id": 38356899464, "head_sha": g2.CANDIDATE_HEAD,
            "head_branch": g2.CANDIDATE_BRANCH, "event": "workflow_dispatch",
            "run_attempt": 1, "status": "completed", "conclusion": "success",
            "repository": {"full_name": g2.REPO}},
        b + "commits/" + g2.CANDIDATE_HEAD + "/check-runs?per_page=100":
            {"total_count": 1, "check_runs": [{"name": "syntax",
             "head_sha": g2.CANDIDATE_HEAD, "app": {"id": 15368},
             "status": "completed", "conclusion": "success"}]},
        b + "git/ref/tags/" + g2.PROSPECTIVE_TAG: None,
        b + "releases/tags/" + g2.PROSPECTIVE_TAG: None,
        b + "git/ref/tags/" + g2.EXISTING_TAG: {"ref": "refs/tags/" + g2.EXISTING_TAG},
        b + "releases/tags/" + g2.EXISTING_TAG: {
            "tag_name": g2.EXISTING_TAG, "draft": False,
            "published_at": "2026-10-11T00:00:00Z"},
    }

class Reader:
    def __init__(self, token, records, fault=None, race=False):
        self.token, self.records, self.fault, self.race = token, records, fault, race
        self.branch_reads = 0
        self.calls = 0

    def get(self, path, *, allow_404=False):
        self.calls += 1
        if path == g2.BASE + "branches/main":
            self.branch_reads += 1
        if path == self.fault or path not in self.records:
            raise g2.Denied("API failed or unknown")
        value = deepcopy(self.records[path])
        if value is None and not allow_404:
            raise g2.Denied("404 cannot be used as 200")
        if self.race and self.branch_reads >= 3 and path.endswith("/branches/main"):
            value["commit"]["sha"] = "b" * 40
        return value

def harness(records, fault=None, race=False):
    readers = []
    def factory(token):
        reader = Reader(token, records, fault, race)
        readers.append(reader)
        return reader
    def composite(reader, *, expected_main_sha):
        return {"status": "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY",
                "mainSha": expected_main_sha, "snapshotCount": 2,
                "independentEffectiveRefZero": True, "independentPushUnrestricted": True,
                "publishableReceipt": False}
    required = frozenset({"syntax", "windows / Resolve extension and PostgreSQL matrix",
                          "windows / PostgreSQL 15 / Windows x64",
                          "windows / PostgreSQL 16 / Windows x64",
                          "windows / PostgreSQL 17 / Windows x64",
                          "windows / PostgreSQL 18 / Windows x64",
                          "Regression-test immutable Release preflight",
                          "Windows required summary"})
    adapter = SimpleNamespace(
        PilotReadOnly=factory,
        classic_lib=SimpleNamespace(
            CompositeReader=lambda token: SimpleNamespace(token=token),
            collect_verified_composite=composite,
            rest=SimpleNamespace(REQUIRED_CONTEXTS=required)),
        trusted_json_file=lambda api, path, ref: {"releasePolicy": "manual-dispatch"})
    return adapter, readers

class TestG2(TestCase):
    def test_two_independent_negative_snapshots(self):
        adapter, readers = harness(data())
        result = g2.verify(adapter, "evidence", "admin", event(), env())
        self.assertEqual(result["status"], "DRY_RUN_G2_NEGATIVE_ONLY")
        self.assertEqual(result["snapshotCount"], 2)
        self.assertEqual(result["classicSnapshotCountPerRound"], 2)
        self.assertEqual(result["authorization"], "ABSENT_AUTHENTICATED_404")
        self.assertEqual(result["candidateExactHeadPassingCheckCount"], 1)
        self.assertEqual(result["fullPositiveJit"], "BLOCKED_NO_REAL_AUTHORIZATION")
        self.assertFalse(result["publishableReceipt"])
        self.assertFalse(result["mutationsEnabled"])
        self.assertEqual(readers[0].calls, 22)
        self.assertEqual(readers[1].calls, 2)

    def test_preflight_fails_closed(self):
        for change in ({"GITHUB_ACTOR": "github-actions[bot]"},
                       {"GITHUB_RUN_ATTEMPT": "2"},
                       {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                       {"GITHUB_REF": "refs/heads/untrusted"},
                       {"GITHUB_SHA": "z" * 40}):
            with self.subTest(change=change), self.assertRaises(g2.Denied):
                g2.preflight(event(), dict(env(), **change))
        x = event(); x["sender"]["login"] = "someoneelse"
        with self.assertRaises(g2.Denied):
            g2.preflight(x, env())

    def test_bad_auth_draft_checks_policy_tag(self):
        b = g2.BASE
        cases = [
            ("installation/repositories?per_page=100", lambda x: x.update(total_count=2)),
            (b+"branches/main", lambda x: x.update(protected=False)),
            (b+"commits/"+SHA, lambda x: x.update(files=[{
                "filename": ".github/release-authorizations/forbidden.json"}])),
            (b+"pulls/29", lambda x: x.update(draft=False)),
            (b+"pulls/29", lambda x: x["head"].update(sha="0"*40)),
            (b+"actions/runs/38356899464", lambda x: x.update(conclusion="failure")),
            (b+"commits/"+g2.CANDIDATE_HEAD+"/check-runs?per_page=100",
             lambda x: x.update(total_count=99)),
        ]
        for path, mutate in cases:
            snapshot = data(); mutate(snapshot[path])
            with self.subTest(path=path), self.assertRaises(g2.Denied):
                g2.verify(harness(snapshot)[0], "evidence", "admin", event(), env())
        for path in (b+"contents/.github/release-authorizations?ref="+SHA,
                     b+"git/ref/tags/"+g2.PROSPECTIVE_TAG,
                     b+"releases/tags/"+g2.PROSPECTIVE_TAG):
            snapshot = data(); snapshot[path] = {"unexpected": "not absent"}
            with self.subTest(path=path), self.assertRaises(g2.Denied):
                g2.verify(harness(snapshot)[0], "evidence", "admin", event(), env())

    def test_http_errors_timeout_race_cannot_pass(self):
        for path in (g2.BASE+"branches/main", g2.BASE+"pulls/29",
                     g2.BASE+"releases/tags/"+g2.PROSPECTIVE_TAG):
            with self.subTest(path=path), self.assertRaises(g2.Denied):
                g2.verify(harness(data(), fault=path)[0], "evidence", "admin", event(), env())
        with self.assertRaises(g2.Denied):
            g2.verify(harness(data(), race=True)[0], "evidence", "admin", event(), env())

    def test_no_write_api_in_new_verifier(self):
        source = (ROOT / "scripts/chat-pr-g2-live-negative.py").read_text()
        for forbidden in ("urlopen(", "Request(", "subprocess", "gh release ",
                          "workflow_dispatch:", "publishableReceipt=true",
                          "def publish("):
            self.assertNotIn(forbidden, source)

if __name__ == "__main__":
    main()
