#!/usr/bin/env python3
"""Fail-closed original-bot candidate base-sync repair tests (offline)."""
import copy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("candidate_update", ROOT / "scripts/candidate-update.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

REPO = "pgextwin/hypopg"
MAIN_SHA, ORIGINAL, HUMAN, NEW = ("a"*40, "b"*40, "c"*40, "d"*40)
BLOB = "e"*40
SHARED_SHA = "1"*40
BRANCH = "auto-candidate/5860b6258e7d21085f38"
MARKER = "<!-- pgextwin-candidate:v1:5860b6258e7d21085f38 -->"
PATH = "config/extension.json"
PROPOSAL = {"schemaVersion": 1, "name": "hypopg", "upstream": {
    "repository": "HypoPG/hypopg", "ref": "1.4.4", "version": "1.4.4",
    "commit": "4e564ebbd46e1ab365ad0d05ca4a2f19cf316ba7"}}
RECORD = {"candidateId": "5860b6258e7d21085f38", "branch": BRANCH}
ENV = {"GITHUB_EVENT_NAME": "schedule", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": REPO,
       "GITHUB_SHA": MAIN_SHA, "GH_TOKEN": "fixture-token"}
LIST = [{"number": 41, "body": MARKER, "state": "OPEN", "isDraft": True,
         "headRefOid": HUMAN, "headRefName": BRANCH, "baseRefName": "main"}]
PR = {"number": 41, "state": "open", "draft": True, "merged": False,
      "body": MARKER, "user": {"login": "github-actions[bot]", "type": "Bot"},
      "head": {"sha": HUMAN, "ref": BRANCH, "repo": {"full_name": REPO}},
      "base": {"sha": MAIN_SHA, "ref": "main", "repo": {"full_name": REPO}}}
RUN = {"id": 40250481553, "event": "pull_request", "head_sha": HUMAN,
       "head_branch": BRANCH, "path": ".github/workflows/windows.yml",
       "status": "completed", "conclusion": "success", "run_attempt": 1,
       "repository": {"full_name": REPO}}


class BotRepairTests(TestCase):
    def run_case(self, *, change=None, good=False, advanced=False, race_main=False):
        env, listing, pr, run = copy.deepcopy(ENV), copy.deepcopy(LIST), copy.deepcopy(PR), copy.deepcopy(RUN)
        responses = {
            ("gh", "api", "repos/" + REPO + "/branches/main"):
                json.dumps({"protected": True, "commit": {"sha": MAIN_SHA}}),
            ("gh", "pr", "list", "--repo", REPO, "--head", BRANCH,
             "--state", "all", "--limit", "100", "--json",
             "number,body,state,headRefOid,headRefName,baseRefName,isDraft"): json.dumps(listing),
            ("gh", "api", "repos/" + REPO + "/pulls/41"): json.dumps(pr),
            ("gh", "api", "repos/" + REPO +
             "/actions/runs?event=pull_request&head_sha=" + HUMAN +
             "&per_page=100"): json.dumps({"workflow_runs": [run]}),
            ("git", "rev-parse", "refs/remotes/origin/" + BRANCH): HUMAN,
            ("git", "rev-list", "--parents", "-n", "1", HUMAN):
                HUMAN + " " + ORIGINAL + " " + MAIN_SHA,
            ("git", "merge-base", "--is-ancestor", MAIN_SHA, MAIN_SHA): "",
            ("git", "log", "-1", "--format=%an", ORIGINAL): "github-actions[bot]",
            ("git", "log", "-1", "--format=%ae", ORIGINAL):
                "41898282+github-actions[bot]@users.noreply.github.com",
            ("git", "log", "-1", "--format=%B", ORIGINAL): "original bot\n" + MARKER,
            ("git", "diff", "--name-only", MAIN_SHA, HUMAN): PATH,
            ("git", "rev-parse", ORIGINAL + ":" + PATH): BLOB,
            ("git", "rev-parse", HUMAN + ":" + PATH): BLOB,
            ("git", "rev-parse", MAIN_SHA + ":" + PATH): "f"*40,
            ("git", "rev-parse", NEW + ":" + PATH): BLOB,
            ("git", "show", HUMAN + ":" + PATH): json.dumps(PROPOSAL),
            ("git", "show", NEW + ":" + PATH): json.dumps(PROPOSAL),
            ("git", "diff", "--name-only", MAIN_SHA, NEW): PATH,
        }
        if advanced:
            previous = "9"*40
            responses[("git", "rev-list", "--parents", "-n", "1", HUMAN)] = (
                HUMAN + " " + ORIGINAL + " " + previous)
            responses[("git", "merge-base", "--is-ancestor", previous, MAIN_SHA)] = ""
            responses[("git", "diff", "--name-only", previous, HUMAN)] = PATH
            responses[("git", "rev-parse", previous + ":" + PATH)] = "f"*40
            responses[("git", "diff", "--name-only", previous, MAIN_SHA)] = (
                ".github/workflows/update-watch.yml")
        if change:
            change(env, listing, pr, run, responses)
            responses[("gh", "pr", "list", "--repo", REPO, "--head", BRANCH,
                       "--state", "all", "--limit", "100", "--json",
                       "number,body,state,headRefOid,headRefName,baseRefName,isDraft")] = json.dumps(listing)
            responses[("gh", "api", "repos/" + REPO + "/pulls/41")] = json.dumps(pr)
            responses[("gh", "api", "repos/" + REPO +
                       "/actions/runs?event=pull_request&head_sha=" + HUMAN +
                       "&per_page=100")] = json.dumps({"workflow_runs": [run]})
        calls = []
        def execute(*args):
            calls.append(args)
            source_main = ("gh", "api", "repos/" + REPO + "/branches/main")
            if race_main and args == source_main and calls.count(source_main) > 1:
                return json.dumps({"protected": True, "commit": {"sha": "0"*40}})
            if args == ("git", "rev-parse", "HEAD"):
                return NEW if any(x[:2] in {("git", "commit"), ("git", "merge")} for x in calls) else MAIN_SHA
            if args in responses:
                return responses[args]
            if args[:3] == ("git", "merge-base", "--is-ancestor"):
                raise c.WatchError("protected main is not a descendant of candidate base")
            if args[0] == "git" and args[1] in {"checkout", "config", "commit", "merge", "push"}:
                return ""
            raise AssertionError("unexpected command " + repr(args))
        with patch.dict(os.environ, env, clear=True), patch.object(c, "execute", execute):
            task = lambda: c.repair_exact_bot_candidate_base_sync(
                RECORD, REPO, PATH, PROPOSAL, MARKER, BRANCH)
            if good:
                task()
                self.assertEqual(sum(x[:2] in {("git", "commit"), ("git", "merge")}
                                     for x in calls), 1)
                self.assertEqual(sum(x[:2] == ("git", "push") for x in calls), 1)
                self.assertFalse(any(x[:3] == ("gh", "workflow", "run") for x in calls))
                self.assertFalse(any("force" in " ".join(x) for x in calls))
            else:
                with self.assertRaises((c.WatchError, ValueError, KeyError, TypeError)):
                    task()
                self.assertFalse(any(x[:2] in {("git", "commit"), ("git", "merge")}
                                     for x in calls))
                self.assertFalse(any(x[:2] == ("git", "push") for x in calls))

    def test_exact_bot_origin_human_sync_can_only_be_repaired_by_real_bot_commit(self):
        self.run_case(good=True)

    def test_advanced_protected_main_reconciles_forward_only(self):
        self.run_case(good=True, advanced=True)

    def test_rest_pr_can_retain_previous_base_after_protected_main_advance(self):
        # Actual HypoPG #41 GET: base.sha=dccc3bb... still records the second
        # parent of the human sync, while protected main advanced to906674d...
        # for a shared caller-pin repair. Both immutable ancestry and unchanged
        # source-manifest checks remain necessary before a forward bot merge.
        self.run_case(good=True, advanced=True,
                      change=lambda e,l,p,r,d: p["base"].update(sha="9"*40))

    def test_advanced_main_manifest_change_fails_closed(self):
        self.run_case(advanced=True, change=lambda e,l,p,r,d: d.update({
            ("git", "rev-parse", "9"*40 + ":" + PATH): "0"*40}))

    def test_main_race_fails_before_bot_write(self):
        self.run_case(advanced=True, race_main=True)

    def test_retained_base_does_not_waive_main_ancestry_or_manifest(self):
        def nonancestor(e,l,p,r,d):
            p["base"]["sha"] = "9"*40
            del d[("git", "merge-base", "--is-ancestor", "9"*40, MAIN_SHA)]
        self.run_case(advanced=True, change=nonancestor)
        def changed_manifest(e,l,p,r,d):
            p["base"]["sha"] = "9"*40
            d[("git", "rev-parse", "9"*40 + ":" + PATH)] = "0"*40
        self.run_case(advanced=True, change=changed_manifest)
        self.run_case(advanced=True,
                      change=lambda e,l,p,r,d: p["base"].update(sha=ORIGINAL))

    def cutover(self, *, corrupt=None):
        def change(e,l,p,r,d):
            previous = "9"*40
            p["base"]["sha"] = previous
            d[("git", "diff", "--name-only", previous, MAIN_SHA)] = (
                ".github/workflows/update-watch.yml\nconfig/release-promotion.json")
            d[("git", "show", previous + ":config/release-promotion.json")] = json.dumps({
                "schemaVersion": 1, "enabled": True, "releasePolicy": "manual-dispatch"})
            d[("git", "show", MAIN_SHA + ":config/release-promotion.json")] = json.dumps({
                "schemaVersion": 1, "enabled": True,
                "releasePolicy": "automatic-signed-schedule"})
            d[("git", "-C", str(ROOT), "rev-parse", "HEAD")] = SHARED_SHA
            d[("git", "show", MAIN_SHA + ":.github/workflows/update-watch.yml")] = (
                "    uses: pgextwin/build/.github/workflows/candidate-update.yml@" + SHARED_SHA)
            d[("gh", "api", "--method", "GET", "repos/pgextwin/build/branches/main")] = json.dumps({
                "protected": True, "commit": {"sha": SHARED_SHA},
                "protection": {"required_status_checks": {
                    "checks": [{"context": "resolver", "app_id": 15368}]}}})
            names = ("automation-fleet.json", "release-promotion.json",
                     "unattended-publication.json", "publisher-write-boundary.json")
            objects = [json.loads((ROOT / "metadata" / n).read_text()) for n in names]
            objects[0]["releasePolicy"] = "automatic-signed-schedule"
            for row in objects[0]["entries"]:
                row["releasePolicy"] = "automatic-signed-schedule"
            objects[1]["releasePolicy"] = "automatic-signed-schedule"
            objects[2]["mode"] = "UNATTENDED"
            objects[2]["controls"] = {key: True for key in objects[2]["controls"]}
            objects[3].update(mode="ENFORCE", publisherAppId=5451798,
                              publisherInstallationId=174720074)
            for name, value in zip(names, objects):
                path = "metadata/" + name
                raw = (json.dumps(value, indent=2) + "\n").encode()
                sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                d[("gh", "api", "--method", "GET",
                   "repos/pgextwin/build/contents/" + path + "?ref=" + SHARED_SHA)] = json.dumps({
                       "path": path, "encoding": "base64", "sha": sha,
                       "size": len(raw), "content": base64.encodebytes(raw).decode()})
            if corrupt:
                corrupt(e,l,p,r,d)
        return change

    def test_exact_cutover_requires_complete_live_protected_automatic_bundle(self):
        self.run_case(good=True, advanced=True, change=self.cutover())

    def test_partial_or_substituted_cutover_fails_before_bot_write(self):
        central = ("gh", "api", "--method", "GET", "repos/pgextwin/build/branches/main")
        metadata = ("gh", "api", "--method", "GET",
                    "repos/pgextwin/build/contents/metadata/unattended-publication.json?ref=" + SHARED_SHA)
        def partial_policy(e,l,p,r,d):
            response = json.loads(d[metadata])
            value = json.loads(base64.b64decode(response["content"]))
            value["controls"]["automaticFormalRelease"] = False
            raw = (json.dumps(value) + "\n").encode()
            response.update(size=len(raw), content=base64.encodebytes(raw).decode(),
                            sha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
            d[metadata] = json.dumps(response)
        cases = [
            partial_policy,
            lambda e,l,p,r,d: d.update({("git", "diff", "--name-only", "9"*40, MAIN_SHA):
                ".github/workflows/update-watch.yml\nconfig/release-promotion.json\nwindows/ci/build.ps1"}),
            lambda e,l,p,r,d: d.update({("git", "show", MAIN_SHA + ":config/release-promotion.json"):
                json.dumps({"schemaVersion": 1, "enabled": False,
                            "releasePolicy": "automatic-signed-schedule"})}),
            lambda e,l,p,r,d: d.update({("git", "show", MAIN_SHA + ":.github/workflows/update-watch.yml"):
                "    uses: pgextwin/build/.github/workflows/candidate-update.yml@" + "2"*40}),
            lambda e,l,p,r,d: d.update({central: json.dumps({"protected": False,
                "commit": {"sha": SHARED_SHA}})}),
            lambda e,l,p,r,d: d.update({central: json.dumps({"protected": True,
                "commit": {"sha": "2"*40}})}),
            lambda e,l,p,r,d: d.update({central: json.dumps({"protected": True,
                "commit": {"sha": SHARED_SHA}, "protection": {"required_status_checks": {
                    "checks": [{"context": "resolver", "app_id": 42}]}}})}),
            lambda e,l,p,r,d: d.update({metadata: json.dumps({"path": "metadata/unattended-publication.json",
                "encoding": "base64", "sha": "0"*40, "content": "e30="})}),
        ]
        for i, corrupt in enumerate(cases):
            with self.subTest(case=i):
                self.run_case(advanced=True, change=self.cutover(corrupt=corrupt))

    def test_all_provenance_mismatches_fail_before_any_write(self):
        cases = [
            lambda e,l,p,r,d: e.update(GITHUB_EVENT_NAME="workflow_dispatch"),
            lambda e,l,p,r,d: e.update(GITHUB_RUN_ATTEMPT="2"),
            lambda e,l,p,r,d: e.update(GITHUB_SHA="f"*40),
            lambda e,l,p,r,d: p["user"].update(login="human"),
            lambda e,l,p,r,d: p.update(draft=False),
            lambda e,l,p,r,d: p["base"].update(sha="f"*40),
            lambda e,l,p,r,d: l[0].update(headRefOid="f"*40),
            lambda e,l,p,r,d: d.update({("git", "rev-list", "--parents", "-n", "1", HUMAN):
                                           HUMAN + " " + ORIGINAL + " " + "f"*40}),
            lambda e,l,p,r,d: d.update({("git", "log", "-1", "--format=%an", ORIGINAL): "human"}),
            lambda e,l,p,r,d: d.update({("git", "log", "-1", "--format=%B", ORIGINAL): "no marker"}),
            lambda e,l,p,r,d: d.update({("git", "diff", "--name-only", MAIN_SHA, HUMAN):
                                           PATH + "\n.github/workflows/windows.yml"}),
            lambda e,l,p,r,d: d.update({("git", "rev-parse", HUMAN + ":" + PATH): "f"*40}),
            lambda e,l,p,r,d: d.update({("git", "show", HUMAN + ":" + PATH): '{"upstream":"forged"}'}),
            lambda e,l,p,r,d: r.update(event="workflow_dispatch"),
            lambda e,l,p,r,d: r.update(conclusion="failure"),
            lambda e,l,p,r,d: r.update(run_attempt=2),
        ]
        for i, modify in enumerate(cases):
            with self.subTest(case=i):
                self.run_case(change=modify)


if __name__ == "__main__":
    main()
