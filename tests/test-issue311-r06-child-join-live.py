#!/usr/bin/env python3
"""Offline hostile-boundary tests. No claim of genuine Run or live App CAS."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("r06_live", ROOT / "scripts/issue311-r06-child-join-live.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def historical_targets():
    raw = (ROOT / "tests/fixtures/issue311-r05-fleet-69918265.json").read_bytes()
    assert mod.store.blob_hash(raw) == mod.FLEET_BLOB
    return sorted(x["repository"] for x in json.loads(raw)["entries"])


def declaration():
    return {"schemaVersion": 1, "kind": "pgextwin-r06-original-child-join",
        "requestId": "r-20261030-r06join17test01", "mode": "AUDIT_ONLY", "requestedBy": "ShutenOishi",
        "createdAt": "2026-10-29T22:00:00Z", "expiresAt": "2026-10-29T22:20:00Z",
        "central": {"requestId": "r-20261029-r06prepare17test07", "runId": 100, "headSha": "a"*40,
                    "artifactId": 101, "zipSha256": "b"*64},
        "children": [{"repo": r, "runId": i+200, "requestId": "r-20261030-r06local" + str(i) + "test07"}
                     for i, r in enumerate(historical_targets())],
        "missingCompletionRepo": "pgextwin/orafce", "publicReleaseAuthorized": False,
        "stateWriteScope": "BUILD_ONLY_REQUEST_LIFECYCLE"}


class BoundaryTests(unittest.TestCase):
    def test_original_step_name_must_match_immutable_command_pin_and_actual_success(self):
        def job(name, conclusion="success"):
            return {"steps": [{"name": name, "status": "completed", "conclusion": conclusion}]}
        def workflow(name):
            return ("          ref: ff551bd2ea20da869e644691090b5ee7c82553ba\n"
                    "          path: .pgextwin-build\n      - name: " + name + "\n"
                    "        env:\n          GH_TOKEN: ${{ github.token }}\n"
                    "        run: python .pgextwin-build/scripts/issue311-r06-fleet-local-prepare.py run\n")
        with patch.object(mod, "targets", return_value=set(historical_targets())):
            for repo, name in [("pgextwin/orafce", mod.SHARED_VERIFY_STEP),
                               ("pgextwin/pg_ivm", mod.SHARED_VERIFY_STEP),
                               ("pgextwin/pg_repack", mod.VERIFY_STEP),
                               ("pgextwin/pg_bigm", mod.VERIFY_STEP)]:
                mod.original_verification_step(repo, job(name), workflow(name))
            original = workflow(mod.VERIFY_STEP)
            cases = [(job(mod.SHARED_VERIFY_STEP), original),
                     (job(mod.VERIFY_STEP, "failure"), original),
                     (job(mod.VERIFY_STEP), original.replace("ff551bd2", "00000000")),
                     (job(mod.VERIFY_STEP), original.replace(".py run", ".py fake")),
                     (job(mod.VERIFY_STEP), original.replace("GH_TOKEN:", "OTHER_TOKEN:"))]
            for record, text in cases:
                with self.assertRaises(ValueError):
                    mod.original_verification_step("pgextwin/pg_repack", record, text)
        with self.assertRaisesRegex(ValueError, "trusted registry drift"):
            mod.targets()

    def test_authentic_central_scan_flag_is_not_the_app_state_flag(self):
        self.assertTrue(mod.central_scope({"publicationAuthorized": False}))
        self.assertFalse(mod.central_scope({"publisherAuthorized": False}))
        self.assertFalse(mod.central_scope({"publicationAuthorized": True}))
        self.assertFalse(mod.central_scope({"publicationAuthorized": False, "publisherAuthorized": False}))

    def validate(self, request):
        path = ".github/execution-requests/" + request["requestId"] + ".json"
        with patch.object(mod, "targets", return_value=set(historical_targets())):
            return mod.validate_request(json.dumps(request).encode(), path,
                now=datetime(2026, 10, 29, 22, 1, tzinfo=timezone.utc))

    def test_exact_scope_is_inert_and_rejects_privileged_or_incomplete(self):
        good = declaration()
        self.assertEqual(self.validate(good), good)
        mutations = [lambda r: r.update(publicReleaseAuthorized=True),
                     lambda r: r.update(mode="PUBLISH_ELIGIBLE"),
                     lambda r: r.update(stateWriteScope="PUBLISHER"),
                     lambda r: r.update(command="dispatch"),
                     lambda r: r.update(missingCompletionRepo="pgextwin/pg_bigm"),
                     lambda r: r["children"].pop(),
                     lambda r: r["children"].__setitem__(0, copy.deepcopy(r["children"][1])),
                     lambda r: r["children"][0].update(runId=True),
                     lambda r: r["children"][0].update(requireWindowsPostmerge="true"),
                     lambda r: r["central"].update(runId=True),
                     lambda r: r["central"].update(zipSha256="f"*40),
                     lambda r: r.update(expiresAt="2026-10-29T23:00:00Z"),
                     lambda r: r.update(expiresAt="2026-10-29T22:00:30Z")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad = copy.deepcopy(good)
                mutate(bad)
                with self.assertRaises(ValueError):
                    self.validate(bad)

    def test_zip_rehash_entry_and_duplicate_json_fail_before_any_writer(self):
        def zipped(entries):
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                for name, raw in entries:
                    z.writestr(name, raw)
            return out.getvalue()
        raw = zipped([("original.json", '{"publicationAuthorized":false}')])
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(mod.single_zip(raw, digest, "original.json"), {"publicationAuthorized": False})
        for altered, claimed, name in [
            (raw, "f"*64, "original.json"),
            (raw, digest, "else.json"),
            (raw[:-1]+bytes([raw[-1]^1]), digest, "original.json"),
        ]:
            with self.assertRaises(ValueError):
                mod.single_zip(altered, claimed, name)
        for entries in [[("original.json", "{}"), ("extra.json", "{}")],
                        [("original.json", '{"scope":0,"scope":1}')]]:
            altered = zipped(entries)
            with self.assertRaises(ValueError):
                mod.single_zip(altered, hashlib.sha256(altered).hexdigest(), "original.json")

    def test_cross_cycle_expired_skipped_declaration_denied_before_cas(self):
        central = {"requestId": "r-20261029-r06prepare17test07", "sourceRunId": 100,
            "sourceHeadSha": "a"*40, "sourceArtifactId": 101, "sourceZipSha256": "b"*64,
            "created_at": "2026-10-29T21:00:00Z", "targetMainSha": {"pgextwin/pg_cron": "c"*40}}
        c = {"repo": "pgextwin/pg_cron", "parentSha": "c"*40,
             "run": {"created_at": "2026-10-29T21:10:00Z"},
             "request": {"schemaVersion": 1, "kind": "pgextwin-local-prepare", "mode": "PREPARE",
                 "requestId": "r-20261030-r06localcrontest07", "centralRequestId": central["requestId"],
                 "sourceRunId": 100, "sourceHeadSha": "a"*40, "sourceArtifactId": 101,
                 "sourceZipSha256": "b"*64, "targetMainSha": "c"*40,
                 "expiresAt": "2026-10-29T21:20:00Z", "publicReleaseAuthorized": False}}
        self.assertIs(mod.preflight_child(central, c), c)
        for field, value in [("sourceRunId", 999), ("centralRequestId", "cross-cycle"),
                             ("sourceZipSha256", "d"*64), ("publicReleaseAuthorized", True),
                             ("expiresAt", "2026-10-29T21:09:59Z")]:
            bad = copy.deepcopy(c)
            bad["request"][field] = value
            with self.assertRaises(ValueError):
                mod.preflight_child(central, bad)

    def test_actual_terminal_preserves_normal_and_quarantines_anomalies_without_replay(self):
        hist = historical_targets()
        with patch.object(mod, "targets", return_value=set(hist)):
            children = [{"repo": r, "receipt": {"result": "NO_UPDATE"}} for r in hist]
            initial = mod.life.new("r-20261030-r06join17test01", "d"*64, "a"*40,
                hist, "2026-10-29T21:20:00Z")
            bound = mod.life.bind_source(initial, 0, "source", run_id=500, attempt=1, head_sha="a"*40)
            with self.assertRaises(ValueError):
                mod.bounded_terminal(bound, children, 500, 501, "e"*64, now="2026-10-29T21:19:59Z")
            terminal = mod.bounded_terminal(bound, children, 500, 501, "e"*64, now="2026-10-29T21:21:00Z")
            self.assertEqual(terminal["eventTransport"], "BOUNDED_WATCHDOG")
            self.assertEqual(list(terminal["targets"].values()).count("NO_UPDATE"), 13)
            self.assertEqual(list(terminal["targets"].values()).count("QUARANTINED"), 4)
            mod.store.require_transition(bound, terminal)
            with self.assertRaises(ValueError):
                mod.life._apply(terminal, 2, "second-event", {"op": "replay"}, lambda s: s.update(terminal=None))
            changed = copy.deepcopy(children)
            normal = next(x for x in changed if x["repo"] not in mod.ANOMALIES)
            normal["receipt"]["result"] = "UPDATE_PRESENT_NOT_AUTHORIZED"
            quarantine = mod.bounded_terminal(bound, changed, 500, 501, "e"*64, now="2026-10-29T21:21:00Z")
            self.assertEqual(quarantine["targets"][normal["repo"]], "QUARANTINED")

    def test_cross_host_artifact_redirect_drops_authorization(self):
        original = urllib.request.Request("https://api.github.com/repos/pgextwin/build/actions/artifacts/1/zip",
                                          headers={"Authorization": "Bearer DO_NOT_FORWARD"})
        after = mod.SafeRedirect().redirect_request(original, None, 302, "Found", {},
                                                    "https://artifacts.example.com/original.zip")
        self.assertIsNone(after.get_header("Authorization"))
        with self.assertRaises(ValueError):
            mod.SafeRedirect().redirect_request(original, None, 302, "Found", {}, "http://example.com/unsafe")


class WindowsEvidenceTests(unittest.TestCase):
    repo = "pgextwin/pg_hint_plan"
    head = "a" * 40
    tip = "b" * 40
    checkout = "c" * 40
    tree = "d" * 40
    build = "e" * 40
    parent = "f" * 40
    number = 99

    def setUp(self):
        repository = {"full_name": self.repo}
        self.protected = {"number": self.number, "headSha": self.tip, "mergedSha": self.head}
        self.pr = {"number": self.number, "merged": True, "merge_commit_sha": self.head,
                   "merged_at": "2026-10-30T02:00:00Z",
                   "head": {"sha": self.tip, "ref": "change", "repo": repository.copy()},
                   "base": {"ref": "main", "repo": repository.copy()}}
        self.push = {"id": 30, "run_attempt": 1, "repository": repository, "head_branch": "main",
                     "head_sha": self.head, "path": mod.WINDOWS_PATH, "event": "push",
                     "status": "completed", "conclusion": "success", "actor": {"login": "ShutenOishi"},
                     "workflow_id": 10, "referenced_workflows": [{"path": mod.reuse.WORKFLOW_PATH + "@windows-ci",
                                                                 "sha": self.build}]}
        self.run = dict(copy.deepcopy(self.push), id=20, event="pull_request", head_sha=self.tip,
                        head_branch="change", head_repository=repository, created_at="2026-10-30T01:00:00Z")
        names = ["windows / " + mod.reuse.MATRIX_JOB_NAME, *mod.WINDOWS_REQUIRED]
        self.jobs = {
            run_id: [{"id": run_id * 10 + i, "run_id": run_id, "name": name, "status": "completed",
                      "conclusion": "success", "steps": [{"name": "Record resolved Windows CI inputs",
                                                         "status": "completed", "conclusion": "success"}]}
                     for i, name in enumerate(names)] for run_id in (20, 30)
        }
        self.records = {
            run_id: dict.fromkeys(mod.reuse.ENV_FIELDS, "input") |
            {"schemaVersion": 1, "repository": self.repo, "checkout_tree": self.tree,
             "checkout_commit": sha, "pr_head_sha": pr_head, "build_sha": self.build,
             "matrix": {"include": [{"upstreamCommit": self.parent}]}}
            for run_id, sha, pr_head in ((20, self.checkout, self.tip), (30, self.head, ""))
        }
        self.commits = {
            sha: {"sha": sha, "commit": {"tree": {"sha": self.tree}},
                  "parents": [{"sha": self.parent}, {"sha": self.tip}]}
            for sha in (self.checkout, self.head)
        }
        self.checkout_log = f"[command]/usr/bin/git checkout --progress --force refs/remotes/pull/{self.number}/merge\n"

    def evidence(self, *, require_push=False):
        responses = {
            f"actions/runs?head_sha={self.head}&event=push&per_page=100":
                {"total_count": 1, "workflow_runs": [self.push]},
            f"pulls/{self.protected['number']}": self.pr,
            f"actions/workflows/windows.yml/runs?event=pull_request&head_sha={self.tip}&per_page=100":
                {"total_count": 1, "workflow_runs": [self.run]},
            "actions/runs/20": self.run, "actions/runs/30": self.push,
            **{f"commits/{sha}": commit for sha, commit in self.commits.items()},
            **{f"actions/runs/{run_id}/attempts/1/jobs?per_page=100": {"total_count": len(items), "jobs": items}
               for run_id, items in self.jobs.items()},
        }
        logs = {
            f"actions/jobs/{run_id * 10}/logs":
                ((self.checkout_log if run_id == 20 else "") +
                 mod.reuse.RECORD_PREFIX + json.dumps(record)).encode()
            for run_id, record in self.records.items()
        }
        with (patch.object(mod, "get", side_effect=lambda repo, path: responses[path]) as get,
              patch.object(mod, "get_bytes", side_effect=lambda repo, path: logs[path])):
            self.get = get
            return mod.windows_evidence(self.repo, self.head, self.protected, require_push=require_push)

    def test_pr_evidence_uses_real_checkout_and_fixed_inputs_when_push_has_no_windows_build(self):
        self.jobs[30] = self.jobs[30][:1]
        result = self.evidence()
        self.assertEqual(result["windowsPrRunId"], 20)
        self.assertNotIn("windowsPostmergeRunId", result)
        proof = result["windowsEvidence"]
        self.assertEqual(proof["checkoutSha"], self.checkout)
        self.assertEqual(proof["mainSha"], self.head)
        self.assertEqual(proof["checkoutTree"], self.tree)
        self.assertEqual(proof["mainTree"], self.tree)
        self.assertEqual(proof["buildSha"], self.build)
        self.assertEqual(proof["mainInputsRunId"], 30)
        self.assertEqual(proof["runAttempt"], 1)
        self.assertEqual(proof["prNumber"], self.number)
        self.assertEqual([row["name"] for row in proof["requiredJobs"]], mod.WINDOWS_REQUIRED)

    def test_pr_evidence_failures_fall_back_to_original_push(self):
        cases = {
            "tree mismatch": lambda: self.commits[self.checkout]["commit"]["tree"].update(sha=self.parent),
            "inputs mismatch": lambda: self.records[20].update(license_files="other licence"),
            "workflow mismatch": lambda: self.run["referenced_workflows"][0].update(sha=self.parent),
            "job failure": lambda: self.jobs[20][1].update(conclusion="failure"),
            "summary failure": lambda: self.jobs[20][-1].update(conclusion="failure"),
            "missing log": lambda: self.records.pop(20),
            "wrong PR merge ref": lambda: setattr(self, "checkout_log", self.checkout_log.replace("/99/", "/98/")),
            "fork PR": lambda: self.pr["head"]["repo"].update(full_name="other/fork"),
            "rerun": lambda: self.run.update(run_attempt=2),
        }
        for reason, invalidate in cases.items():
            with self.subTest(reason=reason):
                self.setUp()
                invalidate()
                result = self.evidence()
                self.assertEqual(result["windowsPostmergeRunId"], 30)
                self.assertEqual(result["windowsEvidence"]["kind"], "push")

    def test_missing_pr_proof_with_skipped_push_denies(self):
        self.records.pop(20)
        self.jobs[30][1]["conclusion"] = "skipped"
        with self.assertRaisesRegex(ValueError, "required job failed"):
            self.evidence()

    def test_explicit_and_pg17_recovery_cases_require_original_push(self):
        self.assertEqual(self.evidence(require_push=True)["windowsPostmergeRunId"], 30)
        self.assertFalse(any(call.args[1].startswith("pulls/") for call in self.get.call_args_list))
        self.protected["number"] = 60
        self.assertEqual(self.evidence()["windowsPostmergeRunId"], 30)
        self.assertFalse(any(call.args[1].startswith("pulls/") for call in self.get.call_args_list))


if __name__ == "__main__":
    unittest.main()
