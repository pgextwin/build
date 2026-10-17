#!/usr/bin/env python3
"""Issue #75: standalone GET-only GO B observer hostile offline tests.

Fixtures prove shape handling, never a live signed run, authentic GET, valid
Sigstore proof or publication authorization. Every transport is mocked.
"""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]

def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

o = load("scripts/issue-75-go-b-live-readonly.py", "issue75_getonly")
fixtures = load("tests/test-issue-75-main-publisher-guard.py", "issue75_existing_main_guards")
RUN = fixtures.RUN
SHA = fixtures.COMMIT
OLD = o.LEGACY_PIN

def workflow(pin=OLD, signer=o.SIGNER_PIN):
    src = (
        "name: promote\non:\n  workflow_dispatch:\n"
        "jobs:\n  authorize:\n    steps:\n      - uses: actions/checkout@full\n"
        "        with:\n"
        f"          ref: {pin}\n"
        "  release_build:\n"
        "    uses: "
        f"pgextwin/build/.github/workflows/build-extension-attested.yml@{signer}\n"
        "  publish:\n    permissions:\n      contents: write\n    steps:\n"
        "      - uses: actions/checkout@full\n        with:\n"
        f"          ref: {pin}\n")
    raw = src.encode()
    claimed_blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()
    return {"encoding": "base64", "sha": claimed_blob,
            "content": base64.b64encode(raw).decode(), "size": len(raw)}

def fake_state(pin=OLD):
    run, page = fixtures.evidence([14, 15, 16, 17, 18])
    # Existing shared Publisher fixture originates from pgextwin/pgaudit;
    # the GO B pilot observer deliberately permits only plpgsql_check.
    run["repository"]["full_name"] = o.REPO
    branch = {
        "name": "main", "protected": True, "commit": {"sha": SHA},
        "protection": {"required_status_checks": {"checks": [
            {"context": name, "app_id": 15368}
            for name in sorted(o.REQUIRED)]}}}
    checks = {"total_count": 8, "check_runs": [
        {"id": i+100, "name": name, "status": "completed",
         "conclusion": "success", "app": {"id": 15368}}
        for i, name in enumerate(sorted(o.REQUIRED))]}
    responses = {
        f"actions/runs/{RUN}": run,
        f"actions/runs/{RUN}/attempts/1/jobs?per_page=100": page,
        "branches/main": branch,
        f"commits/{SHA}/check-runs?per_page=100": checks,
        f"contents/.github/workflows/promote.yml?ref={SHA}": workflow(pin)}
    return responses

def reader(responses, calls, change=None):
    def get(path, *, run_id, attempt, sha):
        calls.append((path, run_id, attempt, sha))
        if change:
            change(responses, path, len(calls))
        if path not in responses:
            raise AssertionError("non-allowlisted test path: " + path)
        return copy.deepcopy(responses[path])
    return get

class GoBObserverOffline(TestCase):
    def test_synthetic_active_publisher_shape_never_grants_publication(self):
        state = fake_state()
        calls = []
        result = o.observe(reader(state, calls), run_id=RUN)
        self.assertEqual(result["observation"],
                         "LIVE_SIGNED_PUBLISHER_TOPOLOGY_METADATA_ONLY")
        self.assertEqual(result["decision"], "BLOCKED_GO_B")
        self.assertEqual(result["deployedPinState"], "LEGACY_UNACCEPTED")
        self.assertEqual((result["runId"], result["runAttempt"],
                          result["packagingSha"]), (RUN, 1, SHA))
        self.assertEqual(len(calls), 10)  # root + jobs/main/checks/workflow ×2
        self.assertEqual(len({path for path, _, _, _ in calls}), 5)
        for key in ("signedArtifactsVerified", "publishableReceipt",
                    "publicationAuthorized", "writerEnabled",
                    "retryAuthorized", "mutationAuthorized"):
            self.assertIs(result[key], False)
        for key in ("goB", "g4", "g5"):
            self.assertEqual(result[key], "NO_GO")

    def test_actual_unsigned_candidate_root_is_deny(self):
        # The real authenticated Run identity, but mocked transport (no network).
        # It is not a signed, main-only, active Publisher Run.
        state = fake_state()
        real_id = 39021934569
        actual_sha = "4899b5c1da8e2fb681381fff4fa2ab41882cb0bc"
        root = state.pop(f"actions/runs/{RUN}")
        jobs = state.pop(f"actions/runs/{RUN}/attempts/1/jobs?per_page=100")
        state.pop(f"commits/{SHA}/check-runs?per_page=100")
        state.pop(f"contents/.github/workflows/promote.yml?ref={SHA}")
        root.update(id=real_id,
                    head_branch="auto-candidate/29d1c1984a1b44a55107",
                    head_sha=actual_sha, status="completed", conclusion="success",
                    path=".github/workflows/windows.yml")
        state[f"actions/runs/{real_id}"] = root
        state[f"actions/runs/{real_id}/attempts/1/jobs?per_page=100"] = jobs
        state[f"commits/{actual_sha}/check-runs?per_page=100"] = fake_state()[
            f"commits/{SHA}/check-runs?per_page=100"]
        state[f"contents/.github/workflows/promote.yml?ref={actual_sha}"] = workflow()
        # Protected branch remains the real main SHA, not the unmerged candidate.
        calls = []
        with self.assertRaises(o.Deny):
            o.observe(reader(state, calls), run_id=real_id)
        self.assertEqual(calls[0][1], real_id)
        self.assertTrue(all(c[0].startswith(("actions/", "branches/",
                                             "commits/", "contents/"))
                            for c in calls))

    def test_other_repository_run_does_not_enter_pilot_positive_path(self):
        state = fake_state()
        state[f"actions/runs/{RUN}"]["repository"]["full_name"] = "pgextwin/pgaudit"
        with self.assertRaises(o.Deny):
            o.observe(reader(state, []), run_id=RUN)

    def test_signed_canary_failure_wrong_workflow_is_deny(self):
        state = fake_state()
        run = state[f"actions/runs/{RUN}"]
        run.update(path=".github/workflows/issue-75-pre-g4-signed-canary.yml",
                   status="completed", conclusion="failure")
        with self.assertRaises(o.Deny):
            o.observe(reader(state, []), run_id=RUN)

    def test_duplicate_missing_or_non_app15368_required_check_deny(self):
        for case in ("wrong app", "in progress", "skipped", "duplicate",
                     "missing", "wrong context", "pagination", "wrong branch SHA",
                     "unprotected", "wrong required App", "wrong required count"):
            state = fake_state()
            checks = state[f"commits/{SHA}/check-runs?per_page=100"]
            br = state["branches/main"]
            if case == "wrong app":
                checks["check_runs"][0]["app"]["id"] = 99
            elif case == "in progress":
                checks["check_runs"][0]["status"] = "in_progress"
            elif case == "skipped":
                checks["check_runs"][0]["conclusion"] = "skipped"
            elif case == "duplicate":
                checks["check_runs"].append(copy.deepcopy(checks["check_runs"][0]))
                checks["total_count"] += 1
            elif case == "missing":
                checks["check_runs"].pop(); checks["total_count"] -= 1
            elif case == "wrong context":
                checks["check_runs"][0]["name"] = "forged"
            elif case == "pagination":
                checks["total_count"] = 100
            elif case == "wrong branch SHA":
                br["commit"]["sha"] = "f" * 40
            elif case == "unprotected":
                br["protected"] = False
            elif case == "wrong required App":
                br["protection"]["required_status_checks"]["checks"][0]["app_id"] = 0
            else:
                br["protection"]["required_status_checks"]["checks"].pop()
            with self.subTest(case=case), self.assertRaises(o.Deny):
                o.observe(reader(state, []), run_id=RUN)

    def test_mutating_live_gets_and_stale_attempt_are_denied(self):
        state = fake_state()
        def race(responses, path, count):
            if count == 6:
                responses[f"actions/runs/{RUN}"]["run_attempt"] = 2
        with self.assertRaises(o.Deny):
            o.observe(reader(state, [], race), run_id=RUN)
        state = fake_state()
        jobs = state[f"actions/runs/{RUN}/attempts/1/jobs?per_page=100"]
        jobs["jobs"][2]["run_attempt"] = 2
        with self.assertRaises(o.Deny):
            o.observe(reader(state, []), run_id=RUN)

    def test_wrong_pins_or_missing_workflow_information_deny(self):
        for case in ("signer", "split publisher pins", "missing signer",
                     "missing writer declaration", "malformed base64"):
            state = fake_state()
            path = f"contents/.github/workflows/promote.yml?ref={SHA}"
            if case == "signer":
                state[path] = workflow(signer="0"*40)
            elif case == "split publisher pins":
                state[path] = workflow()
                raw = base64.b64decode(state[path]["content"]).decode()
                raw = raw.replace(OLD, "f"*40, 1)
                state[path]["content"] = base64.b64encode(raw.encode()).decode()
            elif case == "missing signer":
                state[path] = {"encoding": "base64", "sha": "a"*40, "content": ""}
            elif case == "missing writer declaration":
                raw = base64.b64decode(state[path]["content"]).decode()
                raw = raw.replace("contents: write", "contents: read")
                state[path]["content"] = base64.b64encode(raw.encode()).decode()
            else:
                state[path]["content"] = "%%notbase64%%"
            with self.subTest(case=case), self.assertRaises(o.Deny):
                o.observe(reader(state, []), run_id=RUN)

    def test_other_full_sha_publisher_pin_is_unapproved_even_if_synthetic_shape_valid(self):
        state = fake_state(pin="f"*40)
        result = o.observe(reader(state, []), run_id=RUN)
        self.assertEqual(result["deployedPinState"], "UNAPPROVED_PIN_CHANGE")
        self.assertFalse(result["publicationAuthorized"])
        self.assertEqual(result["goB"], "NO_GO")

    def test_url_allowlist_and_get_method_no_write_transport(self):
        valid = ("actions/runs/123", "actions/runs/123/attempts/1/jobs?per_page=100",
                 "branches/main", "commits/" + SHA + "/check-runs?per_page=100",
                 "contents/.github/workflows/promote.yml?ref=" + SHA)
        self.assertTrue(all(o.api_path_ok(p, 123, 1, SHA) for p in valid))
        for bad in ("releases", "git/refs", "actions/runs/123/rerun",
                    "actions/workflows/promote.yml/dispatches",
                    "branches/other", "actions/runs/124", "/api/private",
                    "contents/.github/workflows/promote.yml?ref=main"):
            with self.subTest(path=bad):
                self.assertFalse(o.api_path_ok(bad, 123, 1, SHA))
                with self.assertRaises(o.Deny):
                    o.get_json(bad, token="SENSITIVE_TOKEN_0", run_id=123,
                               attempt=1, sha=SHA,
                               opener=lambda *a, **k: self.fail("network called"))

        class Response:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, *_): return b'{"ok":true}'

        def opener(request, timeout):
            self.assertEqual(request.get_method(), "GET")
            self.assertTrue(request.full_url.startswith(
                "https://api.github.com/repos/pgextwin/plpgsql_check/"))
            self.assertEqual(timeout, 25)
            return Response()
        observed = o.get_json("actions/runs/123", token="SENSITIVE_TOKEN_0",
                              run_id=123, attempt=1, sha=SHA, opener=opener)
        self.assertEqual(observed, {"ok": True})

    def test_http_pagination_duplicate_json_and_sensitive_errors_deny(self):
        for case in ("http500", "pagination", "duplicate", "malformed", "size"):
            class Response:
                status = 500 if case == "http500" else 200
                headers = {"Link": '<https://api.github.com/>; rel="next"'} if case == "pagination" else {}
                def __enter__(self): return self
                def __exit__(self, *_): return False
                def read(self, *_):
                    if case == "duplicate": return b'{"a":1,"a":2}'
                    if case == "malformed": return b'not-json'
                    if case == "size": return b"x" * 2_000_001
                    return b'{"ok":true}'
            with self.subTest(case=case), self.assertRaises(o.Deny):
                o.get_json("actions/runs/123", token="SENSITIVE_TOKEN_0",
                           run_id=123, attempt=1, sha=SHA,
                           opener=lambda *a, **kw: Response())

    def test_missing_token_run_boolean_and_invalid_sha_fail_closed(self):
        with self.assertRaises(o.Deny):
            o.get_json("actions/runs/1", token="", run_id=1,
                       attempt=1, sha=SHA)
        for v in (0, -1, False, "123", None):
            with self.subTest(value=v), self.assertRaises(o.Deny):
                o.observe(reader(fake_state(), []), run_id=v)
        with self.assertRaises(o.Deny):
            o.get_json("actions/runs/1", token="t", run_id=1,
                       attempt=1, sha="short")

    def test_recovery_schema_v1_remains_unknown_and_no_resume(self):
        rec = load("scripts/release-recovery-evidence.py", "issue75_recovery_v2")
        result = rec.classify_recovery_evidence(
            {"schemaVersion": 1, "state": "DRAFT_STAGED",
             "tag": "v2.10.15-windows.1", "runId": 39021934569,
             "commit": SHA}, [{}, {}])
        self.assertEqual(result["classification"], "UNKNOWN_QUARANTINE")
        self.assertFalse(result["mutationAuthorized"])
        self.assertFalse(result["retryAuthorized"])
        self.assertFalse(result["publicationAuthorized"])

    def test_cli_never_accepts_unsigned_run_as_release_intent(self):
        state = fake_state()
        state[f"actions/runs/{RUN}"]["status"] = "completed"
        state[f"actions/runs/{RUN}"]["conclusion"] = "success"
        with mock.patch.dict(o.os.environ, {"GH_TOKEN": "SENSITIVE_TOKEN_0"}):
            with mock.patch.object(o, "get_json",
                                   side_effect=lambda path, **k:
                                   copy.deepcopy(state[path])):
                with mock.patch("sys.stdout") as output:
                    code = o.main(["--run-id", str(RUN)])
        self.assertEqual(code, 2)
        dumped = "".join(str(c) for c in output.write.call_args_list)
        self.assertNotIn("SENSITIVE_TOKEN_0", dumped)
        self.assertIn("BLOCKED_GO_B", dumped)

if __name__ == "__main__":
    main()
