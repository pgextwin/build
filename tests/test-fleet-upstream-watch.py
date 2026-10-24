#!/usr/bin/env python3
"""Offline hostile tests for scheduled 17-extension read-only detection."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from update_watch_lib import WatchError
spec = importlib.util.spec_from_file_location("fleet_watch", ROOT / "scripts/fleet-upstream-watch.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
sha = "a" * 40


def encoded(value):
    return {"encoding":"base64", "content":base64.b64encode(json.dumps(value).encode()).decode()}


def fixture(url):
    if url.endswith("/branches/main"):
        return {"protected":True, "commit":{"sha":sha}}
    if url.endswith("/contents/config/extension.json?ref=" + sha):
        return encoded({"name":"pgtap", "upstream":{"repository":"theory/pgtap",
                           "ref":"v1.3.4","version":"1.3.4","commit":"b"*40},
                        "postgresql":{"majors":[14,15,16,17,18]}})
    if url.endswith("/contents/config/update-watch.json?ref=" + sha):
        return encoded({"schemaVersion":1,"source":"github","repository":"theory/pgtap",
                        "strategy":"github-releases","prereleases":False,
                        "stableTagPattern":r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"})
    if url.endswith("/releases?per_page=100"):
        return [{"tag_name":"v1.3.4","draft":False,"prerelease":False}]
    raise WatchError("unmocked endpoint")


class ReadonlyFleet(TestCase):
    def test_real_central_policy_and_all_17_entries(self):
        policy=json.loads((ROOT / "metadata/automation-fleet.json").read_text())
        names=w.fleet.validate(policy)
        self.assertEqual(len(names),17)
        self.assertTrue(all("pgextwin/" in n and names[n]["mode"]=="BUILD" for n in names))

    def test_no_update_or_publication(self):
        row=w.snapshot("pgextwin/pgtap", {"mode":"BUILD","strategy":"github-releases"},fixture)
        self.assertEqual(row["mainSha"],sha)
        self.assertEqual(row["status"],"up-to-date")
        self.assertEqual(row["updates"],[])

    def test_failure_is_never_no_change_or_release_permission(self):
        def bad(url):
            if url.endswith("/branches/main"):
                return {"protected":False,"commit":{"sha":sha}}
            return fixture(url)
        with self.assertRaises(WatchError):
            w.snapshot("pgextwin/pgtap",{"mode":"BUILD","strategy":"github-releases"},bad)
        with self.assertRaises(WatchError):
            w.scan({"schemaVersion":1,"entries":[]},fixture)

    def test_main_moves_and_bad_config_denied(self):
        calls=[0]
        def moved(url):
            if url.endswith("/branches/main"):
                calls[0]+=1
                if calls[0]>1:
                    return {"protected":True,"commit":{"sha":"c"*40}}
            return fixture(url)
        with self.assertRaises(WatchError):
            w.snapshot("pgextwin/pgtap",{"mode":"BUILD","strategy":"github-releases"},moved)
        def invalid(url):
            if "config/extension.json" in url:
                return {"encoding":"utf-8","content":"{}"}
            return fixture(url)
        with self.assertRaises(WatchError):
            w.snapshot("pgextwin/pgtap",{"mode":"BUILD","strategy":"github-releases"},invalid)

    def test_transient_upstream_failure_bounded_recovery(self):
        error = WatchError("upstream query failed: HTTP Error 503: Service Unavailable")
        self.assertTrue(w.transient_upstream_error(error))
        self.assertEqual(w.safe_failure_code(error), "UPSTREAM_HTTP_503")
        self.assertTrue(w.transient_upstream_error(
            WatchError("upstream query failed: timed out")))
        self.assertFalse(w.transient_upstream_error(
            WatchError("upstream query failed: HTTP Error 403: Forbidden")))
        self.assertFalse(w.transient_upstream_error(
            WatchError("unprotected or unverifiable upstream manifest main")))
        self.assertEqual(w.safe_failure_code(
            WatchError("upstream response must be a JSON array")),
            "UPSTREAM_INVALID_RESPONSE")
        seen = [0]
        sleeps = []
        def once(url):
            if url.endswith("/releases?per_page=100"):
                seen[0] += 1
                if seen[0] == 1:
                    raise error
            return fixture(url)
        row = w.bounded_snapshot("pgextwin/pgtap",
                                 {"mode":"BUILD","strategy":"github-releases"},
                                 once, pause=lambda seconds: sleeps.append(seconds))
        self.assertEqual(row["status"], "up-to-date")
        self.assertEqual(seen, [2])
        self.assertEqual(sleeps, [2])

    def test_persistent_or_nontransient_error_denied_no_success(self):
        attempts = [0]
        def persistent(url):
            if url.endswith("/releases?per_page=100"):
                attempts[0] += 1
                raise WatchError("upstream query failed: HTTP Error 504: Gateway Timeout")
            return fixture(url)
        with self.assertRaises(WatchError):
            w.bounded_snapshot("pgextwin/pgtap",
                               {"mode":"BUILD","strategy":"github-releases"},
                               persistent, pause=lambda seconds: None)
        self.assertEqual(attempts, [2])
        self.assertEqual(w.safe_failure_code(
            WatchError("upstream query failed: HTTP Error 504: Gateway Timeout")),
            "UPSTREAM_HTTP_504")
        attempts[0] = 0
        def no_retry(url):
            if url.endswith("/releases?per_page=100"):
                attempts[0] += 1
                raise WatchError("upstream query failed: HTTP Error 403: Forbidden")
            return fixture(url)
        with self.assertRaises(WatchError):
            w.bounded_snapshot("pgextwin/pgtap",
                               {"mode":"BUILD","strategy":"github-releases"},
                               no_retry, pause=lambda seconds: None)
        self.assertEqual(attempts, [1])
        # Reject trust or source drift without retry: retries must never
        # turn a changed/unprotected manifest into a successful audit.
        self.assertEqual(w.safe_failure_code(WatchError(
            "protected extension main changed during audit")),
            "PROTECTED_MAIN_DRIFT")

    def test_protected_push_live_smoke_cannot_replace_genuine_schedule(self):
        workflow = (ROOT / ".github/workflows/fleet-upstream-watch.yml").read_text()
        self.assertIn('cron: "0 * * * *"', workflow)
        self.assertIn("  push:\n    branches: [main]\n    paths:\n", workflow)
        # Only the fleet scanner and its trusted sources may initiate this
        # extra read-only run. Extension manifest pushes and arbitrary PRs
        # must not generate another cross-repository 17-fleet scan.
        for path in (
            ".github/workflows/fleet-upstream-watch.yml",
            "scripts/fleet-upstream-watch.py",
            "scripts/update_watch_lib.py",
            "scripts/fleet-control.py",
            "metadata/automation-fleet.json",
        ):
            self.assertIn('      - "' + path + '"', workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("pull_request:\n", workflow)
        # A successful code-change push is never the authentic central
        # schedule proof needed before a local :30 candidate can start.
        verifier = (ROOT / "scripts/verify-scheduled-fleet-candidate.py").read_text()
        self.assertIn('run.get("event") == "schedule"', verifier)
        self.assertIn('run.get("run_attempt") == 1', verifier)
        self.assertIn('report.get("indeterminate") == 0', verifier)
        self.assertIn('report.get("publication") == "DENY"', verifier)

    def test_schedule_is_read_only_and_owner_gates_unchanged(self):
        y=(ROOT/".github/workflows/fleet-upstream-watch.yml").read_text()
        self.assertIn('cron: "0 * * * *"',y)
        self.assertIn("permissions:\n  contents: read",y)
        for forbidden in ("issues: write","contents: write","pull-requests: write",
                          "secrets.","gh pr create","gh release","pull_request_target:"):
            self.assertNotIn(forbidden,y)
        self.assertIn("if: always()",y)
        self.assertIn("GH_TOKEN: ${{ github.token }}",y)
        self.assertIn("candidatePrCreated", (ROOT/"scripts/fleet-upstream-watch.py").read_text())


if __name__=="__main__":
    main()
