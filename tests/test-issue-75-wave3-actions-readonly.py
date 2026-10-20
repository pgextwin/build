"""Wave-three Actions-only main push witness is strictly GET-only and DENY-only.

Synthetic fixtures cannot establish an actual independent Signer, Writer,
effective branch rules, or a publishable authorization.
"""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import unittest
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("issue75_wave3_readonly", ROOT / "scripts/issue-75-wave3-actions-readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BASE = "a" * 40
HEADS = {"pgextwin/pgtap": "b" * 40,
         "pgextwin/pg_variables": "c" * 40,
         "pgextwin/pg_store_plans": "d" * 40}
ENV = {"GITHUB_REPOSITORY": "pgextwin/build", "GITHUB_EVENT_NAME": "push",
       "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1",
       "GITHUB_SHA": BASE}

def branch(sha, target=False):
    return {
        "protected": True, "commit": {"sha": sha},
        **({"protection": {"required_status_checks": {
            "enforcement_level": "everyone",
            "checks": [{"context": "Windows required summary", "app_id": 15368}]}}} if target else {})
    }

def tests_for(sha):
    names = ("Windows required summary",) + m.REQUIRED + (m.ADMISSION,)
    jobs = [{"name": n, "head_sha": sha, "status": "completed",
             "conclusion": "success", "app": {"id": 15368}} for n in names]
    return {"total_count": len(jobs), "check_runs": jobs}

def fixture():
    data = {(m.BUILD, "branches/main"): branch(BASE)}
    for repo, sha in HEADS.items():
        data[(repo, "branches/main")] = branch(sha, True)
        data[(repo, "commits/" + sha + "/check-runs?per_page=100")] = tests_for(sha)
        data[(repo, "releases?per_page=1")] = []
    return data

class Fake:
    def __init__(self, responses):
        self.responses = deepcopy(responses)
        self.calls = []
        self.mutate = None
    def get(self, repo, path):
        m.allow(repo, path)
        key = repo, path
        self.calls.append(key)
        if self.mutate is not None:
            changed = self.mutate(key, self.calls.count(key))
            if changed is not None:
                return changed
        return deepcopy(self.responses[key])

class NegativeWitness(unittest.TestCase):
    def test_three_realistic_synthetic_rosters_are_always_deny(self):
        api = Fake(fixture())
        report = m.inspect(ENV, api)
        self.assertEqual(report["classification"], "LIVE_THREE_TARGET_METADATA_NEGATIVE_ONLY")
        self.assertEqual(len(report["targets"]), 3)
        self.assertEqual(len(api.calls), 2 + 3 * 6)
        self.assertTrue(all(t["requiredApp15368ChecksObserved"] == 1 and
                            t["successfulExactHeadWindowsMajors"] == [14,15,16,17,18]
                            for t in report["targets"]))
        for key in ("publishableReceipt", "publicationAuthorized",
                    "readerSignerWriterRuntimeSeparationVerified",
                    "actualSignerOidcCertificateVerified",
                    "actualIndependentAppWriterVerified",
                    "effectiveClassicGraphqlProtectionVerified"):
            self.assertIs(report[key], False)
        self.assertEqual((report["goB"], report["g4"], report["g5"]),
                         ("NO_GO", "NO_GO", "NO_GO"))

    def test_public_release_metadata_never_grants_publication(self):
        data = fixture()
        data[("pgextwin/pgtap", "releases?per_page=1")] = [
            {"tag_name": "synthetic-only", "published_at": "fixture"}]
        out = m.inspect(ENV, Fake(data))
        self.assertTrue(out["targets"][0]["publicReleasePresent"])
        self.assertFalse(out["publicationAuthorized"])

    def test_wrong_scope_event_and_rerun_denied(self):
        for changes in ({"GITHUB_REPOSITORY": "pgextwin/catalog"},
                        {"GITHUB_EVENT_NAME": "pull_request"},
                        {"GITHUB_REF": "refs/heads/feature"},
                        {"GITHUB_RUN_ATTEMPT": "2"},
                        {"GITHUB_SHA": "main"}):
            env = dict(ENV, **changes)
            with self.subTest(changes=changes), self.assertRaises(m.Deny):
                m.inspect(env, Fake(fixture()))

    def test_tamper_release_or_windows_exact_head_denied(self):
        for corruption in ("wrongApp", "wrongHead", "skipped", "missing18",
                           "duplicate", "pagination", "badRequired", "noProtection"):
            data = fixture()
            repo = "pgextwin/pgtap"
            checks = data[(repo, "commits/" + HEADS[repo] + "/check-runs?per_page=100")]
            jobs = checks["check_runs"]
            if corruption == "wrongApp":
                jobs[0]["app"]["id"] = 12
            elif corruption == "wrongHead":
                jobs[1]["head_sha"] = BASE
            elif corruption == "skipped":
                jobs[2]["conclusion"] = "skipped"
            elif corruption == "missing18":
                jobs.pop(-2)
                checks["total_count"] -= 1
            elif corruption == "duplicate":
                jobs.append(deepcopy(jobs[0]))
                checks["total_count"] += 1
            elif corruption == "pagination":
                checks["total_count"] += 1
            elif corruption == "badRequired":
                data[(repo, "branches/main")]["protection"]["required_status_checks"]["checks"][0]["app_id"] = 12
            else:
                data[(repo, "branches/main")]["protected"] = False
            with self.subTest(corruption=corruption), self.assertRaises(m.Deny):
                m.inspect(ENV, Fake(data))

    def test_tamper_double_get_or_head_race_denied(self):
        for fault in ("target-head", "checks", "releases", "build-head"):
            api = Fake(fixture())
            def change(key, count):
                if count != 2: return None
                repo, path = key
                if fault == "target-head" and repo == "pgextwin/pgtap" and path == "branches/main":
                    return branch("e" * 40, True)
                if fault == "build-head" and repo == m.BUILD and path == "branches/main":
                    return branch("f" * 40)
                if fault == "checks" and repo == "pgextwin/pgtap" and "/check-runs?" in path:
                    alt = tests_for(HEADS[repo])
                    alt["check_runs"][0]["conclusion"] = "failure"
                    return alt
                if fault == "releases" and repo == "pgextwin/pgtap" and path.startswith("releases?"):
                    return [{"id": 1}]
                return None
            api.mutate = change
            with self.subTest(fault=fault), self.assertRaises(m.Deny):
                m.inspect(ENV, api)

    def test_endpoint_allowlist_never_accepts_dispatch_write_or_cross_repo(self):
        for repo, path in (("pgextwin/build", "actions/workflows/promote.yml/dispatches"),
                           ("pgextwin/pgtap", "releases"),
                           ("pgextwin/pgtap", "git/refs"),
                           ("pgextwin/plpgsql_check", "branches/main"),
                           ("pgextwin/catalog", "releases?per_page=1"),
                           ("pgextwin/pgtap", "commits/evil/check-runs?per_page=100")):
            with self.subTest(repo=repo,path=path), self.assertRaises(m.Deny):
                m.allow(repo, path)

    def test_duplicate_keys_malformed_and_credentials_never_appear_in_output(self):
        with self.assertRaises(m.Deny):
            m.unique([("key",1),("key",2)])
        self.assertEqual(m.denied()["publicationAuthorized"], False)
        self.assertNotIn("token", str(m.denied()).lower())

    def test_workflow_nonpublishing_main_only_and_preexisting_45_blob_reused(self):
        workflow = (ROOT / ".github/workflows/issue-75-wave3-actions-readonly.yml").read_text()
        for mandatory in ("branches: [main]", "github.event_name == 'push'",
                          "contents: read", "persist-credentials: false",
                          "scripts/issue-75-wave3-actions-readonly.py"):
            self.assertIn(mandatory, workflow)
        for forbidden in ("contents: write", "id-token: write", "pull-requests: write",
                          "actions: write", "issues: write", "secrets.", "gh release",
                          "workflow_dispatch:", "pull_request_target:"):
            self.assertNotIn(forbidden, workflow)
        script = (ROOT / "scripts/issue-75-wave3-actions-readonly.py").read_text()
        self.assertNotIn("POST", script)
        self.assertNotIn("DELETE", script)
        self.assertTrue((ROOT / "evidence/issue-75/critical-pin-closure-20261017.json").exists())
        self.assertTrue((ROOT / "scripts/issue-75-real-principal-acceptance.py").exists())

if __name__ == "__main__":
    unittest.main()
