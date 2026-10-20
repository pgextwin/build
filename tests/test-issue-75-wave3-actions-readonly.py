"""Wave-three Actions-only main push witness is strictly GET-only and DENY-only.

Synthetic fixtures cannot establish an actual independent Signer, Writer,
effective branch rules, or a publishable authorization.
"""
from __future__ import annotations
from copy import deepcopy
import base64
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

PROMOTION = """name: Promote verified candidate (synthetic fixture only)
on:
  workflow_dispatch:
    inputs:
      confirm_release:
        description: Type PUBLISH to explicitly authorize
concurrency:
  group: synthetic
permissions:
  contents: read
jobs:
  authorize:
    runs-on: ubuntu-latest
    steps:
      - name: authorize
        run: echo DENY
      - name: pin first
        with:
          ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977
  release_build:
    needs: authorize
    uses: pgextwin/build/.github/workflows/build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d
  publish:
    needs: [authorize, release_build]
    name: Check signatures, exact SHA256 and create-only Release ID
    steps:
      - with:
          ref: 455f0ccc667697f600700a6e64bcfd6c57b6a977
"""
POLICY = b'{"schemaVersion":1,"enabled":false,"releasePolicy":"manual-dispatch"}\n'

def content_record(path, raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return {"type":"file", "path":path, "size":len(raw),
            "sha":m.git_blob(raw),"encoding":"base64",
            "content":base64.b64encode(raw).decode("ascii")}

def fixture():
    data = {(m.BUILD, "branches/main"): branch(BASE)}
    for repo, sha in HEADS.items():
        data[(repo, "branches/main")] = branch(sha, True)
        data[(repo, "commits/" + sha + "/check-runs?per_page=100")] = tests_for(sha)
        data[(repo, "releases?per_page=1")] = []
        data[(repo, "contents/" + m.PROMOTION_FILES[0] + "?ref=" + sha)] = content_record(
            m.PROMOTION_FILES[0], PROMOTION)
        data[(repo, "contents/" + m.PROMOTION_FILES[1] + "?ref=" + sha)] = content_record(
            m.PROMOTION_FILES[1], POLICY)
    return data

def fixture_pins():
    data = fixture()
    return {
        repo: {
            "workflowBlob": data[(repo, "contents/" + m.PROMOTION_FILES[0] +
                                   "?ref=" + sha)]["sha"],
            "policyBlob": data[(repo, "contents/" + m.PROMOTION_FILES[1] +
                                 "?ref=" + sha)]["sha"],
        }
        for repo, sha in HEADS.items()
    }

def inspect(env, api):
    # Synthetic data never supplies production accepted Git Blob identities.
    # Actual main() keeps the independent immutable live-evidence constants.
    return m.inspect(env, api, expected_blobs=fixture_pins())

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
        report = inspect(ENV, api)
        self.assertEqual(report["classification"], "LIVE_THREE_TARGET_METADATA_NEGATIVE_ONLY")
        self.assertEqual(len(report["targets"]), 3)
        self.assertEqual(len(api.calls), 2 + 3 * 10)
        self.assertTrue(all(t["requiredApp15368ChecksObserved"] == 1 and
                            t["successfulExactHeadWindowsMajors"] == [14,15,16,17,18] and
                            t["disabledManualPromotionPolicyObserved"] is True and
                            t["legacySignerPublisherPinsObserved"] is True and
                            t["exactHistoricalPromotionBlobPinsObserved"] is True and
                            t["independentWriterProvisionedByThisWorkflow"] is False
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
        out = inspect(ENV, Fake(data))
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
                inspect(env, Fake(fixture()))

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
                inspect(ENV, Fake(data))

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
                inspect(ENV, api)

    def test_production_expected_blobs_are_fresh_authenticated_live_run_ids(self):
        self.assertEqual(m.EXPECTED_PROMOTION_BLOBS, {
            "pgextwin/pgtap": {
                "workflowBlob": "d8b2ffe43633831cd7f00dcec2135fbed18eb04a",
                "policyBlob": "fc354ed9c66fe00b539ba02e0b873b9280e42f90"},
            "pgextwin/pg_variables": {
                "workflowBlob": "88b7c3131ddf0a667b4947261cf5cf69bc3fe087",
                "policyBlob": "fc354ed9c66fe00b539ba02e0b873b9280e42f90"},
            "pgextwin/pg_store_plans": {
                "workflowBlob": "1d4280f7fd1f269a27400b3355feb5845f9ed02b",
                "policyBlob": "fc354ed9c66fe00b539ba02e0b873b9280e42f90"},
        })
        for repo in m.TARGETS:
            self.assertNotEqual(
                fixture_pins()[repo]["workflowBlob"],
                m.EXPECTED_PROMOTION_BLOBS[repo]["workflowBlob"])

    def test_lookalike_policy_or_workflow_with_correct_text_fails_exact_blob(self):
        f=fixture()
        for item, variant in (
            (m.PROMOTION_FILES[0], PROMOTION+"\n# synthetically modified\n"),
            (m.PROMOTION_FILES[1],
             POLICY.decode().replace('"enabled":false','"enabled":false ')+"\n"),
        ):
            with self.subTest(path=item):
                data=deepcopy(f)
                repo="pgextwin/pgtap"
                key=(repo,"contents/"+item+"?ref="+HEADS[repo])
                data[key]=content_record(item,variant)
                # Even if text policy source parser accepts, a trusted
                # previously pinned digest cannot be replaced by a new hash.
                self.assertTrue(
                    m.promotion_workflow(variant.encode()) if item.endswith(".yml")
                    else m.promotion_policy(variant.encode()))
                with self.assertRaises(m.Deny):
                    m.inspect(ENV, Fake(data), expected_blobs=fixture_pins())

    def test_wrong_expected_pins_fail_closed_even_with_matching_files(self):
        p=fixture_pins()
        for wrong in ("wrongRepo","wrongBlob","extra","missing","bool"):
            copies=deepcopy(p)
            if wrong=="wrongRepo":
                copies["pgextwin/other"]=copies.pop("pgextwin/pgtap")
            elif wrong=="wrongBlob":
                copies["pgextwin/pgtap"]["policyBlob"]="0"*40
            elif wrong=="extra":
                copies["pgextwin/pgtap"]["token"]="attacker"
            elif wrong=="missing":
                del copies["pgextwin/pgtap"]["policyBlob"]
            else:
                copies["pgextwin/pgtap"]["policyBlob"]=True
            with self.subTest(wrong=wrong), self.assertRaises(m.Deny):
                m.inspect(ENV, Fake(fixture()), expected_blobs=copies)

    def test_current_synthetic_manual_promotion_policy_source_validator(self):
        self.assertTrue(m.promotion_policy(POLICY))
        self.assertTrue(m.promotion_workflow(PROMOTION.encode()))
        invalid_policies = [
            b'{"schemaVersion":1,"enabled":true,"releasePolicy":"manual-dispatch"}',
            b'{"schemaVersion":1,"enabled":false,"releasePolicy":"automatic"}',
            b'{"schemaVersion":1,"enabled":false,"releasePolicy":"manual-dispatch","goB":"GO"}',
            b'{"schemaVersion":1,"enabled":false,"enabled":true,"releasePolicy":"manual-dispatch"}',
            b'{"schemaVersion":true,"enabled":false,"releasePolicy":"manual-dispatch"}',
        ]
        for invalid in invalid_policies:
            with self.subTest(policy=invalid[:50]), self.assertRaises(m.Deny):
                m.promotion_policy(invalid)
        invalid_sources = [
            PROMOTION.replace("  workflow_dispatch:", "  push:"),
            PROMOTION.replace("  workflow_dispatch:", "  workflow_dispatch:\n  push:"),
            PROMOTION.replace(m.HISTORICAL_SIGNER, "f"*40),
            PROMOTION.replace(m.HISTORICAL_PUBLISHER, "f"*40),
            PROMOTION.replace("description: Type PUBLISH", "description: Type GO"),
            PROMOTION.replace("    needs: [authorize, release_build]", "    needs: release_build"),
            PROMOTION.replace("  publish:", "  publisher_override:"),
            PROMOTION + "\non:\n  push:\n",
        ]
        for invalid in invalid_sources:
            with self.subTest(source=invalid[:45]), self.assertRaises(m.Deny):
                m.promotion_workflow(invalid.encode("utf-8"))

    def test_live_double_get_promotion_source_and_policy_tamper_denied(self):
        repo = "pgextwin/pgtap"
        head = HEADS[repo]
        for kind in ("policyEnable","policyDuplicate","workflowPush","signerRepin",
                     "publisherRepin","digestMismatch","wrongSha","malformedB64",
                     "missing","wrongType","wrongSize","secondRead"):
            data = fixture()
            key = (repo, "contents/" + m.PROMOTION_FILES[
                1 if kind.startswith("policy") else 0] + "?ref=" + head)
            if kind == "policyEnable":
                data[key] = content_record(m.PROMOTION_FILES[1], POLICY.replace(b"false",b"true"))
            elif kind == "policyDuplicate":
                data[key] = content_record(m.PROMOTION_FILES[1],
                    b'{"schemaVersion":1,"enabled":false,"enabled":false,"releasePolicy":"manual-dispatch"}')
            elif kind == "workflowPush":
                data[key] = content_record(m.PROMOTION_FILES[0],
                    PROMOTION.replace("  workflow_dispatch:","  push:"))
            elif kind == "signerRepin":
                data[key] = content_record(m.PROMOTION_FILES[0],
                    PROMOTION.replace(m.HISTORICAL_SIGNER,"f"*40))
            elif kind == "publisherRepin":
                data[key] = content_record(m.PROMOTION_FILES[0],
                    PROMOTION.replace(m.HISTORICAL_PUBLISHER,"f"*40))
            elif kind == "digestMismatch":
                data[key]["sha"] = "0"*40
            elif kind == "wrongSha":
                data[key]["path"] = "config/not-promotion.json"
            elif kind == "malformedB64":
                data[key]["content"] = "!malformed!"
            elif kind == "missing":
                data.pop(key)
            elif kind == "wrongType":
                data[key]["type"] = "dir"
            elif kind == "wrongSize":
                data[key]["size"] = True
            elif kind == "secondRead":
                api = Fake(data)
                def change(key_, count):
                    if key_ == key and count == 2:
                        wrong = deepcopy(data[key])
                        wrong["sha"] = "0"*40
                        return wrong
                    return None
                api.mutate = change
                with self.subTest(kind=kind), self.assertRaises(m.Deny):
                    inspect(ENV, api)
                continue
            with self.subTest(kind=kind), self.assertRaises((m.Deny,KeyError)):
                inspect(ENV, Fake(data))

    def test_base64_transport_git_blob_and_lf_exactness(self):
        doc = content_record(m.PROMOTION_FILES[1], POLICY)
        api = Fake(fixture())
        repo = "pgextwin/pgtap"
        api.responses[(repo, "contents/" + m.PROMOTION_FILES[1] + "?ref=" + HEADS[repo])] = doc
        raw, actual_sha = m.pinned_contents(api, repo, HEADS[repo],m.PROMOTION_FILES[1])
        self.assertEqual(raw,POLICY)
        self.assertEqual(actual_sha,m.git_blob(POLICY))
        with self.assertRaises(m.Deny):
            m.promotion_policy(POLICY.replace(b"\n",b"\r\n"))
    def test_endpoint_allowlist_never_accepts_dispatch_write_or_cross_repo(self):
        for repo, path in (("pgextwin/build", "actions/workflows/promote.yml/dispatches"),
                           ("pgextwin/pgtap", "releases"),
                           ("pgextwin/pgtap", "git/refs"),
                           ("pgextwin/plpgsql_check", "branches/main"),
                           ("pgextwin/catalog", "releases?per_page=1"),
                           ("pgextwin/pgtap", "commits/evil/check-runs?per_page=100"),
                           ("pgextwin/pgtap", "contents/config/release-promotion.json?ref=main"),
                           ("pgextwin/pgtap", "contents/.github/workflows/promote.yml?ref=bad"),
                           ("pgextwin/pgtap", "contents/.github/workflows/publish.yml?ref="+"a"*40)):
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
