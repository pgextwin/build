#!/usr/bin/env python3
"""Offline adversarial contract for protected metadata-only public-pin proposal."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
def import_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

pin = import_file("public_get_pin", ROOT / "scripts/external-direct-get-public-pin-pr.py")
issuer = import_file("original_issuer", ROOT / "scripts/external-direct-get-issuer.py")
BUILD = "a" * 40
CATALOG = "b" * 40
NOW = datetime(2026, 11, 8, 0, 0, 1, tzinfo=timezone.utc)

def valid_manifest():
    row = {
        "assetId": issuer.ASSET_ID, "sourceRepo": issuer.SOURCE_REPO,
        "releaseId": issuer.RELEASE_ID,
        "assetName": "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "releaseTag": "v0.108.3",
        "targetEnvironment": "EDB PostgreSQL 18.6.5 Windows x64",
        "originalProviderUrl":
            "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
            "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "licenseUrl": "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
        "noticeTreatment": "Keep upstream Apache 2.0 LICENSE visible to all users.",
        "dependencyTreatment": "Users install their own upstream binary and prerequisites separately.",
    }
    return issuer.make_manifest(
        build_sha=BUILD, catalog_sha=CATALOG, runid=1234, row=row,
        proof={"bytes": issuer.ASSET_SIZE, "sha256": issuer.ASSET_SHA,
               "zipMembers": 158},
        now=NOW - timedelta(seconds=1))

class Tests(unittest.TestCase):
    def test_exact_original_manifest_is_short_lived(self):
        d = valid_manifest()
        self.assertEqual(pin.verify_manifest(d, build_sha=BUILD,
            catalog_sha=CATALOG, run_id=1234, now=NOW),
            NOW - timedelta(seconds=1) + timedelta(hours=6))
        for bad_now in (NOW - timedelta(seconds=3), NOW + timedelta(hours=6)):
            with self.subTest(bad_now=bad_now), self.assertRaises(pin.Denied):
                pin.verify_manifest(d, build_sha=BUILD, catalog_sha=CATALOG,
                    run_id=1234, now=bad_now)

    def test_hostile_permissions_expiry_owner_run_and_source_fail_closed(self):
        source = valid_manifest()
        variants = [
            ("issuerRunId", 1235), ("issuerCommit", "c" * 40),
            ("catalogCommit", "c" * 40), ("issuerEvent", "schedule"),
            ("ownerActor", "attacker"), ("ownerId", 1234),
            ("publisherEnvironment", "publisher"),
            ("publisherAppId", 5451798), ("approvedOperation", "MIRROR"),
            ("downloadAuthorized", False), ("mirrorAuthorized", True),
            ("redistributionAuthorized", True), ("expiresAt", "2026-11-09T00:00:00Z"),
            ("unexpected", True),
        ]
        for name, value in variants:
            with self.subTest(name=name):
                d = copy.deepcopy(source)
                d[name] = value
                with self.assertRaises(pin.Denied):
                    pin.verify_manifest(d, build_sha=BUILD,
                        catalog_sha=CATALOG, run_id=1234, now=NOW)
        for name, value in (
            ("sourceRepo", "laurenz/oracle_fdw"), ("assetId", 1),
            ("pgMajor", "17"), ("originalSha256", "0" * 64),
            ("originalProviderUrl", "https://evil.example/"),
            ("downloadAuthorized", False), ("mirrorAuthorized", True),
            ("licenseUrl", "https://evil.example/"), ("unexpected", "x")):
            with self.subTest(row=name):
                d = copy.deepcopy(source)
                d["records"][0][name] = value
                with self.assertRaises(pin.Denied):
                    pin.verify_manifest(d, build_sha=BUILD,
                        catalog_sha=CATALOG, run_id=1234, now=NOW)

    def test_owner_approved_same_run_independently_verified(self):
        env = {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "pgextwin/build",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "ShutenOishi", "GITHUB_TRIGGERING_ACTOR": "ShutenOishi",
            "GITHUB_ACTOR_ID": "27071164", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": BUILD, "GITHUB_RUN_ID": "1234",
        }
        event = {"repository": {"full_name": "pgextwin/build"},
                 "inputs": {"extension": "pg_trickle",
                            "operation": "ORIGINAL_PROVIDER_GET_ONLY"}}
        run = {
            "id": 1234, "event": "workflow_dispatch",
            "path": issuer.WORKFLOW, "head_branch": "main", "head_sha": BUILD,
            "run_attempt": 1, "status": "in_progress", "conclusion": None,
            "repository": {"full_name": "pgextwin/build"},
            "actor": {"login": "ShutenOishi", "id": 27071164},
            "triggering_actor": {"login": "ShutenOishi"},
        }
        jobs = {"jobs": [{"name": n, "conclusion": "success", "run_id": 1234}
                         for n in ("issue-and-attest", "independent-verify")]}
        approval = [{"user": {"login": "ShutenOishi", "id": 27071164},
                     "state": "approved",
                     "environments": [{"id": pin.ENV_ID, "name": pin.ENVIRONMENT}]}]
        branch = {"protected": True, "commit": {"sha": BUILD}}
        catalog = {"protected": True, "commit": {"sha": CATALOG}}
        args = dict(branch=branch, run=run, jobs=jobs,
                    approvals=approval, catalog=catalog)
        self.assertEqual(pin.check_run_context(env, event, **args),
                         (BUILD, CATALOG, 1234))
        attacks = [
            (env, event, {**args, "jobs": {"jobs": jobs["jobs"][:1]}}),
            (env, event, {**args, "approvals": []}),
            (env, event, {**args, "approvals": [{
                **approval[0], "user": {"login": "attacker", "id": 2}}]}),
            (env, event, {**args, "catalog": {"protected": False,
                                               "commit": {"sha": CATALOG}}}),
            ({**env, "GITHUB_RUN_ATTEMPT": "2"}, event, args),
            (env, {**event, "inputs": {"extension": "oracle_fdw",
                    "operation": "ORIGINAL_PROVIDER_GET_ONLY"}}, args),
        ]
        for e, ev, kw in attacks:
            with self.assertRaises((pin.Denied, issuer.Denied)):
                pin.check_run_context(e, ev, **kw)

    def test_write_scope_never_tags_releases_mirrors_or_main(self):
        for p in ("external-get-admission.json", "attestation.json"):
            route = "/repos/pgextwin/catalog/contents/" + pin.path_for(1234, p)
            pin.allowed_write("PUT", route, 1234)
        for method, route in (
            ("PATCH", "/repos/pgextwin/catalog/git/refs/heads/main"),
            ("POST", "/repos/pgextwin/catalog/releases"),
            ("POST", "/repos/pgextwin/catalog/git/refs/tags/x"),
            ("PUT", "/repos/pgextwin/catalog/contents/external/windows-candidates-v1.json"),
            ("PUT", "/repos/pgextwin/catalog/contents/" + pin.path_for(1235, "attestation.json")),
            ("DELETE", "/repos/pgextwin/catalog/git/refs/heads/main"),
        ):
            with self.subTest(method=method, route=route), self.assertRaises(pin.Denied):
                pin.allowed_write(method, route, 1234)

    def test_readback_inputs_require_exact_flat_two_files(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / "external-get-admission.json").write_bytes(b"a" * 200)
            (p / "attestation.json").write_bytes(b"b" * 200)
            self.assertEqual(set(pin.read_exact(p)), {
                "external-get-admission.json", "attestation.json"})
            (p / "original.zip").write_bytes(b"bad")
            with self.assertRaises(pin.Denied):
                pin.read_exact(p)

    def test_new_owner_workflow_pr_job_requires_independent_gate_and_environment(self):
        import yaml
        doc = yaml.load((ROOT / ".github/workflows/external-direct-get-issuer.yml")
                         .read_text("utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(set(doc["on"]), {"workflow_dispatch"})
        job = doc["jobs"]["propose-public-pin-pr"]
        self.assertEqual(job["environment"], pin.ENVIRONMENT)
        self.assertEqual(set(job["needs"]), {"issue-and-attest", "independent-verify"})
        self.assertEqual(job["permissions"], {"contents": "read"})
        text = json.dumps(job)
        self.assertIn("external-direct-get-public-pin-pr.py", text)
        self.assertIn("EXTERNAL_DIRECT_PROVIDER_APP_PRIVATE_KEY", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("gh release", text)

if __name__ == "__main__":
    unittest.main()
