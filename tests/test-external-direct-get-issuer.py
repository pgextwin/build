#!/usr/bin/env python3
"""Hostile synthetics for Issue #112 genuine owner external GET-only issuer."""
import copy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "direct_get_issuer",
    Path(__file__).resolve().parents[1] / "scripts/external-direct-get-issuer.py")
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)
SHA = "a" * 40
BUILD = "pgextwin/build"


def env():
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": BUILD,
        "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTOR": "ShutenOishi", "GITHUB_TRIGGERING_ACTOR": "ShutenOishi",
        "GITHUB_ACTOR_ID": "27071164", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "1234",
    }


def event():
    return {
        "repository": {"full_name": BUILD},
        "inputs": {"extension": "pg_trickle",
                   "operation": "ORIGINAL_PROVIDER_GET_ONLY"},
    }


def branch():
    return {"protected": True, "commit": {"sha": SHA}}


def run():
    return {
        "id": 1234, "event": "workflow_dispatch",
        "path": issuer.WORKFLOW, "head_branch": "main",
        "head_sha": SHA, "run_attempt": 1, "status": "in_progress",
        "conclusion": None, "repository": {"full_name": BUILD},
        "actor": {"login": "ShutenOishi", "id": 27071164},
        "triggering_actor": {"login": "ShutenOishi"},
    }


def fake_row():
    return {
        "sourceRepo": issuer.SOURCE_REPO,
        "assetId": issuer.ASSET_ID, "releaseId": issuer.RELEASE_ID,
        "assetName": "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "releaseTag": "v0.108.3",
        "targetEnvironment": "EDB PostgreSQL 18.6.5 Windows x64",
        "originalProviderUrl":
            "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
            "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "licenseUrl": "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
        "noticeTreatment": "Original upstream Apache-2.0 LICENSE included, third party notice references remain user-visible.",
        "dependencyTreatment": "This is a GET-only request; user installs prerequisites separately with the upstream documentation.",
    }


class Tests(unittest.TestCase):
    def test_genuine_original_owner_dispatch_can_pass_shape(self):
        self.assertEqual(
            issuer.validate_original_owner_run(env(), event(), branch(), run()),
            (SHA, 1234))

    def test_forged_dispatch_or_source_denied(self):
        cases = {
            "GITHUB_ACTIONS": "false",
            "GITHUB_EVENT_NAME": "issue_comment",
            "GITHUB_REF": "refs/heads/feature",
            "GITHUB_ACTOR": "attacker",
            "GITHUB_ACTOR_ID": "1",
            "GITHUB_TRIGGERING_ACTOR": "attacker",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SHA": "wrong",
            "GITHUB_RUN_ID": "0",
        }
        for k, v in cases.items():
            with self.subTest(k=k):
                e = env()
                e[k] = v
                with self.assertRaises(issuer.Denied):
                    issuer.validate_original_owner_run(e, event(), branch(), run())
        for k, v in (
            ("id", 1235), ("event", "schedule"), ("path", "publish.yml"),
            ("run_attempt", 2), ("status", "completed"), ("conclusion", "success"),
            ("head_sha", "b" * 40), ("head_branch", "feature")
        ):
            with self.subTest(k=k):
                r = run()
                r[k] = v
                with self.assertRaises(issuer.Denied):
                    issuer.validate_original_owner_run(env(), event(), branch(), r)
        cases = [
            {"extension": "oracle_fdw", "operation": issuer.OPERATION},
            {"extension": "pg_trickle", "operation": "MIRROR"},
            {"extension": "pg_trickle", "operation": issuer.OPERATION,
             "downloadAuthorized": True},
        ]
        for inputs in cases:
            with self.subTest(inputs=inputs):
                ev = event()
                ev["inputs"] = inputs
                with self.assertRaises(issuer.Denied):
                    issuer.validate_original_owner_run(env(), ev, branch(), run())

    def test_unprotected_main_and_untrusted_actor_denied(self):
        b = branch()
        b["protected"] = False
        with self.assertRaises(issuer.Denied):
            issuer.validate_original_owner_run(env(), event(), b, run())
        r = run()
        r["actor"] = {"login": "bot", "id": 27071164}
        with self.assertRaises(issuer.Denied):
            issuer.validate_original_owner_run(env(), event(), branch(), r)
        r = run()
        r["triggering_actor"] = {"login": "bot"}
        with self.assertRaises(issuer.Denied):
            issuer.validate_original_owner_run(env(), event(), branch(), r)

    def test_strict_app_reuse_never_mints_or_writes(self):
        calls = []
        def api(method, route, jwt):
            calls.append((method, route))
            if route == "/app":
                return {"id": issuer.APP_ID,
                        "slug": "pgextwin-external-direct-publisher"}
            if route == f"/app/installations/{issuer.INSTALL_ID}":
                return {
                    "id": issuer.INSTALL_ID, "app_id": issuer.APP_ID,
                    "repository_selection": "selected",
                    "permissions": {"metadata": "read",
                                    "contents": "write", "pull_requests": "write"},
                    "suspended_at": None,
                    "account": {"login": "pgextwin"},
                }
            raise AssertionError("Never POST or use API outside app identity")
        issuer.verify_app_readonly("x" * 100, api=api,
                                   jwt=lambda key, id: "synthetic-JWT")
        self.assertEqual(calls, [
            ("GET", "/app"), ("GET", f"/app/installations/{issuer.INSTALL_ID}")])
        def bad_api(method, route, jwt):
            obj = api(method, route, jwt)
            if route == "/app":
                obj["id"] = 1
            return obj
        with self.assertRaises(issuer.Denied):
            issuer.verify_app_readonly("x" * 100, api=bad_api,
                                       jwt=lambda key, id: "synthetic-JWT")

    def test_manifest_is_exact_scoped_and_unsigned_until_oidc(self):
        data = issuer.make_manifest(
            build_sha=SHA, runid=1234, catalog_sha="b" * 40,
            row=fake_row(),
            proof={"bytes": issuer.ASSET_SIZE, "sha256": issuer.ASSET_SHA,
                   "zipMembers": 158},
            now=datetime(2026, 11, 7, tzinfo=timezone.utc))
        self.assertEqual(set(data), {
            "schemaVersion", "sourceKind", "issuerRepository", "issuerCommit",
            "catalogCommit", "issuerEvent", "issuerRunId", "issuerRunAttempt",
            "ownerActor", "ownerId", "publisherEnvironment", "publisherAppId",
            "approvedOperation", "issuedAt", "expiresAt", "downloadAuthorized",
            "mirrorAuthorized", "redistributionAuthorized", "records"})
        self.assertEqual(data["approvedOperation"], issuer.OPERATION)
        self.assertTrue(data["downloadAuthorized"])
        self.assertFalse(data["mirrorAuthorized"])
        self.assertFalse(data["redistributionAuthorized"])
        self.assertEqual(len(data["records"]), 1)
        self.assertEqual(data["records"][0]["assetId"], issuer.ASSET_ID)
        self.assertEqual(data["expiresAt"], "2026-11-07T06:00:00Z")
        for bad in ({"bytes": 1, "sha256": issuer.ASSET_SHA, "zipMembers": 158},
                    {"bytes": issuer.ASSET_SIZE, "sha256": "0" * 64, "zipMembers": 158},
                    {"bytes": issuer.ASSET_SIZE, "sha256": issuer.ASSET_SHA, "zipMembers": 0}):
            with self.assertRaises(issuer.Denied):
                issuer.make_manifest(build_sha=SHA, runid=1234,
                    catalog_sha="b" * 40, row=fake_row(), proof=bad,
                    now=datetime.now(timezone.utc))

    def test_original_zip_and_duplicate_keys_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "not-the-original.zip"
            p.write_bytes(b"PK\x03\x04")
            with self.assertRaises(issuer.Denied):
                issuer.verify_original_zip(p)
        with self.assertRaises(issuer.Denied):
            issuer.no_duplicates([("downloadAuthorized", False),
                                  ("downloadAuthorized", True)])
        with self.assertRaises(issuer.Denied):
            issuer.gh_get("repos/pgextwin/catalog/releases/latest/download/fake.zip")


if __name__ == "__main__":
    unittest.main()
