#!/usr/bin/env python3
"""Hostile offline regression: exactly five original ZIPs, genuine owner/CI gates.

All fixtures are UNSIGNED; tests must never create a real GitHub authorizing Run,
download provider bytes, publish ZIPs or create a Release.
"""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
import importlib.util


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


issuer = load("batch_issuer_test", "external-direct-get-qualified-cohort-issuer.py")
proposal = load("batch_proposal_test", "external-direct-get-qualified-cohort-pin-pr.py")
SHA = "a" * 40
CATALOG = "b" * 40
RUN = 1234
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
NOTICE = ("Reviewed upstream project licenses and NOTICE remain provider-controlled; "
          "pgextwin never republishes the third-party ZIP or its dependencies.")
DEPENDENCIES = ("Requires the matching EDB PostgreSQL Windows x64 runtime and its "
                "third-party dependencies; no installer or automatic relocation.")


def fake_doc():
    t = issuer.trickle
    trickle = {
        "sourceRepo": t.SOURCE_REPO, "assetId": t.ASSET_ID,
        "releaseTag": "v0.108.3",
        "assetName": "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "targetEnvironment": "EDB PostgreSQL 18.6.5 Windows x64",
        "originalProviderUrl":
            "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
            "pg_trickle-0.108.3-pg18-windows-amd64.zip",
        "licenseUrl": "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
        "noticeTreatment": NOTICE, "dependencyTreatment": DEPENDENCIES,
    }
    hypo = []
    for pg, (aid, size, sha) in issuer.hypopg.PINS.items():
        name = f"hypopg-1.4.1-pg{pg}-x64.zip"
        row = {
            "pgMajor": pg, "targetEnvironment": f"EDB PostgreSQL {pg} Windows x64",
            "assetId": aid, "assetName": name, "originalBytes": size,
            "originalSha256": sha, "originalProviderUrl":
                f"https://github.com/HypoPG/hypopg/releases/download/1.4.1/{name}",
            "licenseUrl": "https://github.com/HypoPG/hypopg/blob/1.4.1/LICENSE",
            "noticeTreatment": NOTICE, "dependencyTreatment": DEPENDENCIES,
        }
        hypo.append((row, {}))
    portal = {
        "targetEnvironment": "EDB PostgreSQL 16.15.5 Windows x64",
        "originalProviderUrl":
            "https://github.com/portalcorp/pgvector_compiled/releases/download/"
            "v0.16.105/pgvector-x86_64-pc-windows-msvc-pg16.zip",
        "licenseUrl":
            "https://github.com/portalcorp/pgvector_compiled/blob/v0.16.105/LICENSE",
        "noticeTreatment": NOTICE + " https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE",
        "dependencyTreatment": DEPENDENCIES,
    }
    return issuer.combine_manifests(
        SHA, RUN, CATALOG, trickle,
        {"bytes": t.ASSET_SIZE, "sha256": t.ASSET_SHA, "zipMembers": 158},
        hypo, portal,
        {"bytes": 163732, "sha256": issuer.portalcorp.ASSET_SHA, "zipMembers": 48},
        NOW)


class ExactFiveOriginals(unittest.TestCase):
    def test_reuses_all_three_exact_source_manifest_validators(self):
        doc = fake_doc()
        self.assertEqual(len(doc["records"]), 5)
        self.assertEqual([r["pgMajor"] for r in doc["records"]],
                         ["18", "14", "15", "16", "16"])
        self.assertEqual(proposal.verify_qualified_manifest(
            doc, SHA, CATALOG, RUN, NOW + timedelta(minutes=1)),
            NOW + timedelta(hours=6))
        with self.assertRaises(proposal.old.Denied):
            proposal.verify_qualified_manifest(
                doc, SHA, CATALOG, RUN, NOW + timedelta(hours=7))

    def test_malicious_source_set_rejected(self):
        doc = fake_doc()
        mutations = [
            lambda d: d["records"].pop(),
            lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
            lambda d: d["records"].reverse(),
            lambda d: d["records"][1].update({"pgMajor": "17"}),
            lambda d: d["records"][3].update({"originalSha256": "0" * 64}),
            lambda d: d["records"][4].update({"sourceRepo": "laurenz/oracle_fdw"}),
            lambda d: d["records"][0].update({"mirrorAuthorized": True}),
            lambda d: d["records"][4].update({"noticeTreatment": ""}),
            lambda d: d.update({"expiresAt": "2026-11-10T06:00:00Z"}),
            lambda d: d.update({"ownerId": 42}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                bad = copy.deepcopy(doc)
                mutate(bad)
                with self.assertRaises(proposal.old.Denied):
                    proposal.verify_qualified_manifest(
                        bad, SHA, CATALOG, RUN, NOW + timedelta(minutes=1))

    def test_owner_event_only_and_reviewed_single_batch(self):
        doc = yaml.load((ROOT / ".github/workflows/external-direct-get-issuer.yml")
                        .read_text("utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(set(doc["on"]), {"workflow_dispatch"})
        self.assertEqual(doc["on"]["workflow_dispatch"]["inputs"]["extension"]["options"],
                         ["pg_trickle", "hypopg", "portalcorp_pgvector", "qualified_cohort"])
        jobs = doc["jobs"]
        self.assertEqual(set(jobs),
                         {"issue-and-attest", "independent-verify", "propose-public-pin-pr"})
        self.assertEqual(jobs["issue-and-attest"]["environment"],
                         "external-direct-provider-publisher")
        self.assertNotIn("environment", jobs["independent-verify"])
        self.assertEqual(jobs["propose-public-pin-pr"]["environment"],
                         "external-direct-provider-publisher")
        verify = next(step for step in jobs["independent-verify"]["steps"]
                      if step.get("name") ==
                      "Independently verify exact Build/main signer and no-mirror operation")
        self.assertIn('elif len(d["records"])==5:', verify["run"])
        self.assertIn('gh attestation verify', verify["run"])
        fetch = next(step for step in jobs["issue-and-attest"]["steps"]
                     if step.get("name") == "Fetch only selected pinned original ZIP bytes privately")
        self.assertIn("for original in pg_trickle hypopg portalcorp_pgvector", fetch["run"])
        self.assertIn("bash scripts/external-direct-get-originals.sh", fetch["run"])
        self.assertNotIn("gh release", fetch["run"])
        proposal_job = jobs["propose-public-pin-pr"]["steps"][-1]
        self.assertIn("scripts/external-direct-get-qualified-cohort-pin-pr.py",
                      proposal_job["run"])

    def test_signed_metadata_destination_only_no_zip(self):
        self.assertEqual(
            proposal.path_for(RUN, "external-get-admission.json"),
            "external/signed-direct-get/qualified_cohort/run-1234/external-get-admission.json")
        with self.assertRaises(proposal.old.Denied):
            proposal.path_for(RUN, "original.zip")
        with self.assertRaises(proposal.old.Denied):
            proposal.path_for(RUN, "../attestation.json")
        with self.assertRaises(issuer.trickle.Denied):
            issuer.combine_manifests(
                SHA, RUN, CATALOG, {}, {}, [], {}, {}, NOW)


if __name__ == "__main__":
    unittest.main()
