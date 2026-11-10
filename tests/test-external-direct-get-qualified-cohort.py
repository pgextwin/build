#!/usr/bin/env python3
"""Hostile offline regression: immutable five- and seven-original signed cohorts.

All fixtures are UNSIGNED; tests must never create a real GitHub authorizing Run,
download provider bytes, publish ZIPs or create a Release.
"""
import copy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from urllib.error import HTTPError
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


def fake_doc(with_pg18=False):
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
            "pgMajor": pg, "targetEnvironment": f"EDB PostgreSQL {pg} Windows x64; archived source-only original with reviewed runtime dependencies",
            "assetId": aid, "assetName": name, "originalBytes": size,
            "originalSha256": sha, "originalProviderUrl":
                f"https://github.com/HypoPG/hypopg/releases/download/1.4.1/{name}",
            "licenseUrl": "https://github.com/HypoPG/hypopg/blob/1.4.1/LICENSE",
            "noticeTreatment": NOTICE, "dependencyTreatment": DEPENDENCIES,
        }
        hypo.append((row, {}))
    portal = {
        "targetEnvironment": "EDB PostgreSQL 16.15.5 Windows x64; original vector 0.8.0 with reviewed runtime dependencies",
        "originalProviderUrl":
            "https://github.com/portalcorp/pgvector_compiled/releases/download/"
            "v0.16.105/pgvector-x86_64-pc-windows-msvc-pg16.zip",
        "licenseUrl":
            "https://github.com/portalcorp/pgvector_compiled/blob/v0.16.105/LICENSE",
        "noticeTreatment": NOTICE + " https://github.com/pgvector/pgvector/blob/v0.8.0/LICENSE",
        "dependencyTreatment": DEPENDENCIES,
    }
    pg18_rows = None
    if with_pg18:
        pg18_rows = []
        for pin in issuer.reviewed.PINS:
            review = dict(sourceRepo=pin[0], extension=pin[1], pgMajor=pin[2],
                repositoryId=pin[3], releaseId=pin[4], releaseTag=pin[5],
                assetId=pin[6], assetName=pin[7], originalBytes=pin[8],
                originalSha256=pin[9], packageLicenseUrl=pin[10],
                originalProviderUrl=f"https://github.com/{pin[0]}/releases/download/{pin[5]}/{pin[7]}",
                referenceLinkReviewed=True, downloadAuthorized=False, mirrorAuthorized=False,
                targetEnvironment="EDB PostgreSQL 18.6.5 Windows x64",
                providerStatusNotice="Unofficial community binary; not upstream endorsed." if pin[1] == "pgvector" else "Official oracle_fdw provider; Oracle Client obtained separately.",
                dependencyInformationUrl="https://github.com/example/provider/README",
                dependencyLicenseUrl="https://www.oracle.com/downloads/licenses/instant-client-lic.html" if pin[1] == "oracle_fdw" else None,
                noticeTreatment="Original ZIP has no LICENSE/NOTICE; upstream copyright notice is available with the provider link. " + NOTICE if pin[1] == "pgvector" else "Oracle Instant Client separately obtained under Oracle terms. " + NOTICE)
            pg18_rows.append(issuer.reviewed.expected_row(pin, review))
    return issuer.combine_manifests(
        SHA, RUN, CATALOG, trickle,
        {"bytes": t.ASSET_SIZE, "sha256": t.ASSET_SHA, "zipMembers": 158},
        hypo, portal,
        {"bytes": 163732, "sha256": issuer.portalcorp.ASSET_SHA, "zipMembers": 48},
        NOW, pg18_rows)


class ExactReviewedOriginals(unittest.TestCase):
    def test_proposal_advances_latest_pointer_with_signed_archive_atomically(self):
        doc = fake_doc(with_pg18=True)
        files = {
            "external-get-admission.json":
                (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            "attestation.json": b"synthetic-sigstore-bundle" * 10,
        }
        stored = {}
        calls = []
        branch = f"issue112-seven-originals-signed-get-run-{RUN}"
        catalog = "/repos/pgextwin/catalog"

        def api(method, route, token, body=None):
            calls.append((method, route, body))
            if method == "GET" and route == catalog + "/branches/main":
                return {"protected": True, "commit": {"sha": CATALOG}}
            if method == "POST" and route == catalog + "/git/refs":
                self.assertEqual(body, {"ref": "refs/heads/" + branch, "sha": CATALOG})
                return {"ref": body["ref"]}
            if method == "GET" and route.startswith(catalog + "/contents/"):
                path = route.split("/contents/", 1)[1].split("?", 1)[0]
                if path not in stored:
                    raise HTTPError(route, 404, "Not Found", None, None)
                return {"type": "file", "path": path,
                        "content": base64.b64encode(stored[path]).decode("ascii")}
            if method == "PUT" and route.startswith(catalog + "/contents/"):
                path = route.split("/contents/", 1)[1]
                stored[path] = base64.b64decode(body["content"], validate=True)
                return {"content": {"path": path}}
            if method == "POST" and route == catalog + "/pulls":
                return {"number": 987, "head": {"ref": branch},
                        "base": {"ref": "main"}, "body": body["body"]}
            raise AssertionError((method, route))

        number = proposal.make_pr(api, "fake-token", RUN, CATALOG, files,
                                  datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertEqual(number, 987)
        self.assertEqual(set(stored), {
            proposal.path_for(RUN, "external-get-admission.json"),
            proposal.path_for(RUN, "attestation.json"),
            proposal.LATEST_PATH,
        })
        self.assertEqual(stored[proposal.path_for(RUN, "external-get-admission.json")],
                         files["external-get-admission.json"])
        latest = json.loads(stored[proposal.LATEST_PATH])
        self.assertEqual(latest["issuerRunId"], RUN)
        self.assertEqual(latest["admissionSha256"],
                         hashlib.sha256(files["external-get-admission.json"]).hexdigest())
        self.assertEqual(len(latest["records"]), 7)
        self.assertEqual(sum(method == "POST" and route == catalog + "/pulls"
                             for method, route, _ in calls), 1)

    def test_catalog_latest_selector_is_bound_to_exact_owner_subject(self):
        doc = fake_doc(with_pg18=True)
        admission = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
        latest = json.loads(proposal.latest_manifest(admission, RUN))
        self.assertEqual(latest["schemaVersion"],
                         "pgextwin-external-latest-original-pins/v1")
        self.assertEqual(latest["issuerRunId"], RUN)
        self.assertEqual(latest["admissionSha256"], hashlib.sha256(admission).hexdigest())
        self.assertEqual(len(latest["records"]), 7)
        self.assertEqual([(x["extension"], x["pgMajor"]) for x in latest["records"]],
                         sorted((x["extension"], x["pgMajor"]) for x in latest["records"]))
        for pin in latest["records"]:
            signed = next(x for x in doc["records"]
                          if (x["extension"], x["pgMajor"]) ==
                          (pin["extension"], pin["pgMajor"]))
            self.assertEqual(pin["releaseTag"], signed["releaseTag"])
            self.assertEqual(pin["releaseId"], signed["releaseId"])
            self.assertEqual(pin["assetId"], signed["assetId"])
            self.assertEqual(pin["originalSha256"], signed["originalSha256"])

        # Advancing Catalog's latest version changes both the selected identity
        # and the subject digest; the previous owner signature cannot match it.
        newer = copy.deepcopy(doc)
        newer["records"][0]["releaseTag"] = "v0.108.4"
        newer_admission = (json.dumps(newer, sort_keys=True, separators=(",", ":")) + "\n").encode()
        newer_latest = json.loads(proposal.latest_manifest(newer_admission, RUN))
        self.assertNotEqual(newer_latest["admissionSha256"], latest["admissionSha256"])
        trickle_latest = next(x for x in newer_latest["records"]
                              if x["extension"] == "pg_trickle")
        self.assertEqual(trickle_latest["releaseTag"], "v0.108.4")
        with self.assertRaises(ValueError):
            proposal.latest_manifest(admission, RUN + 1)
        duplicate = copy.deepcopy(doc)
        duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
        duplicate_bytes = (json.dumps(duplicate, sort_keys=True,
                                      separators=(",", ":")) + "\n").encode()
        with self.assertRaises(ValueError):
            proposal.latest_manifest(duplicate_bytes, RUN)

    def test_reuses_all_three_exact_source_manifest_validators(self):
        doc = fake_doc()
        self.assertEqual(len(doc["records"]), 5)
        self.assertEqual([r["pgMajor"] for r in doc["records"]],
                         ["18", "14", "15", "16", "16"])
        self.assertEqual(proposal.verify_qualified_manifest(
            doc, SHA, CATALOG, RUN, NOW + timedelta(minutes=1)),
            NOW + timedelta(hours=6))
        with self.assertRaises(ValueError):
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
                with self.assertRaises(ValueError):
                    proposal.verify_qualified_manifest(
                        bad, SHA, CATALOG, RUN, NOW + timedelta(minutes=1))

    def test_signed_seven_originals_and_reviewed_pg18_tampering(self):
        doc = fake_doc(with_pg18=True)
        self.assertEqual(len(doc["records"]), 7)
        self.assertEqual([r["sourceRepo"] for r in doc["records"][5:]],
            ["laurenz/oracle_fdw", "andreiramani/pgvector_pgsql_windows"])
        self.assertEqual(proposal.verify_qualified_manifest(
            doc, SHA, CATALOG, RUN, NOW + timedelta(minutes=1)),
            NOW + timedelta(hours=6))
        for index, change in enumerate([
            lambda d: d["records"][5].update({"assetId": 1}),
            lambda d: d["records"][6].update({"originalSha256": "0" * 64}),
            lambda d: d["records"][5].update({"dependencyTreatment": ""}),
            lambda d: d["records"][6].update({"mirrorAuthorized": True}),
            lambda d: d["records"].reverse(),
            lambda d: d["records"].pop(),
        ]):
            with self.subTest(case=index):
                bad = copy.deepcopy(doc)
                change(bad)
                with self.assertRaises(ValueError):
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
        self.assertIn('elif len(d["records"]) in (5,7):', verify["run"])
        self.assertIn('gh attestation verify', verify["run"])
        fetch = next(step for step in jobs["issue-and-attest"]["steps"]
                     if step.get("name") == "Fetch only selected pinned original ZIP bytes privately")
        self.assertIn("for original in pg_trickle hypopg portalcorp_pgvector reviewed_pg18", fetch["run"])
        self.assertIn("bash scripts/external-direct-get-originals.sh", fetch["run"])
        self.assertNotIn("gh release", fetch["run"])
        proposal_job = jobs["propose-public-pin-pr"]["steps"][-1]
        self.assertIn("scripts/external-direct-get-qualified-cohort-pin-pr.py",
                      proposal_job["run"])

    def test_signed_metadata_destination_only_no_zip(self):
        self.assertEqual(
            proposal.path_for(RUN, "external-get-admission.json"),
            "external/signed-direct-get/qualified_cohort/run-1234/external-get-admission.json")
        with self.assertRaises(ValueError):
            proposal.path_for(RUN, "original.zip")
        with self.assertRaises(ValueError):
            proposal.path_for(RUN, "../attestation.json")
        self.assertEqual(proposal.LATEST_PATH,
            "external/signed-direct-get/qualified_cohort/latest.json")
        with self.assertRaises(issuer.trickle.Denied):
            issuer.combine_manifests(
                SHA, RUN, CATALOG, {}, {}, [], {}, {}, NOW)


if __name__ == "__main__":
    unittest.main()
