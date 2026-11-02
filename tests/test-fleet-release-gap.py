#!/usr/bin/env python3
"""Offline deterministic release-gap observations; never Release authorization."""
import importlib.util
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fleet_release_gap", ROOT / "scripts/fleet-release-gap.py"
)
gap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gap)
SHA = "a" * 40


def registry():
    return {
        "schemaVersion": 1, "entries": [
            {"repository": "pgextwin/hypopg"},
            {"repository": "pgextwin/plpgsql_check"},
        ],
    }


def scan():
    return {
        "schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
        "publication": "DENY", "candidatePrCreated": False,
        "fleetSize": 2, "extensions": [
            {"repository": "pgextwin/hypopg", "status": "up-to-date",
             "mainSha": SHA, "current": {"ref": "1.4.5", "version": "1.4.5"}},
            {"repository": "pgextwin/plpgsql_check", "status": "up-to-date",
             "mainSha": SHA, "current": {"ref": "v2.10.16", "version": "2.10.16"}},
        ],
    }


def get(url):
    if url.endswith("/branches/main"):
        return {"protected": True, "commit": {"sha": SHA}}
    if url.endswith("/hypopg/releases?per_page=100"):
        return [{"tag_name": "v1.4.5-windows.1", "draft": False, "prerelease": False}]
    if url.endswith("/plpgsql_check/releases?per_page=100"):
        return [{"tag_name": "v2.10.15-windows.1", "draft": False, "prerelease": False}]
    raise AssertionError("unexpected GitHub read")


class FleetReleaseGapTests(TestCase):
    def test_release_gap_and_published_tag_without_granting_authority(self):
        result = gap.report(registry(), scan(), get)
        self.assertEqual(result["fleetSize"], 2)
        self.assertEqual(result["releaseGaps"], 1)
        self.assertEqual(result["indeterminate"], 0)
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["verifiedPublishedBytes"])
        self.assertFalse(result["catalogVerified"])
        states = {row["repository"]: row for row in result["extensions"]}
        self.assertEqual(states["pgextwin/plpgsql_check"]["status"],
                         "CURRENT_VERSION_RELEASE_MISSING")
        self.assertEqual(states["pgextwin/hypopg"]["status"],
                         "CURRENT_VERSION_TAG_PRESENT_UNVERIFIED")
        self.assertTrue(all(r["publicationAuthorized"] is False
                            and r["publicationVerified"] is False
                            for r in result["extensions"]))

    def test_legacy_date_and_per_major_version_stem(self):
        self.assertEqual(gap.stem("pgextwin/pg_bigm",
                                 {"ref": "v1.2-20250903", "version": "1.2"}),
                         "v1.2-20250903")
        self.assertEqual(gap.stem("pgextwin/pg_hint_plan",
                                 {"14": {"version": "1.4.5"},
                                  "18": {"version": "1.8.1"}}),
                         "v1.8.1")
        for bad in ({}, {"version": "v2.0"}, {"14": {"version": "a"}},
                    {"13": {"version": "1.0"}}):
            with self.assertRaises(gap.GapDenied):
                gap.stem("pgextwin/hypopg", bad)

    def test_stale_or_untrusted_scan_is_rejected(self):
        for field, value in (
            ("publication", "ALLOW"),
            ("candidatePrCreated", True),
            ("fleetSize", 17),
            ("scope", "SCHEDULE_AUTHORIZED"),
            ("extensions", scan()["extensions"][:1]),
        ):
            with self.subTest(field=field):
                report = scan()
                report[field] = value
                with self.assertRaises(gap.GapDenied):
                    gap.report(registry(), report, get)

    def test_main_drift_and_unavailable_public_api_are_indeterminate(self):
        def drift(url):
            if url.endswith("/branches/main"):
                return {"protected": True, "commit": {"sha": "b" * 40}}
            return get(url)
        self.assertEqual(gap.report(registry(), scan(), drift)["indeterminate"], 2)
        def blocked(url):
            if "/releases?per_page=100" in url:
                raise gap.WatchError("HTTP 403")
            return get(url)
        self.assertEqual(gap.report(registry(), scan(), blocked)["indeterminate"], 2)
        def truncated(url):
            if "/releases?per_page=100" in url:
                return [{"tag_name": "v1.4.5-windows.1",
                         "draft": False, "prerelease": False}] * 100
            return get(url)
        self.assertEqual(gap.report(registry(), scan(), truncated)["indeterminate"], 2)

    def test_absent_source_and_upstream_pending_do_not_claim_no_update(self):
        observation = scan()
        observation["extensions"][1]["status"] = "update-available"
        out = gap.report(registry(), observation, get)
        self.assertEqual(out["extensions"][1]["status"], "UPSTREAM_UPDATE_UNPREPARED")
        observation["extensions"][1]["status"] = "INDETERMINATE"
        with self.assertRaises(gap.GapDenied):
            gap.report(registry(), observation, get)


if __name__ == "__main__":
    main()
