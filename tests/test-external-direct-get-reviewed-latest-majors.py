#!/usr/bin/env python3
"""Offline adversarial contract for newest PG14-17 reviewed immutable originals."""
import copy
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "newest_pins", ROOT / "scripts/external-direct-get-reviewed-latest-majors.py")
current = importlib.util.module_from_spec(spec)
spec.loader.exec_module(current)


def fixture():
    rows = []
    for pin in current.PINS:
        repo, ext, pg, rid, release, tag, asset, name, size, sha, license_url = pin
        rows.append({
            "sourceGroup": "external", "extension": ext, "pgMajor": pg,
            "targetEnvironment": "EDB PostgreSQL " + pg + " Windows x64 original",
            "sourceRepo": repo, "repositoryId": rid, "releaseTag": tag,
            "releaseId": release, "assetName": name, "assetId": asset,
            "originalBytes": size, "originalSha256": sha,
            "originalProviderUrl": current.original_url(pin),
            "licenseUrl": license_url,
            "noticeTreatment":
                ("Original third-party ZIP has no LICENSE/NOTICE member. " +
                 "Preserve linked upstream copyright and disclaimer. " * 2)
                if ext == "pgvector" else
                ("Oracle Instant Client separately obtained under Oracle terms. " +
                 "Original provider retains copyright and license. " * 2),
            "dependencyTreatment":
                ("Unofficial community Windows build; independently tested with "
                 "PostgreSQL and no bundled third-party runtime." * 2)
                if ext == "pgvector" else
                ("Oracle Instant Client separately licensed: " +
                 "https://www.oracle.com/downloads/licenses/instant-client-lic.html " * 2),
            "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
            "downloadAuthorized": True, "mirrorAuthorized": False,
        })
    return rows


class NewestExactSourceTests(unittest.TestCase):
    def test_exact_eight_pins_no_old_fallback(self):
        rows = fixture()
        current.verify_signed_rows(rows)
        self.assertEqual(len(rows), 8)
        self.assertEqual({r["pgMajor"] for r in rows}, {"14", "15", "16", "17"})
        self.assertEqual({r["extension"] for r in rows}, {"oracle_fdw", "pgvector"})
        self.assertEqual(len({(r["extension"], r["pgMajor"]) for r in rows}), 8)
        self.assertFalse(any("hypopg" in r["sourceRepo"] or
                             "portalcorp" in r["sourceRepo"] for r in rows))

    def test_hostile_substitution_rights_and_duplicate_denied(self):
        attacks = [
            lambda r: r[0].update({"assetId": 0}),
            lambda r: r[1].update({"originalSha256": "0" * 64}),
            lambda r: r[2].update({"pgMajor": "18"}),
            lambda r: r[3].update({"sourceRepo": "portalcorp/pgvector_compiled"}),
            lambda r: r[4].update({"mirrorAuthorized": True}),
            lambda r: r[5].update({"downloadAuthorized": False}),
            lambda r: r[6].update({"licenseUrl": "https://evil.invalid"}),
            lambda r: r[7].update({"dependencyTreatment": ""}),
            lambda r: r[0].update({"unexpectedAuthority": True}),
            lambda r: r.append(copy.deepcopy(r[0])),
            lambda r: r.pop(),
            lambda r: r.reverse(),
        ]
        for i, attack in enumerate(attacks):
            with self.subTest(case=i):
                rows = fixture()
                attack(rows)
                with self.assertRaises(ValueError):
                    current.verify_signed_rows(rows)

    def test_download_plan_exactly_one_get_per_pinned_original(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            current.download_plan()
        lines = buffer.getvalue().splitlines()
        self.assertEqual(len(lines), 8)
        self.assertEqual(len(set(lines)), 8)
        for line, pin in zip(lines, current.PINS):
            url, name, size, sha, aid = line.split("\t")
            self.assertEqual(url, current.original_url(pin))
            self.assertEqual((name, int(size), sha, int(aid)),
                             (pin[7], pin[8], pin[9], pin[6]))
            self.assertTrue(url.startswith("https://github.com/"))
            self.assertEqual(len(sha), 64)

    def test_genuine_catalog_pilot_identity_and_four_windows_majors(self):
        self.assertEqual(current.PILOT_RUN, 42836398873)
        self.assertEqual(current.PILOT_SHA,
                         "9442cb0f9fb703a9431691514248f93b93f62f7c")
        self.assertEqual(current.PILOT_SCRIPT_BLOB,
                         "1a6c99db93ee87d756840713fb67b619c271ee3d")
        self.assertEqual(len(current.EXPECTED_JOBS), 4)
        self.assertFalse(any("18" in job for job in current.EXPECTED_JOBS))


if __name__ == "__main__":
    unittest.main()
