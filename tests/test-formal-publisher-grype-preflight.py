#!/usr/bin/env python3
"""Hostile offline compatibility tests: frozen legacy Publisher remains untouched."""
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "formal_legacy_grype_guard", ROOT / "scripts" / "formal-publisher-grype-preflight.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def fixture(tmp, name="pg_ivm"):
    ext = {"schemaVersion": 1, "name": name,
           "upstream": {"repository": gate.identity.UPSTREAMS[name],
                        "ref": "v1.2-20250903" if name == "pg_bigm" else "v1.0",
                        "version": "1.2" if name == "pg_bigm" else "1.0",
                        "commit": "b" * 40},
           "postgresql": {"majors": [14, 15, 16, 17, 18]}}
    lifecycle = {"schemaVersion": 1, "postgresql": [
        {"major": i, "eol": "2035-12-31"} for i in range(14, 19)]}
    folder = Path(tmp)
    for major in range(14, 19):
        stem = gate.identity.asset_stem(ext, major)
        zip_path = folder / (stem + ".zip")
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("PACKAGE-INFO.json", json.dumps({
                "package": {"name": name}, "postgresql": {"major": major}}))
        (folder / (stem + ".spdx.json")).write_text(json.dumps({
            "spdxVersion": "SPDX-2.3", "packages": [{
                "name": stem, "checksums": [{
                    "algorithm": "SHA256", "checksumValue": gate.sha256(zip_path)}]}]}))
        (folder / (stem + ".vulnerabilities.json")).write_text(json.dumps({
            "matches": [], "ignoredMatches": [],
            "descriptor": {"name": "grype", "version": "0.120.1",
                "db": {"status": {"valid": True, "schemaVersion": "v6",
                                  "built": "2026-10-23", "from": "2026-10-23"},
                       "providers": {"nvd": {}}},
                "configuration": {"match-upstream-kernel-headers": True,
                                  "ignore": [], "fail-on-severity": ""}},
            "source": {"type": "file", "target": stem}}))
    return ext, lifecycle, folder


class LegacyPublisherGuardTests(unittest.TestCase):
    def test_clean_covers_all_17_without_pub_receipt_or_side_effect(self):
        with TemporaryDirectory() as d:
            for name in sorted(gate.identity.UPSTREAMS):
                with self.subTest(name=name):
                    root = Path(d) / name
                    root.mkdir()
                    ext, lifecycle, folder = fixture(root, name)
                    result = gate.verify(folder, ext, lifecycle)
                    self.assertEqual(set(result), {str(i) for i in range(14, 19)})
                    for item in result.values():
                        self.assertEqual(item["grypeDiagnostic"]["status"],
                                         "FINDINGS_RECORDED")
                        self.assertEqual(
                            item["grypeDiagnostic"]["blockingFindingCount"], 0)
                        self.assertNotIn("publicationAuthorized", item)
                        self.assertNotIn("publishableReceipt", item)
                        self.assertNotIn("authorizationMode", item)

    def test_blocking_severities_are_recorded_not_denied(self):
        # E3 PR3 decision (a): Critical/High/Unknown findings are recorded as
        # diagnostics and never deny the legacy Publisher guard.
        with TemporaryDirectory() as d:
            ext, lifecycle, folder = fixture(d)
            stem = gate.identity.asset_stem(ext, 18)
            p = folder / (stem + ".vulnerabilities.json")
            good = json.loads(p.read_text())
            for severity in ("Critical", "High", "Unknown"):
                with self.subTest(severity=severity):
                    report = json.loads(json.dumps(good))
                    report["matches"] = [{
                        "vulnerability": {"id": "CVE-test", "severity": severity},
                        "artifact": {"name": "module.dll"},
                        "matchDetails": [{"matcher": "dpkg"}]}]
                    p.write_text(json.dumps(report))
                    result = gate.verify(folder, ext, lifecycle)
                    diagnostic = result["18"]["grypeDiagnostic"]
                    self.assertEqual(diagnostic["status"], "FINDINGS_RECORDED")
                    self.assertEqual(diagnostic["blockingFindingCount"], 1)
                    self.assertEqual(
                        diagnostic["findingCountBySeverity"][severity], 1)

    def test_invalid_grype_report_is_recorded_as_diagnostic_failure(self):
        # E3 PR3 decision (b): a malformed/filtered/DB-invalid report is a
        # recorded diagnostic failure, never a clean scan and never a denial
        # of the separate ZIP/SPDX contracts.
        with TemporaryDirectory() as d:
            ext, lifecycle, folder = fixture(d)
            stem = gate.identity.asset_stem(ext, 14)
            p = folder / (stem + ".vulnerabilities.json")
            clean = json.loads(p.read_text())
            mutations = (
                lambda r: r.pop("matches"),
                lambda r: r.update(ignoredMatches=[{"vulnerability": {"severity": "High"}}]),
                lambda r: r["descriptor"]["db"]["status"].update(valid=False),
                lambda r: r["descriptor"].update(version="floating"),
                lambda r: r["descriptor"]["configuration"].update(ignore=[{"name": "z"}]),
                lambda r: r["source"].update(target="spoofed"),
                lambda r: r.update(matches=[{}]),
            )
            for i, change in enumerate(mutations):
                with self.subTest(i=i):
                    item = json.loads(json.dumps(clean))
                    change(item)
                    p.write_text(json.dumps(item))
                    result = gate.verify(folder, ext, lifecycle)
                    diagnostic = result["14"]["grypeDiagnostic"]
                    self.assertEqual(diagnostic["status"], "DIAGNOSTIC_FAILED")
                    self.assertIsNone(diagnostic["blockingFindingCount"])
                    self.assertEqual(result["15"]["grypeDiagnostic"]["status"],
                                     "FINDINGS_RECORDED")

    def test_spdx_zip_bytes_and_directory_completeness_fail_closed(self):
        with TemporaryDirectory() as d:
            ext, lifecycle, folder = fixture(d)
            stem = gate.identity.asset_stem(ext, 16)
            spdx_path = folder / (stem + ".spdx.json")
            clean = spdx_path.read_text()
            document = json.loads(clean)
            document["packages"][0]["checksums"][0]["checksumValue"] = "a" * 64
            spdx_path.write_text(json.dumps(document))
            with self.assertRaises(gate.Denied):
                gate.verify(folder, ext, lifecycle)
            spdx_path.write_text(clean)
            with (folder / (stem + ".zip")).open("ab") as stream:
                stream.write(b"untrusted appended content")
            with self.assertRaises(gate.Denied):
                gate.verify(folder, ext, lifecycle)
            (folder / "unexpected.txt").write_text("x")
            with self.assertRaises(gate.Denied):
                gate.verify(folder, ext, lifecycle)

    def test_grype_anomalies_recorded_but_missing_core_assets_denied(self):
        # E3 PR3 decisions (b)/(c): duplicate-key or missing Grype reports are
        # recorded diagnostics, not denials. A missing ZIP (a separate K2
        # contract asset) still fails closed.
        with TemporaryDirectory() as d:
            ext, lifecycle, folder = fixture(d)
            stem = gate.identity.asset_stem(ext, 17)
            p = folder / (stem + ".vulnerabilities.json")
            p.write_text('{"matches":[],"matches":[]}')
            result = gate.verify(folder, ext, lifecycle)
            self.assertEqual(result["17"]["grypeDiagnostic"]["status"],
                             "DIAGNOSTIC_FAILED")
            p.unlink()
            result = gate.verify(folder, ext, lifecycle)
            self.assertEqual(result["17"]["grypeDiagnostic"]["status"],
                             "NOT_PERFORMED")
            self.assertIsNone(result["17"]["grypeSha256"])
            (folder / (stem + ".zip")).unlink()
            with self.assertRaises(gate.Denied):
                gate.verify(folder, ext, lifecycle)

    def test_expired_pg14_not_released_with_historical_artifact_set(self):
        with TemporaryDirectory() as d:
            ext, lifecycle, folder = fixture(d)
            lifecycle["postgresql"][0]["eol"] = "2020-01-01"
            with self.assertRaises(gate.Denied):
                gate.verify(folder, ext, lifecycle)


if __name__ == "__main__":
    unittest.main()
