#!/usr/bin/env python3
"""Offline PG14-18 timing parser regression tests."""
import importlib.util
from pathlib import Path

p = Path(__file__).resolve().parents[1] / "scripts/report-edb-install-timing.py"
spec = importlib.util.spec_from_file_location("edb_timing", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fixture(pg, download=4, verify=5, install=130, retry=False):
    from datetime import datetime, timedelta, timezone
    t = datetime(2026, 10, 15, tzinfo=timezone.utc)
    def line(sec, msg):
        return (t + timedelta(seconds=sec)).isoformat(timespec="milliseconds").replace("+00:00", "Z") + " " + msg
    lines = [line(0, f"Installing postgresql{pg} version 17.11.4 (attempt 1/3)."),
             line(10, f"Downloading postgresql{pg} 64 bit"),
             line(10 + download, f"Download of postgresql-{pg}.11-4-windows-x64.exe (391 MB) completed."),
             line(10 + download + verify, "Hashes match."),
             line(11 + download + verify, f"Installing postgresql{pg}..."),
             line(11 + download + verify + install, f"postgresql{pg} has been installed.")]
    if retry:
        lines.insert(1, line(1, f"Installing postgresql{pg} version 17.11.4 (attempt 2/3)."))
    return "\n".join(lines)


for major in range(14, 19):
    result = mod.analyze(fixture(major), major)
    assert result["attempts"] == 1, result
    assert result["phases"]["download_seconds"] == 4, result
    assert result["phases"]["verification_seconds"] == 5, result
    assert result["phases"]["installer_seconds"] == 130, result
    assert result["phases"]["total_phase_seconds"] == 140, result

assert mod.analyze(fixture(17, download=644), 17)["phases"]["download_seconds"] == 644
assert all(v == "UNKNOWN" for v in mod.analyze(fixture(17, retry=True), 17)["phases"].values())
assert all(v == "UNKNOWN" for v in mod.analyze("", 17)["phases"].values())
assert mod.analyze(fixture(17).replace("Hashes match.", "Hash missing"), 17)["phases"]["verification_seconds"] == "UNKNOWN"
assert mod.analyze(fixture(17).replace("Downloading postgresql17 64 bit", "Downloading postgresql17 64 bit\n2026-10-15T00:00:00Z Downloading postgresql17 64 bit"), 17)["phases"]["download_seconds"] == "UNKNOWN"
assert mod.analyze(fixture(17).replace("2026-10-15T00:00:10.000Z", "2026-10-15T00:00:30.000Z"), 17)["phases"]["download_seconds"] == "UNKNOWN"
assert mod.analyze("not-a-timestamp Downloading postgresql17 64 bit", 17)["phases"]["download_seconds"] == "UNKNOWN"
print("PASS: PG14-18, retry, missing/ambiguous markers, timestamps, PG17 slow download")
