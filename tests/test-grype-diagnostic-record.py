#!/usr/bin/env python3
"""Producer Grype diagnostic record: shape, states and policy contract."""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "grype-diagnostic-record.py"
STEM = "pg_bigm-v1.2-20250903-pg18-windows-x64"

spec = importlib.util.spec_from_file_location(
    "grype_policy", ROOT / "scripts" / "automatic-grype-publisher-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def run_script(dist, install, scan):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--dist", str(dist),
         "--install-outcome", install, "--scan-outcome", scan],
        text=True, capture_output=True, check=False)


def make_dist(root, with_report=None):
    dist = root / "dist"
    dist.mkdir()
    (dist / (STEM + ".zip")).write_bytes(b"fixture-zip")
    (dist / (STEM + ".spdx.json")).write_text("{}", encoding="utf-8")
    if with_report is not None:
        (dist / (STEM + ".vulnerabilities.json")).write_text(
            with_report, encoding="utf-8")
    return dist


def read_record(dist):
    return json.loads((dist / (STEM + ".vulnerabilities.json")).read_text("utf-8"))


def check(status, install, scan, with_report=None, label=""):
    with tempfile.TemporaryDirectory(prefix="pgextwin-grype-record-") as tmp:
        dist = make_dist(Path(tmp), with_report)
        result = run_script(dist, install, scan)
        assert result.returncode == 0, \
            f"{label}: script failed {result.returncode}\n{result.stderr}"
        record = read_record(dist)
        assert record["status"] == status, f"{label}: {record['status']} != {status}"
        assert record["matches"] == [], f"{label}: matches not empty"
        # The written record must classify under the audit-side policy.
        verdict = policy.review(record, asset_stem=STEM)
        assert verdict["status"] == status, \
            f"{label}: policy verdict {verdict['status']} != {status}"
        assert verdict["diagnosticRecord"] is True
        assert verdict["publicationAuthorized"] is False


# Installation failed: the scan was never performed.
check("NOT_PERFORMED", "failure", "skipped", label="install failure")
# Scan failed operationally (includes database update/status failures).
check("DIAGNOSTIC_FAILED", "success", "failure", label="scan failure")
# A partial file left by a failed scan is replaced, never trusted.
check("DIAGNOSTIC_FAILED", "success", "failure",
      with_report='{"matches": [', label="scan failure overwrites partial file")
# Scan succeeded but produced no report file.
check("DIAGNOSTIC_FAILED", "success", "success", label="missing report")

# A real report from a successful scan is left byte-identical.
with tempfile.TemporaryDirectory(prefix="pgextwin-grype-record-") as tmp:
    real = '{"matches": [], "descriptor": {"name": "grype"}}'
    dist = make_dist(Path(tmp), with_report=real)
    result = run_script(dist, "success", "success")
    assert result.returncode == 0, result.stderr
    assert (dist / (STEM + ".vulnerabilities.json")).read_text("utf-8") == real

# A broken asset composition is not a diagnostic matter: the script fails.
with tempfile.TemporaryDirectory(prefix="pgextwin-grype-record-") as tmp:
    dist = make_dist(Path(tmp))
    (dist / "other.zip").write_bytes(b"extra")
    result = run_script(dist, "failure", "skipped")
    assert result.returncode == 1, "two ZIPs must fail"

print("Grype diagnostic record regression tests passed.")
