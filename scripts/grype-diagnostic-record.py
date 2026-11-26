#!/usr/bin/env python3
"""Materialize a Grype diagnostic record when the producer scan made no report.

E3 PR5 (audit M1): in the signed/unsigned Windows build workflows the Grype
installation and scan steps are diagnostic only. When either step fails, the
release asset set must stay identical to a successful build (ZIP, SPDX SBOM,
vulnerabilities file), so this script writes a diagnostic record into the
report slot instead of letting the job stop. The record states plainly that
no trustworthy scan classification exists for the asset: DIAGNOSTIC_FAILED
when the scan was attempted but failed, NOT_PERFORMED when it never ran.
It is never a claim of safety and carries an empty matches array whose
emptiness means "not classified".

The record shape is the producer half of the contract verified by
automatic-grype-publisher-policy.py (descriptor.diagnosticRecord) and by
validate-vulnerability-report.py. This script grants nothing: it cannot
authorize, sign or publish anything.
"""
import argparse
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"Grype diagnostic record failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write a Grype diagnostic record when no report was produced.")
    parser.add_argument("--dist", default="dist")
    parser.add_argument("--install-outcome", required=True,
                        help="outcome of the Grype installation step")
    parser.add_argument("--scan-outcome", required=True,
                        help="outcome of the Grype scan step")
    parser.add_argument("--expected-scanner-version", default="0.120.1")
    parser.add_argument("--summary-file")
    args = parser.parse_args()

    dist = Path(args.dist)
    if not dist.is_dir():
        fail(f"distribution directory not found: {dist}")
    zips = sorted(dist.glob("*.zip"))
    sboms = sorted(dist.glob("*.spdx.json"))
    if len(zips) != 1:
        fail(f"expected exactly one final ZIP, found {len(zips)}")
    if len(sboms) != 1 or sboms[0].name != zips[0].stem + ".spdx.json":
        fail("expected exactly one SPDX JSON named after the final ZIP")
    stem = zips[0].stem
    report_path = dist / (stem + ".vulnerabilities.json")

    install_ok = args.install_outcome == "success"
    scan_ok = args.scan_outcome == "success"
    if install_ok and scan_ok and report_path.is_file() \
            and report_path.stat().st_size > 0:
        print(f"Grype report present; no diagnostic record needed: {report_path}")
        return

    if not install_ok:
        status = "NOT_PERFORMED"
        detail = ("Grype installation failed; the vulnerability scan was "
                  "not performed for this asset.")
    elif args.scan_outcome == "skipped":
        status = "NOT_PERFORMED"
        detail = ("The Grype scan step did not run; the vulnerability scan "
                  "was not performed for this asset.")
    elif not scan_ok:
        status = "DIAGNOSTIC_FAILED"
        detail = ("Grype scan failed operationally (database update/status "
                  "or scan execution); no trustworthy vulnerability report "
                  "was produced for this asset.")
    else:
        status = "DIAGNOSTIC_FAILED"
        detail = ("Grype scan completed without producing a vulnerability "
                  "report for this asset.")

    record = {
        "matches": [],
        "descriptor": {
            "name": "pgextwin-grype-diagnostic",
            "diagnosticRecord": True,
            "expectedScanner": {"name": "grype",
                                "version": args.expected_scanner_version},
        },
        "source": {"type": "file", "target": stem},
        "status": status,
        "detail": detail,
    }
    report_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"GRYPE_DIAGNOSTIC_RECORD status={status} report={report_path}")
    print(detail)
    if args.summary_file:
        summary = "\n".join([
            "### pgextwin vulnerability scan — diagnostic record",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Diagnostic status | {status} |",
            f"| Detail | {detail} |",
            "",
            "The vulnerability scan produced no report for this asset. "
            "This is a recorded diagnostic state, not a finding of safety: "
            "the empty matches array means the asset was not classified.",
            "",
        ])
        with Path(args.summary_file).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(summary)


if __name__ == "__main__":
    main()
