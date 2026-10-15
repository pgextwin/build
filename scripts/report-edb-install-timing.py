#!/usr/bin/env python3
"""Read-only EDB phase timing from timestamped GitHub Actions job logs.

No installer/Chocolatey behavior is changed. Missing or ambiguous markers => UNKNOWN.
Usage: python scripts/report-edb-install-timing.py <job-log.txt> --major 17
"""
import argparse
import json
import re
from datetime import datetime

MARKERS = {
    "download_start": r"Downloading postgresql{major} 64 bit",
    "download_end": r"Download of postgresql-{major}\\.[^\\r\\n]* completed\\.",
    "verify_end": r"Hashes match\\.",
    "install_start": r"Installing postgresql{major}\\.\\.\\.",
    "install_end": r"postgresql{major} has been installed\\.",
}
STAMP = re.compile(r"^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z)\\s+(.*)$")


def analyze(log: str, major: int) -> dict:
    if major not in range(14, 19):
        raise ValueError("major must be PG14..18")
    matches = {key: [] for key in MARKERS}
    attempts = 0
    for line in log.splitlines():
        match = STAMP.match(line)
        if not match:
            continue
        try:
            stamp = datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
        except ValueError:
            continue
        message = match.group(2)
        if re.search(rf"Installing postgresql{major} version .*\\(attempt \\d+/3\\)", message):
            attempts += 1
        for key, pattern in MARKERS.items():
            if re.search(pattern.format(major=major), message):
                matches[key].append(stamp)

    def elapsed(start: str, end: str):
        a, b = matches[start], matches[end]
        if len(a) != 1 or len(b) != 1 or b[0] < a[0]:
            return None
        return round((b[0] - a[0]).total_seconds(), 3)

    durations = {
        "download_seconds": elapsed("download_start", "download_end"),
        "verification_seconds": elapsed("download_end", "verify_end"),
        "installer_seconds": elapsed("install_start", "install_end"),
        "total_phase_seconds": elapsed("download_start", "install_end"),
    }
    # Multiple attempts invalidate attribution of individual phases.
    if attempts != 1:
        durations = dict.fromkeys(durations)
    return {
        "postgresql_major": major,
        "attempts": attempts,
        "phases": {k: ("UNKNOWN" if v is None else v) for k, v in durations.items()},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("--major", type=int, required=True, choices=range(14, 19))
    args = parser.parse_args()
    with open(args.log, encoding="utf-8-sig", errors="replace") as handle:
        print(json.dumps(analyze(handle.read(), args.major), indent=2))


if __name__ == "__main__":
    main()
