#!/usr/bin/env python3
"""Compare Windows package names, ZIP paths, payload bytes and verified license identities."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def entries(archive):
    by_name = {}
    casefolded = set()
    for entry in archive.infolist():
        name = entry.filename
        parts = name.rstrip("/").split("/")
        if (
            entry.orig_filename != name
            or "\\" in name
            or ":" in name
            or any(part in ("", ".", "..") or part.endswith((" ", ".")) for part in parts)
            or name.rstrip("/").casefold() in casefolded
        ):
            raise ValueError(f"Invalid or duplicate ZIP path: {name!r}")
        casefolded.add(name.rstrip("/").casefold())
        by_name[name] = entry
    return by_name


def identical(before, after, before_entry, after_entry):
    if before_entry.file_size != after_entry.file_size:
        return False
    with before.open(before_entry) as left, after.open(after_entry) as right:
        while chunk := left.read(1024 * 1024):
            if chunk != right.read(len(chunk)):
                return False
        return not right.read(1)


def inventory(archive, items):
    result = {}
    for name, entry in items.items():
        with archive.open(entry) as stream:
            result[name] = {"size": entry.file_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
    return result


def compare(args, report):
    differences = report["differences"]
    if args.before.name != args.after.name:
        differences.append("ZIP asset names differ.")
    with zipfile.ZipFile(args.before) as before, zipfile.ZipFile(args.after) as after:
        left = entries(before)
        right = entries(after)
        before_report, after_report = report["before"], report["after"]
        before_report["entries"] = inventory(before, left)
        after_report["entries"] = inventory(after, right)
        for name in sorted(left.keys() - right.keys()):
            differences.append(f"Missing from after: {name}")
        for name in sorted(right.keys() - left.keys()):
            differences.append(f"Added to after: {name}")
        for name in sorted(left.keys() & right.keys()):
            if not identical(before, after, left[name], right[name]):
                differences.append(f"Changed entry bytes: {name}")

    licenses = json.loads(args.licenses.read_bytes())
    if licenses["schemaVersion"] != 1 or not licenses["licenses"]:
        raise ValueError("Expected a nonempty, versioned verified license list.")
    report["verifiedLicenses"] = licenses
    seen = set()
    for license_info in licenses["licenses"]:
        name = license_info["zipPath"]
        if name.casefold() in seen:
            raise ValueError(f"Duplicate verified license ZIP path: {name}")
        seen.add(name.casefold())
        expected = {field: license_info[field] for field in ("size", "sha256")}
        for side in ("before", "after"):
            if report[side]["entries"].get(name) != expected:
                differences.append(f"{side}: license {name} differs from verified upstream blob.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "licenses", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    report = {"schemaVersion": 1, "before": {}, "after": {}, "differences": []}
    try:
        for side in ("before", "after"):
            path = getattr(args, side)
            with path.open("rb") as stream:
                report[side].update(name=path.name, size=path.stat().st_size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())
        compare(args, report)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, zipfile.BadZipFile) as error:
        report["differences"].append(str(error))
    report["equivalent"] = not report["differences"]
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for diff in report["differences"]:
        print(diff, file=sys.stderr)
    return 0 if report["equivalent"] else 1


if __name__ == "__main__":
    sys.exit(main())
