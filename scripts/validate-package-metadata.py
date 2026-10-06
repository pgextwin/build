#!/usr/bin/env python3
import argparse
import json
import sys
import zipfile
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_metadata(args):
    if args.file:
        return load_json(Path(args.file))

    with zipfile.ZipFile(args.zip, "r") as archive:
        matches = [name for name in archive.namelist() if name == "PACKAGE-INFO.json"]
        if len(matches) != 1:
            raise ValueError(
                f"Expected exactly one root PACKAGE-INFO.json in {args.zip}, found {len(matches)}."
            )
        return json.loads(archive.read(matches[0]).decode("utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description="Validate pgextwin PACKAGE-INFO.json.")
    parser.add_argument("--schema", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file")
    source.add_argument("--zip")
    args = parser.parse_args()

    schema = load_json(Path(args.schema))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    try:
        metadata = load_metadata(args)
    except Exception as exc:
        print(f"Package metadata read failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

    errors = sorted(validator.iter_errors(metadata), key=lambda error: list(error.absolute_path))
    if errors:
        print("Package metadata schema validation failed:", file=sys.stderr)
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            print(f"- {location}: {error.message}", file=sys.stderr)
        raise SystemExit(1)

    print("Package metadata schema validation passed.")


if __name__ == "__main__":
    main()
