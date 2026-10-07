#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re, sys
from jsonschema import Draft202012Validator
from pathlib import Path
from update_watch_lib import WatchError, validate_watch_semantics

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--extension-config", required=True)
    p.add_argument("--watch-config", required=True)
    p.add_argument("--schema", required=True)
    args=p.parse_args()
    try:
        extension=json.loads(Path(args.extension_config).read_text(encoding="utf-8"))
        watch=json.loads(Path(args.watch_config).read_text(encoding="utf-8"))
        schema=json.loads(Path(args.schema).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(watch)
        if watch.get("schemaVersion") != 1:
            raise WatchError("schemaVersion must be 1")
        if watch.get("strategy") not in {"github-releases","github-tags","github-releases-per-postgresql"}:
            raise WatchError("unsupported strategy")
        if "stableTagPattern" in watch:
            re.compile(watch["stableTagPattern"])
        for rule in (watch.get("perPostgresql") or {}).values():
            re.compile(rule["tagPattern"])
        validate_watch_semantics(extension, watch)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, re.error, WatchError) as exc:
        print(f"Update watch contract validation failed: {exc}", file=sys.stderr)
        return 1
    print("Update watch contract validation passed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
