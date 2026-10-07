#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
from update_watch_lib import WatchError, detect_extension_update, github_get_json, utc_now

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--extension-config", required=True)
    p.add_argument("--watch-config", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--watcher-repository", required=True)
    p.add_argument("--watcher-sha", required=True)
    args = p.parse_args()
    output = Path(args.output)
    try:
        extension = json.loads(Path(args.extension_config).read_text(encoding="utf-8"))
        watch = json.loads(Path(args.watch_config).read_text(encoding="utf-8"))
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        result = detect_extension_update(
            extension, watch, lambda url: github_get_json(url, token), utc_now(),
            args.watcher_repository, args.watcher_sha,
        )
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (WatchError, OSError, json.JSONDecodeError, ValueError) as exc:
        failure = {"schemaVersion":1,"kind":"extension-upstream","status":"indeterminate","error":str(exc),"detectedAt":utc_now(),"watcher":{"repository":args.watcher_repository,"sha":args.watcher_sha}}
        output.write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
        print(f"Update detection failed: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
