#!/usr/bin/env python3
"""Record a build Issue #311 owner promotion request with resolved evidence."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent

spec = importlib.util.spec_from_file_location("publisher_trigger_auth", ROOT / "publisher-trigger-auth.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
spec = importlib.util.spec_from_file_location("promotion_run_resolver", ROOT / "promotion-run-resolver.py")
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)

COMMAND = re.compile(r"/pgextwin promote (pgextwin/[a-z][a-z0-9_]*) ([1-9][0-9]*) (\S+)")


def confirm(env, github, *, lifecycle=None):
    comment = auth.owner_issue_comment(env)
    body = comment.get("body")
    command = COMMAND.fullmatch(body) if isinstance(body, str) else None
    auth.need(command is not None, "expected /pgextwin promote <repository> <candidate-pr> <release-tag>")
    repository, candidate_pr, tag = command.groups()
    auth.need(resolver.gate.ident.TAG_NAME.fullmatch(tag), "invalid formal Windows Release tag")

    comment_id = comment["id"]
    created = comment.get("created_at")
    auth.need(isinstance(created, str) and created and created == comment.get("updated_at"),
              "edited owner promotion request")
    evidence = resolver.resolve(repository, int(candidate_pr), github=github,
                                lifecycle=lifecycle, release_tag=tag)

    live = github.json(f"repos/pgextwin/build/issues/comments/{comment_id}",
                       "{id,body,issue_url,created_at,updated_at,user:(.user | {login,id,type})}")
    auth.need(live.get("id") == comment_id and auth.owner(live.get("user"))
              and live.get("body") == body and live.get("issue_url") == comment["issue_url"]
              and live.get("created_at") == live.get("updated_at") == created,
              "current owner promotion comment changed")

    return {
        "schemaVersion": 1,
        "status": "RESOLVED_OWNER_PROMOTION_REQUEST",
        "publication": "DENY",
        **evidence,
        "releaseTag": tag,
        "ownerComment": {
            "id": comment_id,
            "url": f"https://github.com/pgextwin/build/issues/311#issuecomment-{comment_id}",
            "body": body,
            "author": auth.OWNER,
            "createdAt": created,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = confirm(os.environ, resolver.GitHub())
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        summary = (
            "### Owner promotion request recorded\n\n"
            f"- Repository `{record['repository']}`\n"
            f"- Candidate PR #{record['candidatePr']}\n"
            f"- Release tag `{record['releaseTag']}`\n"
            f"- Candidate Run `{record['candidateRunId']}`\n"
            f"- Decision Run `{record['decisionRunId']}`\n"
            f"- [Owner confirmation]({record['ownerComment']['url']})\n"
            "- Publication DENY\n"
        )
        with args.summary.open("a", encoding="utf-8") as stream:
            stream.write(summary)
        return 0
    except resolver.INPUT_ERRORS as error:
        print(f"OWNER PROMOTION REQUEST DENY: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
