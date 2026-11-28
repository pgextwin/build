#!/usr/bin/env python3
"""Authenticate the central caller and bind its run to a nonpublishing intent."""

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.request import urlopen

REPOSITORY = "pgextwin/build"
REPO_URI = f"https://github.com/{REPOSITORY}"
CALLER = ".github/workflows/central-signed-main.yml"
REUSABLE = ".github/workflows/central-extension-attested.yml"
REF = "refs/heads/main"
CONFIG_URI = f"{REPO_URI}/{CALLER}@{REF}"
INTENT_NAME = "central-signed-main-intent.json"
ARTIFACT_NAME = "central-signed-main-intent-nonpublishing"
CENTRAL_AUTHENTIC_EVENTS = {"schedule", "issue_comment"}
CRON = "23 3 * * *"
OWNER = "ShutenOishi"
OWNER_ID = 27071164
NAME = r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"
SHA = r"[0-9a-f]{40}"
DIGEST = r"[0-9a-f]{64}"
INVALID_INTENT = "AUTH_INTENT_MISSING_OR_INVALID"
BAD_SHA = "AUTH_SHA_CONFLICT_4SHA"
BAD_TARGET = "AUTH_TARGET_NOT_ADMITTED"
FIXED_FIELDS = {
    "schema_version": 1,
    "mode": "m1-central-live-signing-nonpublishing",
    "repository": REPOSITORY,
    "caller_workflow_path": CALLER,
    "reusable_workflow_path": REUSABLE,
    "head_ref": REF,
}
INTENT_FIELDS = FIXED_FIELDS.keys() | {
    "reusable_pin_sha", "authentic_event", "actor_login", "head_sha", "run_id",
    "run_attempt", "run_invocation_uri", "extension_name", "extension_source_sha",
    "upstream_tarball_sha256", "issue_comment_id", "publishing_allowed",
}
RUNTIME_INPUTS = {
    "M1_EXTENSION": "extension_name",
    "M1_EXTENSION_SOURCE_SHA": "extension_source_sha",
    "M1_PACKAGING_SHA": "head_sha",
    "M1_REUSABLE_PIN_SHA": "reusable_pin_sha",
    "M1_UPSTREAM_TARBALL_SHA256": "upstream_tarball_sha256",
    "M1_CALLER_RUN_ID": "run_id",
    "M1_CALLER_RUN_ATTEMPT": "run_attempt",
    "M1_CALLER_EVENT": "authentic_event",
}


class Denied(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(detail)
        self.code = code


def require(condition, code, detail=""):
    if not condition:
        raise Denied(code, detail)


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY", key)
        result[key] = value
    return result


def parse_json(text):
    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    return json.loads(text, object_pairs_hook=unique_keys, parse_constant=invalid_constant)


def read_json(path, code):
    try:
        return parse_json(Path(path).read_text(encoding="utf-8"))
    except (ValueError, OSError, TypeError) as error:
        raise Denied(code, str(error)) from error


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def run_uri(run_id, attempt):
    return f"{REPO_URI}/actions/runs/{run_id}/attempts/{attempt}"


def signer_uri(pin):
    return f"{REPO_URI}/{REUSABLE}@{pin}"


def verify_trigger(env, event_path=None):
    event = env.get("GITHUB_EVENT_NAME")
    require(event in CENTRAL_AUTHENTIC_EVENTS, "AUTH_EVENT_NOT_ALLOWED")
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY, "AUTH_REPO_MISMATCH")
    require(env.get("GITHUB_REF") == REF, "AUTH_REF_NOT_MAIN")
    require(env.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{CALLER}@{REF}",
            "AUTH_CALLER_WORKFLOW_MISMATCH")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1", "AUTH_RUN_ATTEMPT_MISMATCH")
    head_sha = env.get("GITHUB_SHA")
    require(matches(SHA, head_sha) and env.get("GITHUB_WORKFLOW_SHA") == head_sha, BAD_SHA)
    run = env.get("GITHUB_RUN_ID")
    require(matches(r"[1-9][0-9]{0,18}", run), "AUTH_RUN_ID_MISMATCH")
    actor = env.get("GITHUB_ACTOR")
    require(matches(r"[A-Za-z0-9_-]+(?:\[bot\])?", actor), "AUTH_ACTOR_INVALID")
    event_file = env.get("GITHUB_EVENT_PATH")
    require(bool(event_file), "AUTH_EVENT_PAYLOAD_INVALID")
    require(event_path is None or event_path.resolve() == Path(event_file).resolve(),
            "AUTH_EVENT_PAYLOAD_MISMATCH")
    payload = object_or_empty(read_json(event_file, "AUTH_EVENT_PAYLOAD_INVALID"))
    comment_id = None
    target = None

    if event == "schedule":
        require(payload.get("schedule") == CRON, "AUTH_SCHEDULE_NOT_ALLOWED")
        if "repository" in payload:
            require(object_or_empty(payload["repository"]).get("full_name") == REPOSITORY,
                    "AUTH_REPO_MISMATCH")
    else:
        require(object_or_empty(payload.get("repository")).get("full_name") == REPOSITORY,
                "AUTH_REPO_MISMATCH")
        issue = object_or_empty(payload.get("issue"))
        require(type(issue.get("number")) is int and issue["number"] == 311
                and "pull_request" not in issue, "AUTH_ISSUE_NOT_CENTRAL_311")
        comment = object_or_empty(payload.get("comment"))
        user = object_or_empty(comment.get("user"))
        require(actor == OWNER and env.get("GITHUB_ACTOR_ID") == str(OWNER_ID)
                and user.get("login") == OWNER and type(user.get("id")) is int
                and user["id"] == OWNER_ID and user.get("type") == "User"
                and comment.get("author_association") == "OWNER", "AUTH_ACTOR_NOT_OWNER")
        comment_id = comment.get("id")
        require(payload.get("action") == "created" and type(comment_id) is int and comment_id > 0,
                "AUTH_EVENT_PAYLOAD_INVALID")
        body = comment.get("body")
        require(matches(rf"/pgextwin sign-main {NAME}", body), "AUTH_COMMAND_INVALID")
        target = body.rsplit(" ", 1)[1]

    return {
        "authentic_event": event, "actor_login": actor, "head_sha": head_sha,
        "run_id": int(run), "run_attempt": 1, "run_invocation_uri": run_uri(run, 1),
        "issue_comment_id": comment_id,
    }, target


def validate_intent(intent):
    require(isinstance(intent, dict) and intent.keys() == INTENT_FIELDS, INVALID_INTENT)
    require(all(type(intent[key]) is type(value) and intent[key] == value
                for key, value in FIXED_FIELDS.items()), INVALID_INTENT)
    require(intent["publishing_allowed"] is False, "AUTH_PUBLISHING_FORBIDDEN")
    require(matches(NAME, intent["extension_name"]), INVALID_INTENT)
    require(all(matches(SHA, intent[key]) for key in
                ("head_sha", "reusable_pin_sha", "extension_source_sha"))
            and matches(DIGEST, intent["upstream_tarball_sha256"]), BAD_SHA)
    require(type(intent["run_id"]) is int and intent["run_id"] > 0, "AUTH_RUN_ID_MISMATCH")
    require(type(intent["run_attempt"]) is int and intent["run_attempt"] == 1,
            "AUTH_RUN_ATTEMPT_MISMATCH")
    require(intent["run_invocation_uri"] == run_uri(intent["run_id"], 1),
            "AUTH_RUN_ID_MISMATCH")
    event = intent["authentic_event"]
    require(isinstance(event, str) and event in CENTRAL_AUTHENTIC_EVENTS, "AUTH_EVENT_NOT_ALLOWED")
    require(matches(r"[A-Za-z0-9_-]+(?:\[bot\])?", intent["actor_login"]), INVALID_INTENT)
    comment_id = intent["issue_comment_id"]
    if event == "issue_comment":
        require(intent["actor_login"] == OWNER and type(comment_id) is int and comment_id > 0,
                "AUTH_ACTOR_NOT_OWNER")
    else:
        require(comment_id is None, INVALID_INTENT)
    return intent


def load_intent(path):
    return validate_intent(read_json(path, INVALID_INTENT))


def read_caller_pin(root):
    workflow = (root / CALLER).read_text(encoding="utf-8")
    pins = re.findall(rf"^    uses: {re.escape(REPOSITORY + '/' + REUSABLE)}@({SHA})$",
                      workflow, re.MULTILINE)
    require(len(pins) == 1, BAD_SHA, "Expected one fixed reusable signer in caller")
    return pins[0]


def verify_runtime(intent, env, event_path=None):
    run, requested = verify_trigger(env, event_path)
    for key, value in run.items():
        code = {
            "run_id": "AUTH_RUN_ID_MISMATCH",
            "run_attempt": "AUTH_RUN_ATTEMPT_MISMATCH",
            "run_invocation_uri": "AUTH_RUN_ID_MISMATCH",
            "head_sha": BAD_SHA,
        }.get(key, "AUTH_EVENT_PAYLOAD_MISMATCH")
        require(intent[key] == value, code, key)
    require(requested is None or intent["extension_name"] == requested, BAD_TARGET)
    for name, key in RUNTIME_INPUTS.items():
        code = (
            BAD_SHA if key.endswith(("sha", "sha256"))
            else "AUTH_RUN_ID_MISMATCH" if key == "run_id"
            else "AUTH_RUN_ATTEMPT_MISMATCH" if key == "run_attempt"
            else INVALID_INTENT
        )
        require(env.get(name) == str(intent[key]), code, key)
    pin = intent["reusable_pin_sha"]
    require(env.get("M1_JOB_WORKFLOW_SHA") == pin
            and env.get("M1_JOB_WORKFLOW_REPOSITORY") == REPOSITORY, BAD_SHA)
    require(env.get("M1_SIGNER_URI") == signer_uri(pin)
            and env.get("M1_BUILD_CONFIG_URI") == CONFIG_URI
            and env.get("M1_AUTH_ARTIFACT") == ARTIFACT_NAME, INVALID_INTENT)


def git(root, *args):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(root), *args], encoding="utf-8",
    ).strip()


def declared_extensions(root):
    paths = git(root, "ls-tree", "-r", "--name-only", "HEAD", "--", "extensions").splitlines()
    return sorted({path.split("/")[1] for path in paths
                   if re.fullmatch(rf"extensions/{NAME}/extension\.json", path)})


def extension_source(root, extension):
    return git(root, "log", "--first-parent", "-1", "--format=%H", "HEAD", "--",
               f"extensions/{extension}")


def extension_dir(root, name):
    require(matches(NAME, name) and not (root / "extensions").is_symlink(), BAD_TARGET)
    path = root / "extensions" / name
    central = importlib.import_module("central-extension")
    errors = central.validate_extension_dir(path)
    require(not errors, BAD_TARGET, "; ".join(errors))
    return path


def upstream_digest(repository, commit):
    require(matches(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            and all(part not in {".", ".."} for part in repository.split("/"))
            and matches(SHA, commit), BAD_TARGET)
    with urlopen(f"https://codeload.github.com/{repository}/tar.gz/{commit}", timeout=60) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def matrix_rows(root, manifest):
    # resolve-matrix.ps1 uses the Actions output format. Give each invocation
    # a private output file so extension-controlled values never set job outputs.
    with TemporaryDirectory() as tmp:
        output = Path(tmp) / "matrix"
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(root / "scripts/resolve-matrix.ps1"),
             "-ExtensionConfigPath", str(manifest), "-PostgreSqlConfigPath",
             str(root / "metadata/postgresql.json")],
            env={**os.environ, "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True,
            check=False,
        )
        require(result.returncode == 0, BAD_TARGET, result.stderr)
        fields = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
                      if "=" in line)
        require(fields["verify_upstream_license"] == "true", BAD_TARGET, "K4 is required")
        return parse_json(fields["matrix"])["include"]


def emit_intents(root, directory, env):
    run, requested = verify_trigger(env)
    require(git(root, "rev-parse", "HEAD") == run["head_sha"], BAD_SHA)
    names = declared_extensions(root)
    if requested is not None:
        require(requested in names, BAD_TARGET)
        names = [requested]
    require(len({name.casefold() for name in names}) == len(names),
            BAD_TARGET, "Extension names collide on Windows")
    pin = read_caller_pin(root)
    targets = []
    digests = {}
    for name in names:
        ext = extension_dir(root, name)
        source = extension_source(root, name)
        declaration = read_json(ext / "extension.json", BAD_TARGET)
        upstream = declaration["upstream"]["repository"]
        for row in matrix_rows(root, ext / "extension.json"):
            major = row["major"]
            key = upstream, row["upstreamCommit"]
            if key not in digests:
                digests[key] = upstream_digest(*key)
            intent = validate_intent({
                **FIXED_FIELDS, **run, "reusable_pin_sha": pin, "extension_name": name,
                "extension_source_sha": source, "upstream_tarball_sha256": digests[key],
                "publishing_allowed": False,
            })
            target_dir = directory / name / str(major)
            target_dir.mkdir(parents=True)
            write_json(target_dir / INTENT_NAME, intent)
            targets.append({
                "extension": name, "major": major, "extension_source_sha": source,
                "upstream_tarball_sha256": digests[key],
            })
    return {
        "has_targets": json.dumps(bool(targets)),
        "matrix": json.dumps({"include": targets}, separators=(",", ":")),
        "reusable_pin_sha": pin,
        "signer_uri": signer_uri(pin),
        "build_config_uri": CONFIG_URI,
        "auth_artifact_name": ARTIFACT_NAME,
    }


def verify_build_source(root, intent, major):
    require(git(root, "rev-parse", "HEAD") == intent["head_sha"]
            and read_caller_pin(root) == intent["reusable_pin_sha"]
            and extension_source(root, intent["extension_name"]) == intent["extension_source_sha"],
            BAD_SHA)
    path = f'extensions/{intent["extension_name"]}/extension.json'
    declaration = parse_json(git(root, "cat-file", "blob", f"HEAD:{path}"))
    require(object_or_empty(declaration).get("name") == intent["extension_name"], BAD_TARGET)
    package = importlib.import_module("central-package")
    commit = package.declared_upstream_commit(declaration, major)
    repo = declaration["upstream"]["repository"]
    require(upstream_digest(repo, commit) == intent["upstream_tarball_sha256"], BAD_SHA,
            "Pinned upstream archive SHA-256 differs from the intent")
    return {"upstream_repository": repo, "upstream_commit": commit}


def verify_finalizer(args, intent, env):
    verify_runtime(intent, env, args.event)
    for key, value in {
        "repository": args.repository, "extension_name": args.extension,
        "authentic_event": args.workflow_event, "head_ref": args.ref,
        "run_id": args.run_id, "run_attempt": args.run_attempt,
        "head_sha": args.packaging_sha, "reusable_pin_sha": args.reusable_pin_sha,
        "reusable_workflow_path": args.reusable_workflow,
    }.items():
        require(intent[key] == value, INVALID_INTENT, key)
    require(f"{args.run_url}/attempts/{args.run_attempt}" == intent["run_invocation_uri"],
            "AUTH_RUN_ID_MISMATCH")


def outputs(env, fields):
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        for key, value in fields.items():
            require("\n" not in value and "\r" not in value, INVALID_INTENT, key)
            stream.write(f"{key}={value}\n")


def report_error(error, default):
    print(json.dumps({"error_code": getattr(error, "code", default), "detail": str(error)}),
          file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ("verify-trigger", "emit-intent", "verify-intent", "verify-finalizer"):
        modes.add_argument(f"--{name}", action="store_true")
    parser.add_argument("--event", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--intent-dir", type=Path)
    parser.add_argument("--intent", type=Path)
    parser.add_argument("--postgresql-major", type=int)
    for name in ("repository", "extension", "workflow-event", "ref", "packaging-sha",
                 "reusable-pin-sha", "reusable-workflow", "run-url"):
        parser.add_argument(f"--{name}")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    args = parser.parse_args()

    try:
        if args.verify_trigger:
            verify_trigger(os.environ, args.event)
        elif args.emit_intent:
            outputs(os.environ, emit_intents(args.root.resolve(), args.intent_dir, os.environ))
        else:
            require(matches(NAME, os.environ.get("M1_EXTENSION"))
                    and matches(r"[1-9][0-9]*", os.environ.get("M1_MAJOR")), BAD_TARGET)
            intent = load_intent(args.intent)
            if args.verify_finalizer:
                verify_finalizer(args, intent, os.environ)
            else:
                verify_runtime(intent, os.environ, args.event)
                if args.postgresql_major is not None:
                    require(str(args.postgresql_major) == os.environ["M1_MAJOR"], BAD_TARGET)
                    outputs(os.environ, verify_build_source(args.root.resolve(), intent,
                                                            args.postgresql_major))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        return report_error(error, INVALID_INTENT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
