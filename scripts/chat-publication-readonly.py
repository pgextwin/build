#!/usr/bin/env python3
"""Third-wave PR/push admission observer. GET-only; cannot publish or mint.

Only immutable shared code is executed. Caller files are obtained as exact
GitHub blobs, never checked out or executed. NO_AUTHORIZATION is a harmless
success. Even a valid PUBLISH file remains DENY until the independent #75
production boundary is genuinely accepted in a separate protected change.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("chat_authorization", ROOT / "chat-pr-authorization.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
TARGETS = frozenset({"pgextwin/pgtap", "pgextwin/pg_variables", "pgextwin/pg_store_plans"})
OPERATORS = frozenset({"ShutenOishi"})
PREFIX = ".github/release-authorizations/"
MAX_JSON = 2 * 1024 * 1024


class Denied(ValueError):
    pass


def need(ok):
    if not ok:
        raise Denied("unproven or inconsistent read-only admission evidence")


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Denied("redirect denied")


class Reader:
    """Single-repository, bounded authenticated GET only; 404 is never success."""
    def __init__(self, repository, token, opener=None):
        need(repository in TARGETS and type(token) is str and bool(token))
        self.repository, self._token = repository, token
        self._open = opener or build_opener(NoRedirect()).open

    @staticmethod
    def allowed(path):
        need(type(path) is str and len(path) < 400)
        patterns = (
            r"branches/main", r"actions/runs/[1-9][0-9]*",
            r"pulls/[1-9][0-9]*(?:/files\?per_page=100)?",
            r"commits/[0-9a-f]{40}(?:/pulls\?per_page=100|/check-runs\?per_page=100)?",
            r"contents/\.github/release-authorizations/v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*\.json\?ref=[0-9a-f]{40}",
        )
        need(any(re.fullmatch(p, path) for p in patterns))

    def get(self, path):
        self.allowed(path)
        request = Request("https://api.github.com/repos/" + self.repository + "/" + path,
                          headers={"Authorization": "Bearer " + self._token,
                                   "Accept": "application/vnd.github+json",
                                   "X-GitHub-Api-Version": "2022-11-28"}, method="GET")
        try:
            with self._open(request, timeout=20) as response:
                need(response.status == 200)
                need(not re.search(r'\brel\s*=\s*"?next"?', response.headers.get("Link", ""), re.I))
                raw = response.read(MAX_JSON + 1)
                need(len(raw) <= MAX_JSON)
                return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        except (HTTPError, URLError, OSError, TimeoutError, ValueError, UnicodeError):
            # No exception body, response, header or credential ever escapes.
            raise Denied("GET evidence unavailable") from None


def is_operator(user):
    return (type(user) is dict and user.get("type") == "User"
            and auth.human(user.get("login")) and user["login"] in OPERATORS)


def result(status, **facts):
    return {"schemaVersion": 1, "status": status, **facts,
            "evidenceKind": "AUTHENTICATED_GITHUB_METADATA_ONLY",
            "effectiveClassicProtectionVerified": False,
            "candidateSignaturesVerified": False, "independentWriterVerified": False,
            "publishableReceipt": False, "publicationAuthorized": False,
            "catalogProposalAuthorized": False, "mutationsEnabled": False,
            "publication": "DENY", "goB": "NO_GO", "g4": "NO_GO", "g5": "NO_GO"}


def required_checks(branch, checks, head):
    """Observe App-bound exact-head CI; NOT an effective Classic-rules proof."""
    required = (branch.get("protection") or {}).get("required_status_checks", {}).get("checks")
    need(type(required) is list and bool(required))
    need(type(checks) is dict and type(checks.get("check_runs")) is list)
    need(type(checks.get("total_count")) is int and checks["total_count"] == len(checks["check_runs"]))
    names = []
    for rule in required:
        need(type(rule) is dict and type(rule.get("context")) is str and bool(rule["context"]))
        need(type(rule.get("app_id")) is int and rule["app_id"] == 15368)
        matches = [c for c in checks["check_runs"] if type(c) is dict
                   and c.get("name") == rule["context"] and (c.get("app") or {}).get("id") == 15368]
        need(len(matches) == 1 and matches[0].get("head_sha") == head
             and matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success")
        need(rule["context"] not in names)
        names.append(rule["context"])
    return sorted(names)


def request_format(api, files, repository, head, branch, pr):
    paths = [x for x in files if type(x) is dict and
             (str(x.get("filename", "")).startswith(PREFIX)
              or str(x.get("previous_filename", "")).startswith(PREFIX))]
    if not paths:
        return "NO_AUTHORIZATION"
    need(len(files) == 1 and len(paths) == 1 and paths[0].get("status") == "added")
    path = paths[0]["filename"]
    need(re.fullmatch(re.escape(PREFIX) + r"v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*\.json", path) is not None)
    need(is_operator(pr.get("user")))
    obj = api.get("contents/" + path + "?ref=" + head)
    need(type(obj) is dict and obj.get("type") == "file" and obj.get("path") == path
         and obj.get("encoding") == "base64" and type(obj.get("content")) is str)
    need(type(obj.get("size")) is int and 0 < obj["size"] <= 16384)
    raw = base64.b64decode(obj["content"].replace("\n", ""), validate=True)
    need(len(raw) == obj["size"] and auth.git_blob_sha(raw) == obj.get("sha") == paths[0].get("sha"))
    request = auth.parse_authorization(raw.decode("utf-8"), repository=repository, allowed_operators=OPERATORS)
    need(path == PREFIX + request["releaseTag"] + ".json")
    need(pr["head"].get("ref") == "auth-release/" + request["releaseTag"])
    need(request["packagingMainSha"] == branch and request["operatorLogin"] == pr["user"]["login"])
    # UPDATE is a different operation. No dispatch, build, signature, mint or
    # publisher is called, and no valid typed publication receipt is returned.
    return "VALID_REQUEST_FORMAT_PUBLICATION_DENIED"


def inspect(env, event, api):
    repo, mode, sha = (env.get(k) for k in ("GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_SHA"))
    need(repo in TARGETS and mode in {"pull_request", "push", "workflow_dispatch"} and auth.full_sha(sha))
    need(type(event) is dict and (event.get("repository") or {}).get("full_name") == repo)
    need(re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")) is not None)
    need(env.get("GITHUB_RUN_ATTEMPT") == "1")
    run_id = int(env["GITHUB_RUN_ID"])
    actor = env.get("GITHUB_ACTOR")
    run = api.get("actions/runs/" + str(run_id))
    need(type(run) is dict and type(run.get("id")) is int and run["id"] == run_id
         and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
         and run.get("event") == mode and run.get("path") == ".github/workflows/windows.yml"
         and (run.get("repository") or {}).get("full_name") == repo
         and (run.get("actor") or {}).get("login") == actor
         and (run.get("triggering_actor") or {}).get("login") == actor
         and (event.get("sender") or {}).get("login") == actor)
    branch = api.get("branches/main")
    need(type(branch) is dict and branch.get("protected") is True
         and auth.full_sha((branch.get("commit") or {}).get("sha")))
    main = branch["commit"]["sha"]
    facts = {"repository": repo, "event": mode, "eventSha": sha, "runId": run_id,
             "runAttempt": 1, "actor": actor, "actorIsAllowedHuman": is_operator(run.get("actor")),
             "protectedMainObserved": True, "requiredChecksAppId": 15368}
    if mode == "workflow_dispatch":
        need(env.get("GITHUB_REF") == "refs/heads/main" and run.get("head_sha") == sha == main)
        return result("WINDOWS_DISPATCH_IS_NOT_PUBLICATION_AUTHORIZATION", **facts)
    if mode == "pull_request":
        number = event.get("number")
        need(auth.positive_int(number))
        pr = api.get("pulls/" + str(number))
        head = (pr.get("head") or {}).get("sha")
        need(auth.full_sha(head) and (event.get("pull_request") or {}).get("head", {}).get("sha") == head
             and run.get("head_sha") == head and pr.get("state") == "open"
             and pr.get("number") == number and pr.get("merged") is False)
        need(env.get("GITHUB_REF") == "refs/pull/" + str(number) + "/merge")
        base = (pr.get("base") or {}).get("sha")
    else:
        need(env.get("GITHUB_REF") == "refs/heads/main" and event.get("ref") == "refs/heads/main")
        need(run.get("head_sha") == event.get("after") == sha == main and run.get("head_branch") == "main")
        need(is_operator(run.get("actor")) and is_operator(run.get("triggering_actor"))
             and is_operator(event.get("sender")))
        commit = api.get("commits/" + sha)
        need(type(commit) is dict and commit.get("sha") == sha)
        linked = api.get("commits/" + sha + "/pulls?per_page=100")
        need(type(linked) is list)
        matches = [p for p in linked if type(p) is dict and p.get("merge_commit_sha") == sha]
        need(len(matches) == 1 and auth.positive_int(matches[0].get("number")))
        pr = api.get("pulls/" + str(matches[0]["number"]))
        need(pr.get("merged") is True and pr.get("state") == "closed" and pr.get("merge_commit_sha") == sha)
        need(is_operator(pr.get("merged_by")) and pr["merged_by"]["login"] == actor)
        need(event.get("created") is False and event.get("deleted") is False
             and type(event.get("commits")) is list and len(event["commits"]) == 1
             and event["commits"][0].get("id") == sha)
        parents = commit.get("parents")
        need(type(parents) is list and len(parents) == 1 and auth.full_sha(event.get("before"))
             and parents[0].get("sha") == event["before"])
        verification = (commit.get("commit") or {}).get("verification") or {}
        need(verification.get("verified") is True and verification.get("reason") == "valid"
             and (commit.get("committer") or {}).get("login") == "web-flow")
        head = (pr.get("head") or {}).get("sha")
        need(auth.full_sha(head))
        checks = api.get("commits/" + head + "/check-runs?per_page=100")
        facts.update(authorizationOrSetupPr=pr["number"], prAuthor=pr["user"]["login"],
                     prAuthorIsAllowedHuman=is_operator(pr.get("user")), mergedBy=pr["merged_by"]["login"],
                     commitSignatureVerified=True, committer="web-flow", prHeadSha=head,
                     requiredHeadChecksObserved=required_checks(branch, checks, head))
        base = event["before"]
    need(type(pr.get("base")) is dict and pr["base"].get("ref") == "main"
         and pr["base"].get("repo", {}).get("full_name") == repo)
    # Fork PRs without authorization are harmless; requests must be same-repo.
    files = api.get("pulls/" + str(pr["number"]) + "/files?per_page=100")
    need(type(files) is list and type(pr.get("changed_files")) is int
         and pr["changed_files"] == len(files) and 0 < len(files) <= 100)
    if mode == "push":
        need(type(commit.get("files")) is list and
             [(f.get("filename"), f.get("sha"), f.get("status")) for f in commit["files"]] ==
             [(f.get("filename"), f.get("sha"), f.get("status")) for f in files])
    status = request_format(api, files, repo, head, base, pr)
    if status != "NO_AUTHORIZATION":
        need(pr.get("head", {}).get("repo", {}).get("full_name") == repo)
        if mode == "pull_request":
            need(base == main and is_operator(run.get("actor")) and is_operator(event.get("sender")))
    need(api.get("branches/main") == branch)
    return result(status, **facts)


def main():
    try:
        env = os.environ
        raw = Path(env["GITHUB_EVENT_PATH"]).read_bytes()
        need(0 < len(raw) <= MAX_JSON)
        event = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        out = inspect(env, event, Reader(env["GITHUB_REPOSITORY"], env["GH_TOKEN"]))
        code = 0
    except Exception:
        out, code = result("DENY_MISSING_OR_MISMATCHED_EVIDENCE"), 2
    encoded = json.dumps(out, sort_keys=True)
    print(encoded)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("### Read-only publication admission\n\n```json\n" + encoded + "\n```\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
