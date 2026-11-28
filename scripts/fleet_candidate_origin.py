"""Join a GitHub App proposal to its original protected Build schedule (GET only)."""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
BUILD = "pgextwin/build"
WATCH = ".github/workflows/fleet-upstream-watch.yml"
MANIFEST = "config/extension.json"
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"pgextwin/[a-z][a-z0-9_]*")
MARKER = "<!-- pgextwin-fleet-origin:v1:"
UPLOAD_STEP = "Preserve exact App candidate origin"
MAX_RECORD = 32000


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scheduled = load("verify-scheduled-fleet-candidate")
contents = load("github_contents")
candidate_branch = load("candidate_branch")
APP = json.loads((ROOT / "metadata/fleet-candidate-app.json").read_text(encoding="utf-8"))
BOT = APP["slug"] + "[bot]"
LEGACY = "github-actions[bot]"


class Denied(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Denied(message)


def positive(value):
    return type(value) is int and value > 0


def sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def is_app(pr):
    """Identify a possible App candidate for discovery. This grants no authority."""
    return (pr.get("user") or {}).get("login") == BOT


def app_identity(account):
    return (account.get("login") == BOT and account.get("type") == "Bot"
            and type(account.get("id")) is int and account["id"] == APP["botUserId"])


def check_app(api):
    app = api("apps/" + APP["slug"])
    require(app.get("id") == APP["appId"] and app.get("slug") == APP["slug"]
            and (app.get("owner") or {}).get("login") == "pgextwin",
            "dedicated candidate App ID, slug or owner differs")


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def marker(record):
    data = canonical(record)
    require(len(data) <= MAX_RECORD, "candidate origin evidence is oversized")
    return MARKER + base64.b64encode(data).decode("ascii") + " -->"


def parse_marker(body):
    require(type(body) is str and body.count(MARKER) == 1,
            "missing or duplicate candidate origin record")
    encoded, delimiter, _ = body.split(MARKER, 1)[1].partition(" -->")
    require(delimiter and 0 < len(encoded) <= 4 * ((MAX_RECORD + 2) // 3),
            "malformed candidate origin record")
    record = scheduled.strict_json(base64.b64decode(encoded, validate=True).decode("ascii"))
    require(type(record) is dict and marker(record) == MARKER + encoded + delimiter,
            "noncanonical candidate origin record")
    return record


def proof_bytes(record, number):
    return canonical({"origin": record, "pullRequest": number})


def artifact_prefix(repo):
    return "candidate-origin-" + repo.split("/")[1] + "-"


def artifact_name(repo, record, number):
    return artifact_prefix(repo) + hashlib.sha256(proof_bytes(record, number)).hexdigest()


def github(path):
    # Caller GITHUB_TOKEN may lack Actions access across public repositories.
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    try:
        return json_get(path, token)
    except HTTPError as exc:
        if not token or exc.code not in (401, 403, 404):
            raise
        return json_get(path, None)


def json_get(path, token):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request("https://api.github.com/" + path, headers=headers, method="GET")
    with build_opener(scheduled.NoRedirect()).open(request, timeout=20) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, "oversized GitHub metadata")
    return scheduled.strict_json(raw.decode("utf-8"))


def scope(repository):
    require(type(repository) is str and REPO.fullmatch(repository), "invalid candidate target")
    fleet = json.loads((ROOT / "metadata/automation-fleet.json").read_text(encoding="utf-8"))
    rows = [row for row in fleet["entries"] if row.get("repository") == repository]
    require(len(rows) == 1 and rows[0].get("mode") == "BUILD"
            and rows[0].get("candidateEnabled") is True,
            "repository is outside the registered candidate fleet")


def validate_pr(repository, pr, record):
    require(app_identity(pr.get("user") or {}) and positive(pr.get("number")),
            "candidate author does not match the pinned App bot user")
    app = pr.get("performed_via_github_app")
    require(app is None or (type(app) is dict and app.get("id") == APP["appId"]),
            "PR GitHub App differs from the pinned App")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    repo_id = record.get("repositoryId")
    branch = head.get("ref", "")
    decision = record.get("decision")
    require(type(decision) is dict, "candidate origin decision is missing")
    extension = decision.get("extension")
    try:
        central = candidate_branch.branch_style_for_repository(repository, extension) == "central"
        candidate = candidate_branch.parse_branch(branch, expected_extension=extension,
                                                  allow_legacy=not central, allow_central=central)
    except ValueError as exc:
        raise Denied("candidate origin branch does not match the repository and extension") from exc
    require(record.get("schemaVersion") == 1 and record.get("repository") == repository
            and positive(repo_id) and record.get("appId") == APP["appId"]
            and record.get("botUserId") == APP["botUserId"]
            and base.get("ref") == "main" and sha(record.get("baseSha"))
            and sha(record.get("headSha")) and head.get("sha") == record["headSha"]
            and all((info.get("repo") or {}).get("id") == repo_id
                    and (info.get("repo") or {}).get("full_name") == repository
                    for info in (head, base))
            and "<!-- pgextwin-candidate:v1:" + candidate.candidate_id + " -->" in pr["body"],
            "candidate origin does not match exact PR, repository, head or base ref")
    require(decision.get("schemaVersion") == 1
            and decision.get("status") == "candidate" and decision.get("releasePolicy") == "manual-only"
            and decision.get("candidateId") == candidate.candidate_id and decision.get("branch") == branch
            and decision.get("firstRelease") is not True and sha(record.get("manifestBlob")),
            "original decision does not identify the exact stable candidate")
    return decision


def inventory(doc, field):
    rows = doc.get(field)
    require(type(rows) is list and doc.get("total_count") == len(rows) < 100
            and all(type(row) is dict for row in rows), "incomplete central " + field)
    return rows


def unique(rows, name):
    matches = [row for row in rows if row.get("name") == name]
    require(len(matches) == 1, "missing or duplicate central evidence: " + name)
    return matches[0]


def validate_run(api, repository, pr, record):
    run_id = record.get("runId")
    source = record.get("runSha")
    decision_id = record.get("decisionArtifactId")
    require(positive(run_id) and positive(decision_id) and sha(source)
            and type(record.get("runAttempt")) is int and record["runAttempt"] == 1,
            "invalid original central run, attempt or decision ID")
    build = "repos/" + BUILD + "/"
    run_path = build + "actions/runs/" + str(run_id)
    run = api(run_path)
    repo_id = APP["buildRepositoryId"]
    require(run.get("id") == run_id and run.get("event") == "schedule"
            and run.get("path") == WATCH and run.get("head_branch") == "main"
            and run.get("head_sha") == source and run.get("run_attempt") == 1
            and run.get("status") in ("in_progress", "completed")
            and all((run.get(key) or {}).get("id") == repo_id
                    and (run.get(key) or {}).get("full_name") == BUILD
                    for key in ("repository", "head_repository")),
            "original Run is not the first protected Build fleet schedule")
    main = api(build + "branches/main")
    current = (main.get("commit") or {}).get("sha")
    require(main.get("name") == "main" and main.get("protected") is True and sha(current),
            "central main is not protected")
    if source != current:
        compare = api(build + "compare/" + source + "..." + current)
        require(compare.get("status") == "ahead"
                and (compare.get("merge_base_commit") or {}).get("sha") == source,
                "original Build Run is outside protected main history")

    jobs = inventory(api(run_path + "/attempts/1/jobs?per_page=100"), "jobs")
    scan = unique(jobs, "readonly-fleet")
    writer_name = "Bind fleet candidate " + repository.split("/")[1]
    # GitHub prefixes jobs inside reusable workflows with their callers.
    writers = [job for job in jobs
               if (job.get("name") or "").endswith(" / " + writer_name)]
    require(len(writers) == 1, "candidate writer job missing or ambiguous")
    writer = writers[0]
    for job in (scan, writer):
        require(job.get("run_id") == run_id and job.get("run_attempt") == 1
                and job.get("head_sha") == source and job.get("status") == "completed"
                and job.get("conclusion") == "success", "central scan or writer did not succeed")
    upload = unique(writer.get("steps") or [], UPLOAD_STEP)
    require(upload.get("status") == "completed" and upload.get("conclusion") == "success",
            "central writer did not upload origin evidence")

    artifacts = inventory(api(run_path + "/artifacts?per_page=100"), "artifacts")
    extension = repository.split("/")[1]
    decision = unique(artifacts, "candidate-decision-" + extension)
    origins = [a for a in artifacts if (a.get("name") or "").startswith(artifact_prefix(repository))]
    require(len(origins) == 1 and origins[0].get("name") == artifact_name(repository, record, pr["number"])
            and decision.get("id") == decision_id, "missing, ambiguous or mismatched App origin or plan artifact")
    origin = origins[0]
    for artifact in (decision, origin):
        require(positive(artifact.get("id")) and artifact.get("expired") is False
                and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest") or "")
                and 0 < artifact.get("size_in_bytes", 0) <= 262144
                and all((artifact.get("workflow_run") or {}).get(key) == value for key, value in {
                    "id": run_id, "repository_id": repo_id, "head_repository_id": repo_id,
                    "head_branch": "main", "head_sha": source}.items()),
                "central artifact is expired or does not belong to the original Run and commit")
    when = scheduled.timestamp
    created = when(pr.get("created_at"))
    started = when(run.get("created_at"))
    require(started <= when(scan.get("completed_at")) <= when(decision.get("created_at"))
            <= when(writer.get("started_at")) <= created <= when(upload.get("started_at"))
            <= when(origin.get("created_at")) <= when(upload.get("completed_at"))
            <= when(writer.get("completed_at")) and created - started < timedelta(hours=3),
            "stale or unrelated central decision, proposal or writer")
    return origin


def verify_regeneration_chain(api, repository, record):
    """Bind a regenerated decision to the exact closed App PR it supersedes."""
    visited = {record["decision"]["candidateId"]}
    extension = record["decision"].get("extension")
    try:
        style = candidate_branch.branch_style_for_repository(repository, extension)
    except ValueError as exc:
        raise Denied("invalid regeneration repository or extension") from exc

    def walk(current, depth):
        if "regeneration" not in current:
            return
        link = current.get("regeneration")
        require(depth <= 8, "candidate regeneration chain exceeds depth limit")
        require(type(link) is dict and set(link) == {
            "predecessorCandidateId", "predecessorPrNumber"},
            "malformed candidate regeneration pointer")
        predecessor_id = link.get("predecessorCandidateId")
        number = link.get("predecessorPrNumber")
        require(type(predecessor_id) is str and re.fullmatch(r"[0-9a-f]{20}", predecessor_id)
                and positive(number), "malformed candidate regeneration pointer")
        require(predecessor_id not in visited, "candidate regeneration chain contains a cycle")
        visited.add(predecessor_id)
        pr = api("repos/" + repository + "/pulls/" + str(number))
        require(type(pr) is dict and pr.get("number") == number
                and app_identity(pr.get("user") or {}) and pr.get("state") == "closed"
                and pr.get("merged") is False,
                "regeneration predecessor is not a closed, unmerged App PR")
        head, base = pr.get("head") or {}, pr.get("base") or {}
        try:
            predecessor = candidate_branch.parse_branch(head.get("ref"), expected_extension=extension,
                                                        allow_central=style == "central")
        except ValueError as exc:
            raise Denied("regeneration predecessor branch differs") from exc
        require(predecessor.candidate_id == predecessor_id and base.get("ref") == "main",
                "regeneration predecessor branch or base differs")
        body = pr.get("body")
        markers = re.findall(r"<!-- pgextwin-candidate:v1:([0-9a-f]{20}) -->", body or "")
        require(type(body) is str and body.count("<!-- pgextwin-candidate:v1:") == 1
                and markers == [predecessor_id],
                "regeneration predecessor candidate marker is missing, duplicate or mismatched")
        previous = parse_marker(body)
        require(previous.get("repository") == repository
                and previous.get("appId") == APP["appId"]
                and previous.get("botUserId") == APP["botUserId"],
                "regeneration predecessor origin identity differs")
        old_decision = previous.get("decision")
        new_decision = current.get("decision")
        require(type(old_decision) is dict and type(new_decision) is dict
                and old_decision.get("candidateId") == predecessor_id
                and old_decision.get("branch") == predecessor.branch
                and {k: v for k, v in old_decision.items() if k not in ("candidateId", "branch")} ==
                {k: v for k, v in new_decision.items() if k not in ("candidateId", "branch")},
                "regeneration predecessor decision differs from successor")
        walk(previous, depth + 1)

    walk(record, 1)


def verify(repository, pr, *, api=github):
    """Verify the App route independently of any caller-supplied PR audit."""
    scope(repository)
    record = parse_marker(pr.get("body"))
    decision = validate_pr(repository, pr, record)
    if "regeneration" in record:
        verify_regeneration_chain(api, repository, record)
    check_app(api)
    artifact = validate_run(api, repository, pr, record)
    target = "repos/" + repository + "/"
    base = record["baseSha"]
    head = record["headSha"]
    branch = api(target + "branches/main")
    require(branch.get("name") == "main" and branch.get("protected") is True,
            "target main is not protected")
    if pr.get("merged") is True:
        merged = pr.get("merge_commit_sha")
        require(sha(merged), "merged candidate has no exact main SHA")
        commit = api(target + "commits/" + merged)
        files = commit.get("files")
        require(pr.get("state") == "closed" and commit.get("sha") == merged
                and [p.get("sha") for p in commit.get("parents", [])] == [base]
                and type(files) is list and len(files) == 1 and files[0].get("filename") == MANIFEST
                and files[0].get("sha") == record["manifestBlob"],
                "merged candidate did not land on its original protected base")
    else:
        require(pr.get("state") == "open" and pr.get("merged") is False
                and (branch.get("commit") or {}).get("sha") == base and pr["base"].get("sha") == base,
                "candidate base is no longer exact protected main")
    commit = api(target + "commits/" + head)
    files = commit.get("files")
    require(commit.get("sha") == head and [p.get("sha") for p in commit.get("parents", [])] == [base]
            and type(files) is list and len(files) == 1
            and files[0].get("filename") == MANIFEST and files[0].get("status") == "modified"
            and files[0].get("sha") == record["manifestBlob"],
            "candidate head is no longer the original manifest-only child of protected main")
    source = api(target + "contents/" + MANIFEST + "?ref=" + head)
    require(source.get("sha") == record["manifestBlob"], "candidate manifest blob differs")
    manifest = contents.decode_json_file(source, MANIFEST)
    upstream = manifest.get("upstream") or {}
    updates = decision.get("updates")
    require(manifest.get("name") == decision["extension"]
            and upstream.get("repository") == decision.get("repository")
            and type(updates) is list and bool(updates), "candidate decision source differs")
    per_major = upstream.get("perPostgresql")
    require(type(per_major) is dict or (per_major is None and len(updates) == 1),
            "original decision and candidate source shape differ")
    seen = set()
    for update in updates:
        major = update.get("major")
        require((per_major is None and major is None) or (per_major is not None and type(major) is int),
                "decision uses a different PostgreSQL source layout")
        pins = upstream if per_major is None else per_major.get(str(major))
        require(major not in seen and type(pins) is dict
                and update.get("initialOnly") is False and update.get("pinOnly") is False
                and sha(update.get("commit"))
                and all(update.get(field) == pins.get(field) and update.get(field)
                        for field in ("ref", "version", "commit")), "planned upstream pins differ from head")
        seen.add(major)
    return {"record": record, "artifactId": artifact["id"]}


def author(repository, pr, *, verify_origin=None, denied=Denied):
    """Retain the existing local bot check and require a complete App origin."""
    if (pr.get("user") or {}).get("login") == LEGACY:
        return None
    if not is_app(pr) or verify_origin is None:
        raise denied("candidate PR author is not bound to an approved bot origin")
    try:
        return verify_origin(repository, pr)
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        raise denied("dedicated App origin denied: " + str(exc)) from exc


def summary(evidence):
    if evidence is None:
        return {}
    record = evidence["record"]
    return {"candidateOrigin": {
        "repository": BUILD, "runId": record["runId"], "runAttempt": record["runAttempt"],
        "decisionArtifactId": record["decisionArtifactId"], "originArtifactId": evidence["artifactId"],
    }}
