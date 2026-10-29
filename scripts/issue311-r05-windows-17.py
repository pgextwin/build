#!/usr/bin/env python3
"""Issue311 R05: genuinely linked Windows read-only positive transport (NO RELEASE).

A separate protected-main one-shot request triggers seventeen Windows remote GETs,
binding R04's immutable genuine separated-run checkpoint, then a Linux original-ZIP
aggregator. No Writer, dispatch, cron, signing, Publisher or Catalog access.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parents[1]
REQUEST = "r-20261029-r05win17new02"
REQUEST_PATH = ".github/execution-requests/" + REQUEST + ".json"
TARGETS = {
    "pgextwin/pg_bigm": "713a76b8650f61097b5d5a55f15cd7f2ebcb4ec0",
    "pgextwin/pg_cron": "a36e180a3922e070cde03642ec9fcc40e171567e",
    "pgextwin/pg_hint_plan": "40e68cc8177a3d0707ac87f346e3d88c3247769c",
    "pgextwin/pgaudit": "f53e97d7c4a51c089f8bdc7b33f3ae005f516b29",
    "pgextwin/set_user": "4f02f925e7bc0534af421441c1b2fb1ecd755846",
    "pgextwin/pg_repack": "b9da885a4ef132b5f3d5af448fb09e5bfe56e6a7",
    "pgextwin/pg_ivm": "6e3904af78cccbd67ce84eef183ceda9f4eef553",
    "pgextwin/pg_qualstats": "fa31026f041070c821d317041b8f973ccd0a794d",
    "pgextwin/plpgsql_check": "b75d9c90f2c349788b21a7f47d59ca31f3c8ebdd",
    "pgextwin/orafce": "e96941dd3ec09f88011feb1165a3f6f83231460f",
    "pgextwin/hypopg": "6c6ddfb7b62dd220fdea4004e5e5f6a0a054f271",
    "pgextwin/wal2json": "51850b29b4eca4cc85ac648342d490605557a2ff",
    "pgextwin/pg_partman": "4e3be24b9b2523cc6b1979d61f6be912be6d3e31",
    "pgextwin/pg_stat_monitor": "97f1f41054bed4a3900e0ae924d04cbe5b2f08e4",
    "pgextwin/pgtap": "c536e9d90760eea88f7c42ba4b675e05a0d0fcf8",
    "pgextwin/pg_variables": "0662ed8757e2f0c821a0a300c6f98df9374d8a8c",
    "pgextwin/pg_store_plans": "7d3d4a1b099fb5d408de4f50ee72b4e49854734b"
}
R04_BLOB = "ac4bc107cffbe9f0ff451923218e042443b069b4"
R04_INPUT_SHA = "b57c693d6da26bdd53e18d51f0d2c7df311a550d4ee2f12090c7c1e970fb2ef4"
FLEET_BLOB = "69918265dabb86b11a9406533cbe0ce495137b94"
ARTIFACT_PREFIX = "issue311-r05-win17-"

spec = importlib.util.spec_from_file_location("r05existing", HERE / "scripts/issue311-r05-windows-probe.py")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)


def original_bytes():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != os.environ["GITHUB_SHA"]:
        raise ValueError("HEAD is not event SHA")
    return subprocess.check_output(["git", "show", "HEAD:" + REQUEST_PATH])


def strict_request(raw):
    spec = importlib.util.spec_from_file_location("contract", HERE / "scripts/issue311-request-contract.py")
    lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lib)
    result = lib.validate_declaration(raw, REQUEST_PATH)
    data = json.loads(raw)
    if (result["requestId"] != REQUEST or result["mode"] != "AUDIT_ONLY"
            or data["source"]["centralMainSha"] != json.loads(
                Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["before"]
            or data["source"]["fleetRegistryBlobSha"] != FLEET_BLOB
            or data["limits"]["maxParallel"] != 4
            or data["limits"]["maxOperations"] > 100
            or len(data["targets"]) != 17
            or data["allowFutureUpdates"] is not False
            or data["approval"]["publicReleaseAuthorized"] is not False
            or data["approval"]["publicationGrants"] != []
            or {x["repo"]: x["mainSha"] for x in data["targets"]} != TARGETS):
        raise ValueError("unexpected untrusted request or target")
    # Windows checkout may convert CRLF. Only Git's immutable source blob
    # bytes, never the worktree's filesystem line endings, identify registry.
    registry_bytes=subprocess.check_output(
        ["git","show","HEAD:metadata/automation-fleet.json"])
    fleet=json.loads(registry_bytes)
    if (sorted(TARGETS)!=sorted(x["repository"] for x in fleet["entries"])
            or hashlib.sha1(
                b"blob "+str(len(registry_bytes)).encode()
                +b"\0"+registry_bytes
               ).hexdigest()!=FLEET_BLOB):
        raise ValueError("fleet names or original registry Git blob mismatch")
    return result


def real_event():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    if (os.environ["GITHUB_REPOSITORY"] != "pgextwin/build"
            or os.environ["GITHUB_EVENT_NAME"] != "push"
            or os.environ["GITHUB_REF"] != "refs/heads/main"
            or os.environ["GITHUB_ACTOR"] != "ShutenOishi"
            or (event.get("sender") or {}).get("login") != "ShutenOishi"
            or event.get("before") != json.loads(original_bytes())["source"]["centralMainSha"]
            or event.get("after") != os.environ["GITHUB_SHA"]
            or event.get("ref") != "refs/heads/main"
            or event.get("repository", {}).get("full_name") != "pgextwin/build"
            or event.get("created") is not False or event.get("deleted") is not False):
        raise ValueError("not original protected main-push actor/event")


def admit():
    real_event()
    checked = strict_request(original_bytes())
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write("raw_sha=" + checked["rawSha256"] + "\n")
    print("R05_POSITIVE_AUDIT_ONLY_ADMITTED", checked["rawSha256"])


def verify_immutable_state(payload):
    if payload.get("encoding") != "base64" or payload.get("sha") != R04_BLOB:
        raise ValueError("R04 exact Git blob mismatch")
    raw = base64.b64decode(payload["content"])
    git_blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
    if hashlib.sha1(git_blob).hexdigest() != R04_BLOB:
        raise ValueError("R04 bytes are not their authenticated Git blob")
    state = json.loads(raw)
    if not (state.get("phase") == "RECOVERED_ANOTHER_RUN"
            and state.get("requestSha256") == R04_INPUT_SHA
            and state.get("revision") == 2
            and state.get("completedStages") == ["READONLY_PROTECTED_MAIN_BOUND"]
            and state.get("sourceRunId") == 40789724530
            and state.get("resumedByRunId") == 40789923987
            and state.get("lease", {}).get("generation") == 2
            and state.get("lease", {}).get("scope") == "READONLY"
            and state.get("publisherAuthorized") is False
            and state.get("writeOutcomeUnknown") is False):
        raise ValueError("unaccepted R04 state in Windows transport")
    return state


def inspect():
    repo = os.environ["REMOTE_REPO"]
    receipt = {"requestId": REQUEST, "repo": repo,
               "runId": int(os.environ["GITHUB_RUN_ID"]),
               "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
               "runnerOS": os.environ["RUNNER_OS"], "result": "FAILED",
               "completionEvent": "WINDOWS_ORIGINAL_REMOTE_GET",
               "publicationAuthorized": False, "requestSha256": os.environ["REQUEST_SHA"]}
    try:
        raw = original_bytes()
        if (strict_request(raw)["rawSha256"] != os.environ["REQUEST_SHA"]
                or repo not in TARGETS or os.environ["REMOTE_SHA"] != TARGETS[repo]
                or os.environ["RUNNER_OS"] != "Windows"
                or os.environ["GITHUB_EVENT_NAME"] != "push"
                or os.environ["GITHUB_REPOSITORY"] != "pgextwin/build"):
            raise ValueError("Windows request/target binding mismatch")
        branch = old.get_json("https://api.github.com/repos/" + repo + "/branches/main",
                              os.environ["GH_TOKEN"])
        if not (branch.get("name") == "main" and branch.get("protected") is True
                and branch.get("commit", {}).get("sha") == TARGETS[repo]):
            raise ValueError("remote main/branch protection changed")
        state = old.get_json("https://api.github.com/repos/pgextwin/build/contents/"
                             "checkpoints/issue311-cross-run-v1.json?ref=issue311-state",
                             os.environ["GH_TOKEN"])
        verify_immutable_state(state)
        receipt.update(result="SUCCESS", targetMainSha=TARGETS[repo],
                       remoteProtected=True, stateGitBlobSha=R04_BLOB)
    except Exception as exc:
        receipt["reason"] = str(exc)[:260]
    Path("issue311-r05-win17-target.json").write_text(
        json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "SUCCESS" else 1


def evaluate(jobs, receipts, admission):
    expected = set(TARGETS)
    found = {}
    for job in jobs:
        name = job.get("name", "")
        if not name.startswith("WINDOWS STATE GET "):
            continue
        repo = name.removeprefix("WINDOWS STATE GET ")
        if repo not in expected or repo in found:
            raise ValueError("unexpected or duplicate Windows child")
        found[repo] = job.get("conclusion") if job.get("status") == "completed" else "incomplete"
    if set(found) != expected or set(receipts) != expected:
        raise ValueError("missing or duplicate original Windows receipt")
    for repo, receipt in receipts.items():
        if (receipt.get("requestId") != REQUEST or receipt.get("repo") != repo
                or receipt.get("runnerOS") != "Windows"
                or receipt.get("completionEvent") != "WINDOWS_ORIGINAL_REMOTE_GET"
                or receipt.get("remoteProtected") is not True
                or receipt.get("stateGitBlobSha") != R04_BLOB
                or receipt.get("targetMainSha") != TARGETS[repo]
                or receipt.get("result") != "SUCCESS"
                or receipt.get("publicationAuthorized") is not False):
            raise ValueError("forged or incomplete original Windows receipt")
    return {"terminal": "NO_UPDATE" if admission == "success" and
            all(x == "success" for x in found.values()) else "FAILED",
            "perTarget": found, "publicReleaseAuthorized": False}


def aggregate():
    receipt = {"requestId": REQUEST, "terminal": "FAILED",
               "runId": int(os.environ["GITHUB_RUN_ID"]),
               "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
               "publicReleaseAuthorized": False, "reason": "original Windows proof missing"}
    try:
        token = os.environ["GH_TOKEN"]
        base = "https://api.github.com/repos/pgextwin/build/actions/runs/" + str(receipt["runId"])
        jobs = old.get_json(base + "/jobs?per_page=100", token)
        arts = old.get_json(base + "/artifacts?per_page=100", token)
        if jobs.get("total_count", 999) > 100 or arts.get("total_count", 999) > 100:
            raise ValueError("truncated original GitHub pages")
        originals, digests = {}, {}
        for a in arts["artifacts"]:
            name = a["name"]
            if name not in {ARTIFACT_PREFIX + repo.removeprefix("pgextwin/") for repo in TARGETS}:
                continue
            repo = "pgextwin/" + name.removeprefix(ARTIFACT_PREFIX)
            if repo in originals or a.get("expired") is not False:
                raise ValueError("duplicated or expired receipt")
            request = urllib.request.Request(a["archive_download_url"], headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json"})
            with urllib.request.build_opener(old.StripCrossHostAuthorization()).open(
                    request, timeout=30) as result:
                raw = result.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError("oversize original ZIP")
            digest = hashlib.sha256(raw).hexdigest()
            if a.get("digest") != "sha256:" + digest:
                raise ValueError("original ZIP SHA256 mismatch")
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if archive.namelist() != ["issue311-r05-win17-target.json"]:
                    raise ValueError("unexpected original ZIP members")
                child = json.loads(archive.read("issue311-r05-win17-target.json"))
            if (child.get("runId") != receipt["runId"]
                    or child.get("runAttempt") != receipt["runAttempt"]
                    or child.get("requestSha256") != os.environ["REQUEST_SHA"]):
                raise ValueError("original receipt replay or request mismatch")
            originals[repo] = child
            digests[repo] = digest
        receipt.update(evaluate(jobs["jobs"], originals, os.environ["ADMIT_RESULT"]))
        receipt["originalZipSha256"] = digests
        receipt.pop("reason")
    except Exception as exc:
        receipt["reason"] = str(exc)[:300]
    Path("issue311-r05-win17-terminal.json").write_text(
        json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["terminal"] == "NO_UPDATE" else 1


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else ""
    if phase == "admit":
        admit()
    elif phase == "inspect":
        sys.exit(inspect())
    elif phase == "aggregate":
        sys.exit(aggregate())
    else:
        sys.exit("expected admit|inspect|aggregate")
