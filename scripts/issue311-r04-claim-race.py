#!/usr/bin/env python3
"""Issue #311 R04: two real, distinct AUDIT_ONLY claims on one protected App CAS ledger.

This single-use proof cannot invoke Release, Publisher, Catalog, or dispatch.
A rejected competitor must observe the winner using a fresh authenticated GET.
"""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import urllib.parse
import zipfile

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("issue311_writer", BASE / "issue311-writer-runtime.py")
writer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)

REQUEST_ID = "r-20261029-r04claimrace001"
REQUEST_PATH = Path(".github/execution-requests/" + REQUEST_ID + ".json")
IDS = ("r-20261029-claimracea01", "r-20261029-claimraceb01")
CANDIDATE = "pgextwin/orafce"
CANDIDATE_SHA = "e96941dd3ec09f88011feb1165a3f6f83231460f"
ARTIFACT_PREFIX = "issue311-r04-claim-"
RECEIPT_NAME = "issue311-r04-claim-receipt.json"


def guard(condition, reason):
    writer.require(condition, "R04_RACE_DENY: " + reason)


def request_data():
    raw = REQUEST_PATH.read_bytes()
    value = json.loads(raw, object_pairs_hook=writer.unique_pairs)
    guard(type(value) is dict and set(value) == {
        "schemaVersion", "requestId", "mode", "kind", "candidate",
        "competitors", "baseMainSha", "publicReleaseAuthorized"}, "request schema")
    guard(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["requestId"] == REQUEST_ID and value["mode"] == "AUDIT_ONLY"
          and value["kind"] == "issue311-r04-claim-race-proof"
          and value["publicReleaseAuthorized"] is False, "unrecognized request")
    guard(type(value["candidate"]) is dict and value["candidate"] == {
        "repo": CANDIDATE, "sha": CANDIDATE_SHA}, "candidate not pinned")
    guard(type(value["competitors"]) is list and value["competitors"] == list(IDS),
          "competitors must be unique and pinned")
    guard(type(value["baseMainSha"]) is str
          and writer.SHA1.fullmatch(value["baseMainSha"]), "missing base main")
    return value, hashlib.sha256(raw).hexdigest()


def provenance():
    guard(os.environ.get("GITHUB_REPOSITORY") == writer.REPOSITORY
          and os.environ.get("GITHUB_EVENT_NAME") == "push"
          and os.environ.get("GITHUB_REF") == "refs/heads/main"
          and os.environ.get("GITHUB_ACTOR") == "ShutenOishi", "event or actor")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                       object_pairs_hook=writer.unique_pairs)
    guard(event.get("ref") == "refs/heads/main"
          and event.get("created") is False and event.get("deleted") is False
          and event.get("repository", {}).get("full_name") == writer.REPOSITORY
          and event.get("after") == os.environ["GITHUB_SHA"], "original push")
    value, raw_sha = request_data()
    guard(event.get("before") == value["baseMainSha"], "not the exact first main push")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    guard(head == event["after"], "checkout not original push")
    subprocess.run(["git", "merge-base", "--is-ancestor", event["before"], head],
                   check=True)
    return value, raw_sha


def own_receipt(index, status, raw_sha, blob, current, **extra):
    result = {"schemaVersion": 1, "requestId": REQUEST_ID, "requestSha256": raw_sha,
              "claimant": IDS[index], "status": status,
              "candidate": {"repo": CANDIDATE, "sha": CANDIDATE_SHA},
              "runId": int(os.environ["GITHUB_RUN_ID"]),
              "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
              "ledgerBlobSha": blob, "revision": current["revision"],
              "publisherAuthorized": False, **extra}
    return result


def race():
    _, raw_sha = provenance()
    index = int(os.environ["COMPETITOR_INDEX"])
    guard(index in (0, 1), "invalid independent competitor")
    claimant = IDS[index]
    key = CANDIDATE + "@" + CANDIDATE_SHA
    private_key = os.environ.get("STATE_WRITER_PRIVATE_KEY", "")
    guard(bool(private_key), "missing dedicated App key")
    token = writer.mint_token(private_key)
    error = None
    receipt = None
    try:
        before_blob, current = writer.read_ledger(token)
        guard(current["phase"] == "RECOVERED" and current["publisherAuthorized"] is False
              and current["writeOutcomeUnknown"] is False, "prior proof state not recovered")
        incumbent = current["candidateClaims"].get(key)
        if incumbent is not None:
            guard(incumbent in IDS and incumbent != claimant,
                  "unknown incumbent or replay")
            receipt = own_receipt(index, "DENIED_EXISTING_CLAIM", raw_sha,
                                  before_blob, current, winner=incumbent)
        else:
            proposed = writer.claim_candidate(current, claimant, CANDIDATE, CANDIDATE_SHA)
            try:
                proof = writer.commit(token, proposed, before_blob)
            except writer.HTTPStatus as exc:
                guard(exc.code in (409, 422), "unexpected HTTP write rejection")
                proof = "STALE_CAS_DENIED"
            except writer.UncertainWrite:
                # Ambiguous write must NOT retry. Even if an authoritative GET later
                # reveals a winner, no additional write is attempted.
                proof = "AMBIGUOUS_WRITE_QUARANTINED"
            observed_blob, observed = writer.read_ledger(token)
            winner = observed["candidateClaims"].get(key)
            guard(winner in IDS, "missing canonical winner")
            if winner == claimant:
                guard(observed["revision"] == proposed["revision"]
                      and observed == proposed and proof != "STALE_CAS_DENIED"
                      and proof != "AMBIGUOUS_WRITE_QUARANTINED",
                      "ambiguous or inconsistent winning write")
                receipt = own_receipt(index, "WON", raw_sha, observed_blob, observed,
                                      writeProof=proof)
            else:
                guard(winner != claimant and proof == "STALE_CAS_DENIED",
                      "unexpected/ambiguous loser")
                receipt = own_receipt(index, "DENIED_STALE_CAS", raw_sha,
                                      observed_blob, observed, winner=winner)
    except BaseException as exc:
        error = exc
    finally:
        writer.revoke_and_prove_401(token)
    if error:
        raise error
    receipt["revoked401"] = True
    Path(RECEIPT_NAME).write_bytes(writer.canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))


class StripCrossHostAuthorization(urllib.request.HTTPRedirectHandler):
    """Prevent GITHUB_TOKEN from being forwarded to artifact blob CDN."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if (redirected is not None and
            urllib.parse.urlsplit(req.full_url).hostname
                != urllib.parse.urlsplit(newurl).hostname):
            redirected.remove_header("Authorization")
        return redirected


def public_api(endpoint):
    guard(endpoint.startswith("repos/pgextwin/build/actions/runs/")
          or endpoint.startswith("repos/pgextwin/build/actions/artifacts/")
          or endpoint == writer.ledger_endpoint() + "?ref=" + writer.STATE_BRANCH,
          "read endpoint")
    req = urllib.request.Request(writer.API_URL + endpoint,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.build_opener(StripCrossHostAuthorization()).open(
            req, timeout=30) as response:
        data = response.read(2_000_001)
    guard(len(data) <= 2_000_000, "original response too large")
    return data


def verify_original(run_id, attempt, raw_sha):
    """Independent read-only reconciliation; never schedules or replays an App write."""
    guard(type(run_id) is int and run_id > 0 and type(attempt) is int
          and attempt == 1 and writer.SHA256.fullmatch(raw_sha),
          "unrecognized original run/attempt/request")
    jobs = json.loads(public_api(
        f"repos/pgextwin/build/actions/runs/{run_id}/jobs?per_page=100"))
    guard(jobs.get("total_count", 101) <= 100, "original jobs truncated")
    for index in (0, 1):
        matches = [j for j in jobs["jobs"] if j.get("name") ==
                   "Fresh App scoped protected ledger contender " + str(index)]
        guard(len(matches) == 1 and matches[0].get("conclusion") == "success",
              "original independent contender job not successful")
    archive_list = json.loads(public_api(
        f"repos/pgextwin/build/actions/runs/{run_id}/artifacts?per_page=100"))
    guard(archive_list.get("total_count", 101) <= 100, "artifacts truncated")
    found = {}
    for artifact in archive_list["artifacts"]:
        name = artifact.get("name", "")
        if name not in (ARTIFACT_PREFIX + "0", ARTIFACT_PREFIX + "1"):
            continue
        guard(name not in found and artifact["workflow_run"]["id"] == run_id,
              "duplicate/foreign artifact")
        guard(artifact.get("expired") is False, "expired original ZIP")
        raw = public_api(f"repos/pgextwin/build/actions/artifacts/{artifact['id']}/zip")
        guard(artifact.get("digest") == "sha256:" + hashlib.sha256(raw).hexdigest(),
              "original artifact ZIP digest mismatch")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            guard(archive.namelist() == [RECEIPT_NAME], "unexpected ZIP members")
            value = json.loads(archive.read(RECEIPT_NAME),
                               object_pairs_hook=writer.unique_pairs)
        found[int(name[-1])] = value
    guard(set(found) == {0, 1}, "missing independent runner artifact")
    statuses = [found[0]["status"], found[1]["status"]]
    guard(statuses.count("WON") == 1
          and sum(x.startswith("DENIED_") for x in statuses) == 1,
          "one winner and one denied contender required")
    for index, value in found.items():
        guard(value["claimant"] == IDS[index] and value["requestId"] == REQUEST_ID
              and value["requestSha256"] == raw_sha and value["runId"] == run_id
              and value["runAttempt"] == attempt
              and value["publisherAuthorized"] is False
              and value["revoked401"] is True, "original receipt mismatch")
    contents = json.loads(public_api(writer.ledger_endpoint() + "?ref=" + writer.STATE_BRANCH))
    import base64
    state_raw = base64.b64decode(contents["content"])
    state = json.loads(state_raw, object_pairs_hook=writer.unique_pairs)
    writer.validate_ledger(state)
    git_blob = b"blob " + str(len(state_raw)).encode() + b"\0" + state_raw
    guard(hashlib.sha1(git_blob).hexdigest() == contents["sha"],
          "protected ledger blob mismatch")
    key = CANDIDATE + "@" + CANDIDATE_SHA
    winner = next(x["claimant"] for x in found.values() if x["status"] == "WON")
    guard(state["candidateClaims"].get(key) == winner, "ledger winner discrepancy")
    guard(state["publisherAuthorized"] is False and
          state["writeOutcomeUnknown"] is False, "publication/write ambiguity")
    print(json.dumps({"requestId": REQUEST_ID, "result": "NO_UPDATE",
                      "originalRun": run_id, "originalAttempt": attempt,
                      "claimWinner": winner, "claimLoserDenied": True,
                      "revoked401Both": True, "ledgerSha": contents["sha"],
                      "publisherAuthorized": False}, sort_keys=True))


def verify():
    _, raw_sha = provenance()
    return verify_original(int(os.environ["GITHUB_RUN_ID"]),
                           int(os.environ["GITHUB_RUN_ATTEMPT"]), raw_sha)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("admit", "race", "verify"))
    args = parser.parse_args()
    if args.phase == "admit":
        _, raw_sha = provenance()
        print("AUDIT_ONLY_RACE_ADMITTED " + raw_sha)
    elif args.phase == "race":
        race()
    else:
        verify()


if __name__ == "__main__":
    main()
