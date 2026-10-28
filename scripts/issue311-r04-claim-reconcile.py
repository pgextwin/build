#!/usr/bin/env python3
"""R04: one-shot READ-ONLY recovery of genuine failed terminal after two real claims.

Never replays, retries or reclaims either successful/denied original contender.
Original run 40788234785 remains FAILURE, even when independent witness succeeds.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location(
    "r04race", Path(__file__).resolve().parent / "issue311-r04-claim-race.py")
race = importlib.util.module_from_spec(spec)
spec.loader.exec_module(race)

REQUEST_ID = "r-20261029-r04claimread02"
PATH = Path(".github/execution-requests/" + REQUEST_ID + ".json")
SOURCE_RUN = 40788234785
SOURCE_SHA = "a209d0ac8d451dfec8180dca1effed1a1434d31e"
SOURCE_HASH = "d44f836a0a50ee1e4f840918b0c74565b1763ec87a92f1b1b6969d90579c088b"


def admit():
    race.guard(os.environ.get("GITHUB_REPOSITORY") == "pgextwin/build"
               and os.environ.get("GITHUB_EVENT_NAME") == "push"
               and os.environ.get("GITHUB_REF") == "refs/heads/main"
               and os.environ.get("GITHUB_ACTOR") == "ShutenOishi",
               "untrusted one-shot reconciliation actor/event")
    value = json.loads(PATH.read_bytes(), object_pairs_hook=race.writer.unique_pairs)
    race.guard(type(value) is dict and set(value) == {
        "schemaVersion", "requestId", "mode", "kind", "baseMainSha",
        "originalRunId", "originalRunAttempt", "originalMainSha",
        "originalRequestSha256", "publicReleaseAuthorized"},
        "invalid exact read-only request schema")
    race.guard(value["schemaVersion"] == 1 and value["requestId"] == REQUEST_ID
               and value["mode"] == "AUDIT_ONLY"
               and value["kind"] == "issue311-r04-original-zip-readonly-reconcile"
               and value["originalRunId"] == SOURCE_RUN
               and value["originalRunAttempt"] == 1
               and value["originalMainSha"] == SOURCE_SHA
               and value["originalRequestSha256"] == SOURCE_HASH
               and value["publicReleaseAuthorized"] is False,
               "forged read-only reconciliation")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes(),
                       object_pairs_hook=race.writer.unique_pairs)
    race.guard(event.get("ref") == "refs/heads/main"
               and event.get("created") is False and event.get("deleted") is False
               and event.get("repository", {}).get("full_name") == "pgextwin/build"
               and event.get("before") == value["baseMainSha"]
               and event.get("after") == os.environ["GITHUB_SHA"]
               and subprocess.check_output(["git", "rev-parse", "HEAD"],
                                          text=True).strip() == event["after"],
               "not the exact protected-main first push")
    subprocess.run(["git", "merge-base", "--is-ancestor",
                    event["before"], event["after"]], check=True)
    return hashlib.sha256(PATH.read_bytes()).hexdigest()


def main():
    original = admit()
    race.guard(original != SOURCE_HASH, "replayed original request")
    race.verify_original(SOURCE_RUN, 1, SOURCE_HASH)
    print(json.dumps({"reconciliationRequestId": REQUEST_ID,
                      "reconciliationRawSha256": original,
                      "originalRunId": SOURCE_RUN,
                      "originalRunStatus": "FAILURE_PRESERVED",
                      "readOnly": True, "publisherAuthorized": False,
                      "noOriginalWriteRepeated": True}, sort_keys=True))


if __name__ == "__main__":
    main()
