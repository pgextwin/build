#!/usr/bin/env python3
"""R08 v2.1 App OIDC intent adversarial tests (NO CREDENTIALS / NO SIGNATURE)."""
import copy
import importlib.util
from pathlib import Path

s = importlib.util.spec_from_file_location(
    "app_r08", Path("scripts/issue311-r08-app-oidc-intent.py"))
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)

env = {
    "GITHUB_REPOSITORY": m.REPO, "GITHUB_WORKFLOW": m.WORKFLOW,
    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
    "GITHUB_ACTOR": m.ACTOR, "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_JOB": "r08_app_signing_intent",
    "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123456"
}
event = {
    "repository": {"full_name": m.REPO}, "ref": "refs/heads/main",
    "sender": {"login": m.ACTOR, "id": m.ACTOR_ID, "type": "Bot"},
    "inputs": {
        "request_id": "r-20261030-r06coordlocalpilot01",
        "source_run_id": "987654", "source_head_sha": "b" * 40,
        "source_artifact_id": "765432", "source_zip_sha256": "c" * 64,
        "central_request_id": "r-20261030-r06prepareproof01",
        "local_main_sha": "a" * 40
    }
}
run = {
    "id": 123456, "run_attempt": 1,
    "repository": {"full_name": m.REPO}, "head_branch": "main",
    "head_sha": "a" * 40, "event": "workflow_dispatch", "path": m.PATH,
    "name": m.WORKFLOW, "status": "in_progress", "conclusion": None,
    "actor": {"login": m.ACTOR, "id": m.ACTOR_ID},
    "triggering_actor": {"login": m.ACTOR}
}
branch = {"name": "main", "protected": True, "commit": {"sha": "a" * 40}}
receipt = {
    "schemaVersion": 1, "sourceKind": m.SOURCE_KIND, "result": "NO_UPDATE",
    "localOriginalEvent": "workflow_dispatch",
    "actualBotLogin": m.ACTOR, "actualBotUserId": m.ACTOR_ID,
    "localRunId": 123456, "localRunAttempt": 1,
    "localProtectedMainSha": "a" * 40,
    "requestId": event["inputs"]["request_id"],
    "centralSourceRunId": 987654, "centralSourceHeadSha": "b" * 40,
    "centralSourceArtifactId": 765432,
    "centralOriginalOuterZipSha256Verified": "c" * 64,
    "centralSourceRequestId": event["inputs"]["central_request_id"],
    "centralSourceRawRequestSha256": "d" * 64,
    **{key: False for key in m.NO_AUTH}
}
intent = m.validate(receipt, event, run, branch, env)
assert intent["status"] == m.INTENT
assert intent["centralRunId"] == 987654
assert intent["publicationAuthorized"] is False
assert intent["signedArtifactsVerified"] is False
assert intent["independentSigstoreAudits"] == 0

denied = 0

def reject(category, key, value):
    global denied
    objects = [copy.deepcopy(receipt), copy.deepcopy(event),
               copy.deepcopy(run), copy.deepcopy(branch), dict(env)]
    target = {"receipt": 0, "event": 1, "run": 2, "branch": 3, "env": 4}[category]
    objects[target][key] = value
    try:
        m.validate(*objects)
    except m.Denied:
        denied += 1
        return
    raise AssertionError("R08 forged source accepted: " + category + "." + key)

for key, value in [
    ("GITHUB_ACTOR", "ShutenOishi"), ("GITHUB_EVENT_NAME", "schedule"),
    ("GITHUB_REF", "refs/tags/v1"), ("GITHUB_RUN_ATTEMPT", "2"),
    ("GITHUB_JOB", "signed_audit_first"), ("GITHUB_SHA", "e"*40),
    ("GITHUB_RUN_ID", "987654"), ("GITHUB_REPOSITORY", "pgextwin/build"),
]:
    reject("env", key, value)
for key, value in [
    ("actor", {"login": "ShutenOishi", "id": 1}),
    ("triggering_actor", {"login": "ShutenOishi"}),
    ("id", 123455), ("run_attempt", 2), ("head_sha", "e"*40),
    ("head_branch", "dev"), ("event", "schedule"),
    ("path", ".github/workflows/update-watch.yml"),
    ("status", "completed"), ("conclusion", "success"),
]:
    reject("run", key, value)
for key, value in [
    ("protected", False), ("commit", {"sha": "e"*40})
]:
    reject("branch", key, value)
for key, value in [
    ("result", "UPDATE_PRESENT_NOT_AUTHORIZED"), ("result", "FAILED"),
    ("localRunId", 987654), ("localRunAttempt", 2),
    ("sourceKind", "MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"),
    ("centralSourceRunId", 9876541),
    ("centralSourceHeadSha", "e"*40),
    ("centralSourceArtifactId", 111),
    ("centralSourceRequestId", "r-20261029-r06prepareother01"),
    ("centralSourceRawRequestSha256", "x"*64),
    ("centralOriginalOuterZipSha256Verified", "e"*64),
    ("requestId", "r-20261030-r06coordlocalother01"),
    ("publicationAuthorized", True), ("runtimeEnabled", True),
    ("publisherSourceKindAuthorized", True), ("candidateCreated", True),
    ("genuineSchedule", True),
]:
    reject("receipt", key, value)
reject("event", "sender", {"login": m.ACTOR, "id": 10, "type": "Bot"})
reject("event", "inputs", {**event["inputs"], "mode": "PUBLISH_ELIGIBLE"})
reject("event", "inputs", {**event["inputs"], "source_run_id": "987650"})
reject("event", "inputs", {**event["inputs"], "local_main_sha": "f"*40})
reject("event", "ref", "refs/heads/dev")
assert denied >= 40
workflow_text = Path("scripts/issue311-r08-app-oidc-intent.py").read_text()
for token in ("read_get(", "R08_AUTHENTIC_APP_SIGNING_INTENT_ONLY",
              "signedArtifactsVerified", "independentSigstoreAudits",
              "publisherSourceKindAuthorized", "publicationAuthorized"):
    assert token in workflow_text
assert "release create" not in workflow_text
print(f"R08_APP_SOURCE_OIDC_INTENT_NEGATIVE_PASS tests={denied}; OFFLINE_ONLY; NO_SIGNING_CREDIT")
