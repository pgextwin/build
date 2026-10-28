#!/usr/bin/env python3
"""Offline hostile fixtures: completed central daily proof cannot mint PUBLISH."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scheduled_fleet", ROOT / "scripts/verify-scheduled-fleet-candidate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

now = datetime.now(timezone.utc).replace(microsecond=0)
iso = lambda dt: dt.isoformat()
old = now - timedelta(minutes=4)
end = now - timedelta(minutes=3)
good_sha = "a" * 40
build_sha = "b" * 40
repo = "pgextwin/pgtap"
branch = lambda sha: {"protected": True, "commit": {"sha": sha}}
run = {
    "id": 12345, "event": "schedule", "path": m.WATCH_PATH,
    "head_branch": "main", "run_attempt": 1, "status": "completed",
    "conclusion": "success", "head_sha": build_sha,
    "created_at": iso(old), "updated_at": iso(end),
    "repository": {"full_name": m.BUILD},
}
rows = [{"repository": r, "mainSha": good_sha, "status": "up-to-date", "updates": []}
        for r in sorted(m.REPOSITORIES)]
for item in rows:
    if item["repository"] == repo:
        item["status"] = "update-available"
        item["updates"] = [{"version": "v1.99", "commit": "c" * 40}]
report = {
    "schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
    "publication": "DENY", "candidatePrCreated": False, "fleetSize": 17,
    "indeterminate": 0, "generatedAt": iso(end), "updatesDetected": 1,
    "extensions": rows,
}
def check(document=report, event=run, bbranch=None, target=None, repository=repo,
          head=good_sha, pin=m.COHORT_3, live_replay=False,
          source_equivalent=False):
    return m.validate(document, event, bbranch or branch(build_sha),
                      target or branch(good_sha), repository, head, pin, now,
                      live_replay=live_replay,
                      source_equivalent=source_equivalent)

assert check() == "candidate"
# The independent fresh GET-only replay is not the central ZIP; it must
# maintain the same protected-main, 17-row, candidate-only contract.
assert check(live_replay=True) == "candidate"

# A prospective 18th entry is permitted ONLY after explicit protected
# registration, complete 18-row genuine-schedule proof and a GitHub-owned
# immutable reusable-workflow source SHA. This is candidate-only, never Release.
import json
registered = json.loads((ROOT / "metadata/automation-fleet.json").read_text("utf-8"))
future_repo = "pgextwin/future_registered"
future_policy = deepcopy(registered)
future_entry = deepcopy(future_policy["entries"][-1])
future_entry["repository"] = future_repo
future_policy["entries"].append(future_entry)
future_report = deepcopy(report)
future_report["extensions"].append({
    "repository": future_repo, "mainSha": good_sha,
    "status": "update-available", "updates": [{"version": "v3.0", "commit": "c" * 40}]
})
future_report["fleetSize"] = 18
future_report["updatesDetected"] = 2
assert m.protected_fleet(future_policy) == m.HISTORICAL_FLOOR | {future_repo}
assert m.validate(future_report, run, branch(build_sha), branch(good_sha),
                  future_repo, good_sha, build_sha, now,
                  registry=future_policy, workflow_sha=build_sha) == "candidate"
for name, changed in (
    ("not registered", registered),
    ("mismatched immutable pin", future_policy),
):
    try:
        m.validate(future_report, run, branch(build_sha), branch(good_sha),
                   future_repo, good_sha,
                   "f" * 40 if name == "mismatched immutable pin" else build_sha,
                   now, registry=changed, workflow_sha=build_sha)
    except m.Denied:
        pass
    else:
        raise AssertionError("future candidate escaped protected identity gate: " + name)
for field in ("fleetSize", "extensions", "updatesDetected"):
    broken = deepcopy(future_report)
    if field == "fleetSize":
        broken[field] = 17
    elif field == "extensions":
        broken[field].pop()
    else:
        broken[field] = 1
    try:
        m.validate(broken, run, branch(build_sha), branch(good_sha),
                   future_repo, good_sha, build_sha, now,
                   registry=future_policy, workflow_sha=build_sha)
    except m.Denied:
        pass
    else:
        raise AssertionError("partial new-fleet proof accepted: " + field)
for mutated in (
    {**future_policy, "entries": future_policy["entries"][:-2] + [future_entry]},
    {**future_policy, "entries": future_policy["entries"] + [future_entry]},
    {**future_policy, "entries": future_policy["entries"] + [
        {**future_entry, "repository": "bad/unknown"}]},
):
    try:
        m.protected_fleet(mutated)
    except m.Denied:
        pass
    else:
        raise AssertionError("untrusted or missing historical fleet registry accepted")
# Even on a future row, no caller-supplied SHA may replace the actual
# immutable central reusable workflow SHA.
try:
    m.validate(future_report, run, branch(build_sha), branch(good_sha),
               future_repo, good_sha, build_sha, now,
               registry=future_policy, workflow_sha="e" * 40)
except m.Denied:
    pass
else:
    raise AssertionError("forged reusable workflow SHA accepted")

# Normal schedule-head exact match remains mandatory. Only a distinct fresh
# live replay after an authenticated immutable source-identity comparison may
# tolerate unrelated central main advances. Target main still MUST match.
drift_build = branch("d" * 40)
for replay, identical in ((False, False), (True, False), (False, True)):
    try:
        check(bbranch=drift_build, live_replay=replay, source_equivalent=identical)
    except m.Denied:
        pass
    else:
        raise AssertionError("unproven central SHA drift was authorized")
assert check(bbranch=drift_build, live_replay=True,
             source_equivalent=True) == "candidate"
try:
    check(bbranch=drift_build, target=branch("f" * 40),
          live_replay=True, source_equivalent=True)
except m.Denied:
    pass
else:
    raise AssertionError("stale target main accepted after central replay")

# The two GitHub trees and actual pinned checkout must agree on the same
# exact mode/type/blob per file. Malformed/incomplete/changed trees all DENY.
def pristine_tree():
    return {"sha": "a" * 40, "truncated": False,
            "tree": [{"path": path, "type": "blob", "mode": "100644",
                      "sha": m.git_blob_sha((ROOT / path).read_bytes())}
                     for path in m.REPLAY_SOURCE_PATHS]}

with patch.object(m, "api", return_value=pristine_tree()) as fetch:
    assert m.verify_replay_source_blobs("b" * 40, "d" * 40, "") is True
    assert fetch.call_count == 2
    assert all("/git/trees/" in call.args[0] for call in fetch.call_args_list)
with patch.object(m, "api", return_value=pristine_tree()) as fetch:
    assert m.verify_replay_source_blobs(build_sha, build_sha, "") is True
    assert fetch.call_count == 1
for variant in ("missing", "changed", "symlink", "duplicate", "truncated"):
    item = pristine_tree()
    if variant == "missing":
        item["tree"].pop()
    elif variant == "changed":
        item["tree"][0]["sha"] = "f" * 40
    elif variant == "symlink":
        item["tree"][0]["mode"] = "120000"
    elif variant == "duplicate":
        item["tree"].append(dict(item["tree"][0]))
    else:
        item["truncated"] = True
    with patch.object(m, "api", return_value=item):
        try:
            m.verify_replay_source_blobs("b" * 40, "d" * 40, "")
        except m.Denied:
            pass
        else:
            raise AssertionError("malformed identical-source claim accepted: " + variant)
# Original scheduled-tree mismatch cannot be hidden by a matching current
# tree, and no API response is accepted as authentication by itself.
bad = pristine_tree()
bad["tree"][0]["sha"] = "e" * 40
with patch.object(m, "api", side_effect=[bad, pristine_tree()]):
    try:
        m.verify_replay_source_blobs("b" * 40, "d" * 40, "")
    except m.Denied:
        pass
    else:
        raise AssertionError("original schedule scan source tampering accepted")
none = deepcopy(report)
for entry in none["extensions"]:
    if entry["repository"] == repo:
        entry["status"] = "up-to-date"
        entry["updates"] = []
none["updatesDetected"] = 0
assert check(none) == "none"
assert check(none, live_replay=True) == "none"

denials = []
for name, target, key, value in (
    ("PUBLISH", "report", "publication", "ALLOW"),
    ("unsigned candidate", "report", "candidatePrCreated", True),
    ("partial", "report", "fleetSize", 16),
    ("indeterminate", "report", "indeterminate", 1),
    ("forged date", "report", "generatedAt", iso(now - timedelta(days=2))),
    ("wrong count", "report", "updatesDetected", 4),
    ("failed run", "run", "conclusion", "failure"),
    ("unfinished", "run", "status", "in_progress"),
    ("rerun", "run", "run_attempt", 2),
    ("non-schedule", "run", "event", "workflow_dispatch"),
    ("other source", "run", "path", ".github/workflows/validate.yml"),
    ("wrong build HEAD", "run", "head_sha", "d" * 40),
    ("stale run", "run", "created_at", iso(now - timedelta(days=3))),
):
    r, event = deepcopy(report), deepcopy(run)
    if target == "report":
        r[key] = value
    else:
        event[key] = value
    denials.append((name, lambda a=r, b=event: check(a, b)))

r = deepcopy(report)
r["extensions"].append(deepcopy(r["extensions"][0]))
denials.append(("duplicate rows", lambda: check(r)))
r = deepcopy(report)
r["extensions"][0]["repository"] = "pgextwin/evil"
denials.append(("unknown repo", lambda: check(r)))
r = deepcopy(report)
r["extensions"][0]["status"] = "update-available"
denials.append(("lying status", lambda: check(r)))
r = deepcopy(report)
next(row for row in r["extensions"] if row["repository"] == repo)["mainSha"] = "d" * 40
denials.append(("stale extension main", lambda: check(r)))
denials.append(("unprotected main", lambda: check(target={"protected": False, "commit": {"sha": good_sha}})))
denials.append(("detector branch swap", lambda: check(pin=m.COHORT_14)))
denials.append(("unregistered repository", lambda: check(repository="pgextwin/evil")))
denials.append(("caller SHA drift", lambda: check(head="d" * 40)))
replay_early = deepcopy(report)
replay_early["generatedAt"] = iso(old - timedelta(minutes=10))
denials.append(("replayed fleet result predates central schedule",
                lambda: check(replay_early, live_replay=True)))
replay_future = deepcopy(report)
replay_future["generatedAt"] = iso(now + timedelta(minutes=6))
denials.append(("replayed fleet result lies in future",
                lambda: check(replay_future, live_replay=True)))
replay_bad = deepcopy(report)
replay_bad["extensions"][1]["status"] = "INDETERMINATE"
denials.append(("replayed fleet row indeterminate",
                lambda: check(replay_bad, live_replay=True)))
for name, f in denials:
    try:
        f()
    except (m.Denied, TypeError, ValueError):
        pass
    else:
        raise AssertionError("unsafe daily candidate evidence accepted: " + name)

workflow = (ROOT / ".github/workflows/operator-update-auto.yml").read_text("utf-8")
for item in (
    "github.event_name == 'schedule'",
    "permissions:\n  contents: read", "PGEXTWIN_DETECTOR_SHA:",
    "persist-credentials: false",
):
    assert item in workflow, item
for item in ("contents: write", "issues: write", "actions: write", "pull-requests: write",
             "secrets.", "PUBLISH=ALLOW", "gh release ", "build-extension-attested"):
    assert item not in workflow, item
source = (ROOT / "scripts/verify-scheduled-fleet-candidate.py").read_text("utf-8")
for item in ("def replay_live_fleet(", "FLEET_EVIDENCE=INDEPENDENT_GET_ONLY_REPLAY",
             "live_replay=live_replay", "PUBLISH=DENY"):
    assert item in source, item
assert "contents: write" not in workflow
print("PASS: 17-repo schedule proof and distinct GET-only replay plus",
      len(denials), "hostile cases; no Release token or PUBLISH")

# A failed or missing genuine central run never authorizes a candidate.
# Its original failure is preserved; local hourly preflight is labelled DEFERRED
# (not misreported as a Windows compile failure). A forged/invalid successful
# run still goes through strict validate(), so cannot take this route.
import os
from tempfile import TemporaryDirectory
latest_fail = deepcopy(run)
latest_fail["conclusion"] = "failure"
for records, expected_reason in (([latest_fail], "LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL"),
                                 ([], "NO_GENUINE_CENTRAL_FLEET_SCHEDULE")):
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1"}):
        responses = [branch(build_sha), branch(good_sha), {"workflow_runs": records}]
        if records:
            responses.append(latest_fail)
        with patch.object(m, "api", side_effect=responses):
            try:
                m.run(repo, good_sha, m.COHORT_3, "opaque-token")
            except m.Deferred as e:
                assert str(e) == expected_reason
            else:
                raise AssertionError("failed or missing central schedule created a candidate")
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": m.COHORT_3,
                                 "GH_TOKEN": "never-log-secret",
                                 "GITHUB_OUTPUT": str(output)}):
        with patch.object(m, "run", side_effect=m.Deferred("LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL")):
            assert m.main() == 0
    assert output.read_text() == "mode=deferred\n"
print("PASS: unavailable genuine central schedule is safe deferred, not candidate or publish")


# A scheduled run delayed past the original strict three-hour TTL must never
# trigger an expensive 17-repository replay or create a candidate. It is
# operationally DEFERRED (same as missing/failed schedule), not a green proof.
expired = deepcopy(run)
expired["created_at"] = iso(now - timedelta(hours=4))
expired["updated_at"] = iso(now - timedelta(hours=4, minutes=-1))
expired["id"] = 99818
def expired_run_check(original):
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1"}):
        with patch.object(m, "api", side_effect=[
            branch(build_sha), branch(good_sha),
            {"workflow_runs": [original]}, original
        ]) as getter:
            try:
                m.run(repo, good_sha, m.COHORT_3, "opaque-token")
            except m.Deferred as exc:
                assert str(exc) == "LATEST_GENUINE_CENTRAL_SCAN_EXPIRED"
                assert getter.call_count == 4
            else:
                raise AssertionError("expired central schedule was not safely deferred")
expired_run_check(expired)
bad_clock = deepcopy(expired)
bad_clock["updated_at"] = iso(now + timedelta(days=1))
with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_RUN_ATTEMPT": "1"}):
    with patch.object(m, "api", side_effect=[
        branch(build_sha), branch(good_sha),
        {"workflow_runs": [bad_clock]}, bad_clock
    ]):
        try:
            m.run(repo, good_sha, m.COHORT_3, "opaque-token")
        except m.Denied:
            pass
        else:
            raise AssertionError("forged future run clock was not hard denied")
bad_actor = deepcopy(expired)
bad_actor["event"] = "workflow_dispatch"
with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_RUN_ATTEMPT": "1"}):
    with patch.object(m, "api", side_effect=[
        branch(build_sha), branch(good_sha),
        {"workflow_runs": [bad_actor]}, bad_actor
    ]):
        try:
            m.run(repo, good_sha, m.COHORT_3, "opaque-token")
        except m.Denied:
            pass
        else:
            raise AssertionError("forged dispatch accepted as schedule")
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": m.COHORT_3,
                                 "GH_TOKEN": "never-log-secret",
                                 "GITHUB_OUTPUT": str(output)}):
        with patch.object(m, "run", side_effect=m.Deferred("LATEST_GENUINE_CENTRAL_SCAN_EXPIRED")):
            assert m.main() == 0
    assert output.read_text() == "mode=deferred\n"
print("PASS: expired genuine central scan defers only, clock and spoofing DENY")


# Regression: a central artifact can download successfully while its target
# row predates a protected packaging-main merge. Reject that stale row, then
# independently authenticate the scanner closure and replay the whole fleet.
# This is a distinct GET-only result, never acceptance of the stale archive.
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace

new_head = "f" * 40
fresh = deepcopy(report)
next(row for row in fresh["extensions"] if row["repository"] == repo)["mainSha"] = new_head

def stale_archive_run(*, original=report, replay=fresh, tree=None,
                      live_branch=None, final_branch=None):
    requests = []
    live_branch = live_branch or branch(new_head)
    target_gets = 0

    def getter(url, token):
        nonlocal target_gets
        requests.append(url)
        if url == m.HOST + m.BUILD + "/branches/main":
            return branch(build_sha)
        if url == m.HOST + repo + "/branches/main":
            target_gets += 1
            return final_branch if final_branch is not None and target_gets > 1 else live_branch
        if url == m.HOST + m.BUILD + "/actions/runs?event=schedule&per_page=100":
            return {"workflow_runs": [run]}
        if url == m.HOST + m.BUILD + "/actions/runs/12345":
            return run
        if url == m.HOST + m.BUILD + "/actions/runs/12345/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [{
                "name": "fleet-upstream-watch", "expired": False,
                "size_in_bytes": 1234,
            }]}
        if url == m.HOST + m.BUILD + "/git/trees/" + build_sha + "?recursive=1":
            return pristine_tree() if tree is None else tree
        raise AssertionError("unexpected GET during stale-archive repair: " + url)

    def download(command, **kwargs):
        destination = Path(command[-1])
        (destination / "fleet-upstream-watch.json").write_text(json.dumps(original), "utf-8")
        (destination / "fleet-upstream-watch.md").write_text("original central snapshot", "utf-8")
        return SimpleNamespace(returncode=0)

    capture = StringIO()
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1"}):
        with patch.object(m, "api", side_effect=getter), \
             patch.object(m.subprocess, "run", side_effect=download), \
             patch.object(m, "replay_live_fleet", return_value=replay) as fresh_scan, \
             redirect_stdout(capture):
            try:
                result = m.run(repo, new_head, m.COHORT_3, "opaque-token")
            except m.Denied as exc:
                return None, exc, fresh_scan.call_count, requests, capture.getvalue()
            return result, None, fresh_scan.call_count, requests, capture.getvalue()

mode, error, replay_count, requests, diagnostic = stale_archive_run()
assert mode == "candidate" and error is None and replay_count == 1
assert sum("/git/trees/" in url for url in requests) == 1
assert requests.count(m.HOST + repo + "/branches/main") == 2
assert "FRESH_FLEET_REPLAY_AFTER_PROTECTED_TARGET_MAIN_CHANGE" in diagnostic
assert "central artifact target row was not accepted" in diagnostic

# The new route cannot hide bad original evidence, alter the scanner source,
# accept an old replay, or race a second protected-main change.
bad_tree = pristine_tree()
bad_tree["tree"][0]["sha"] = "e" * 40
bad_original = deepcopy(report)
bad_original["publication"] = "ALLOW"
partial_original = deepcopy(report)
partial_original["extensions"].pop()
indeterminate_replay = deepcopy(fresh)
indeterminate_replay["indeterminate"] = 1
for name, kwargs, expected_replays in (
    ("scanner source changed", {"tree": bad_tree}, 0),
    ("original attempts PUBLISH", {"original": bad_original}, 0),
    ("original fleet incomplete", {"original": partial_original}, 0),
    ("caller schedule is stale", {"live_branch": branch("e" * 40)}, 0),
    ("replay still has old target main", {"replay": report}, 1),
    ("replay is indeterminate", {"replay": indeterminate_replay}, 1),
    ("main changes during replay", {"final_branch": branch("e" * 40)}, 1),
):
    mode, error, replay_count, _, _ = stale_archive_run(**kwargs)
    assert mode is None and isinstance(error, m.Denied), name
    assert replay_count == expected_replays, name
print("PASS: stale artifact target requires authenticated complete fresh replay;",
      "7 hostile archive/source/main-race variants DENY")

# X02: original outer ZIP bytes versus a source-typed replay receipt.
from io import BytesIO
from zipfile import ZipFile
with BytesIO() as stream:
    with ZipFile(stream, "w") as archive:
        archive.writestr("fleet-upstream-watch.json", '{"schemaVersion":1}')
        archive.writestr("fleet-upstream-watch.md", "NONPUBLISHING")
    zip_bytes = stream.getvalue()
outer_metadata = {
    "id": 982, "expired": False,
    "digest": "sha256:" + m.hashlib.sha256(zip_bytes).hexdigest()
}
assert m.original_outer_sha256(zip_bytes, outer_metadata,
                               {"schemaVersion": 1}) == outer_metadata["digest"][7:]
for name, payload, metadata, report_data in (
    ("replaced bytes", zip_bytes + b"tamper", outer_metadata, {"schemaVersion": 1}),
    ("digest movement", zip_bytes, {**outer_metadata, "digest": "sha256:" + "a"*64},
     {"schemaVersion": 1}),
    ("wrong decoded report", zip_bytes, outer_metadata, {"schemaVersion": 2}),
    ("missing metadata", zip_bytes, {"id": 982}, {"schemaVersion": 1}),
):
    try:
        m.original_outer_sha256(payload, metadata, report_data)
    except m.Denied:
        pass
    else:
        raise AssertionError("original ZIP proof accepts " + name)
with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "23456"}):
    good_receipt = m.candidate_receipt(
        "none", run, outer_metadata, report, branch(build_sha),
        repo, good_sha, "ORIGINAL_OUTER_ZIP_VERIFIED",
        outer_metadata["digest"][7:])
    assert good_receipt["centralRunId"] == 12345
    assert good_receipt["centralArtifactId"] == 982
    assert good_receipt["localRunId"] == 23456
    assert good_receipt["originalOuterZipByteVerified"] is True
    assert good_receipt["publicationAuthorized"] is False
    for kind, digest in (("ORIGINAL_OUTER_ZIP_VERIFIED", None),
                         ("INDEPENDENT_GET_ONLY_REPLAY", outer_metadata["digest"][7:]),
                         ("ORIGINAL_EXTRACTED_UNVERIFIED_OUTER_ZIP", outer_metadata["digest"][7:]),
                         ("FORGED_ARCHIVE_KIND", None)):
        try:
            m.candidate_receipt("none", run, outer_metadata, report,
                                branch(build_sha), repo, good_sha, kind, digest)
        except m.Denied:
            pass
        else:
            raise AssertionError("source-kind/digest spoof accepted: " + kind)
    replay = m.candidate_receipt(
        "none", run, outer_metadata, report, branch(build_sha),
        repo, good_sha, "INDEPENDENT_GET_ONLY_REPLAY")
    assert replay["originalOuterZipByteVerified"] is False
    assert replay["originalOuterZipSha256Verified"] is None
    assert replay["centralArtifactDigestMetadata"] == outer_metadata["digest"]
print("PASS: X02 source-kind and actual central outer ZIP SHA256 hostile fixtures")
