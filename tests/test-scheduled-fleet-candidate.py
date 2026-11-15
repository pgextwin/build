#!/usr/bin/env python3
"""Offline hostile fixtures: completed central daily proof cannot mint PUBLISH."""
from __future__ import annotations
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scheduled_fleet", ROOT / "scripts/verify-scheduled-fleet-candidate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

registered = json.loads((ROOT / "metadata/automation-fleet.json").read_text("utf-8"))


def contents_payload(doc, path="metadata/automation-fleet.json"):
    raw = json.dumps(doc, indent=2).encode("utf-8")
    return {
        "path": path,
        "encoding": "base64",
        "size": len(raw),
        "sha": m.git_blob_sha(raw),
        "content": base64.b64encode(raw).decode("ascii"),
    }


now = datetime.now(timezone.utc).replace(microsecond=0)
iso = lambda dt: dt.isoformat()
old = now - timedelta(minutes=4)
end = now - timedelta(minutes=3)
good_sha = "a" * 40
build_sha = "b" * 40
pinned_sha = "1" * 40
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
        for r in sorted(m.protected_fleet(registered))]
for item in rows:
    if item["repository"] == repo:
        item["status"] = "update-available"
        item["updates"] = [{"version": "v1.99", "commit": "c" * 40}]
report = {
    "schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
    "publication": "DENY", "candidatePrCreated": False, "fleetSize": len(rows),
    "indeterminate": 0, "generatedAt": iso(end), "updatesDetected": 1,
    "extensions": rows,
}
def check(document=report, event=run, bbranch=None, target=None, repository=repo,
          head=good_sha, pin=build_sha, live_replay=False,
          source_equivalent=False, registry=registered, workflow_sha=build_sha):
    return m.validate(document, event, bbranch or branch(build_sha),
                      target or branch(good_sha), repository, head, pin, now,
                      live_replay=live_replay,
                      source_equivalent=source_equivalent,
                      registry=registry, workflow_sha=workflow_sha)

for removed in ("COHORT_14", "COHORT_3", "OLD", "NEW"):
    assert not hasattr(m, removed), removed
assert "metadata/automation-fleet.json" not in m.REPLAY_SOURCE_PATHS
assert len(m.REPLAY_SOURCE_PATHS) == 5

# Live manifest is never read implicitly from the pinned checkout.
for fn in (lambda: m.protected_fleet(), lambda: m.replay_live_fleet("opaque-token")):
    try:
        fn()
    except m.Denied:
        pass
    else:
        raise AssertionError("implicit checkout manifest fallback was not denied")

with patch.object(m, "api", return_value=contents_payload(registered)) as fetch_manifest:
    assert m.protected_fleet(commit_sha=build_sha, token="opaque-token") == m.protected_fleet(registered)
    assert fetch_manifest.call_count == 1
    assert fetch_manifest.call_args.args[0] == (
        m.HOST + m.BUILD + "/contents/metadata/automation-fleet.json?ref=" + build_sha
    )
bad_contents = contents_payload(registered)
bad_contents["sha"] = "0" * 40
with patch.object(m, "api", return_value=bad_contents):
    try:
        m.protected_fleet(commit_sha=build_sha, token="opaque-token")
    except m.Denied:
        pass
    else:
        raise AssertionError("tampered Contents blob SHA accepted")

assert check() == "candidate"
# Same unified rule applies to historical 14-cohort repos too.
assert check(repository="pgextwin/pg_bigm") == "none"
# The independent fresh GET-only replay is not the central ZIP; it must
# maintain the same protected-main, live-fleet, candidate-only contract.
assert check(live_replay=True) == "candidate"

# A newly registered entry is permitted after explicit protected registration,
# complete live-fleet schedule proof, and an immutable reusable-workflow SHA.
# When the caller pin differs from both current build main and scheduled head,
# the 5-file code closure must match both refs.
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
future_report["fleetSize"] = len(future_report["extensions"])
future_report["updatesDetected"] = 2
assert m.protected_fleet(future_policy) == m.protected_fleet(registered) | {future_repo}
assert m.validate(future_report, run, branch(build_sha), branch(good_sha),
                  future_repo, good_sha, build_sha, now,
                  registry=future_policy, workflow_sha=build_sha) == "candidate"
# (a) Caller registered after pin froze is authorized when code closure matches.
assert m.validate(future_report, run, branch(build_sha), branch(good_sha),
                  future_repo, good_sha, pinned_sha, now,
                  source_equivalent=True, registry=future_policy,
                  workflow_sha=pinned_sha) == "candidate"
# Without code-closure equivalence, a pinned SHA differing from both refs DENIES.
try:
    m.validate(future_report, run, branch(build_sha), branch(good_sha),
               future_repo, good_sha, pinned_sha, now,
               source_equivalent=False, registry=future_policy,
               workflow_sha=pinned_sha)
except m.Denied:
    pass
else:
    raise AssertionError("cross-SHA caller accepted without code-closure equivalence")
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
# (e) Central report fleetSize / row set differing from the live manifest -> DENY.
for field in ("fleetSize", "extensions", "updatesDetected"):
    broken = deepcopy(future_report)
    if field == "fleetSize":
        broken[field] = len(rows)
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
swapped_report = deepcopy(future_report)
swapped_report["extensions"][-1]["repository"] = "pgextwin/other_repo"
try:
    m.validate(swapped_report, run, branch(build_sha), branch(good_sha),
               future_repo, good_sha, build_sha, now,
               registry=future_policy, workflow_sha=build_sha)
except m.Denied:
    pass
else:
    raise AssertionError("mismatched row set vs live manifest accepted")
# (b) Live manifest missing any HISTORICAL_FLOOR repository -> DENY.
for idx in range(len(m.HISTORICAL_FLOOR)):
    missing_floor = deepcopy(future_policy)
    missing_floor["entries"].pop(idx)
    try:
        m.protected_fleet(missing_floor)
    except m.Denied:
        pass
    else:
        raise AssertionError("live manifest missing HISTORICAL_FLOOR repo accepted")
for mutated in (
    {**future_policy, "entries": future_policy["entries"] + [future_entry]},
    {**future_policy, "entries": future_policy["entries"] + [
        {**future_entry, "repository": "bad/unknown"}]},
):
    try:
        m.protected_fleet(mutated)
    except m.Denied:
        pass
    else:
        raise AssertionError("untrusted or duplicate fleet registry accepted")
# (d) detector_sha != workflow_sha -> DENY.
try:
    m.validate(future_report, run, branch(build_sha), branch(good_sha),
               future_repo, good_sha, build_sha, now,
               registry=future_policy, workflow_sha="e" * 40)
except m.Denied:
    pass
else:
    raise AssertionError("detector_sha != workflow_sha accepted")

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
denials.append(("detector_sha != workflow_sha", lambda: check(pin="e" * 40)))
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
                                 "GITHUB_RUN_ATTEMPT": "1",
                                 "PGEXTWIN_WORKFLOW_SHA": build_sha}):
        responses = [branch(build_sha), contents_payload(registered),
                     branch(good_sha), {"workflow_runs": records}]
        if records:
            responses.append(latest_fail)
        with patch.object(m, "api", side_effect=responses):
            try:
                m.run(repo, good_sha, build_sha, "opaque-token")
            except m.Deferred as e:
                assert str(e) == expected_reason
            else:
                raise AssertionError("failed or missing central schedule created a candidate")
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": build_sha,
                                 "PGEXTWIN_WORKFLOW_SHA": build_sha,
                                 "GH_TOKEN": "never-log-secret",
                                 "GITHUB_OUTPUT": str(output)}):
        with patch.object(m, "run", side_effect=m.Deferred("LATEST_GENUINE_CENTRAL_SCAN_NOT_SUCCESSFUL")):
            assert m.main() == 0
    assert output.read_text() == "mode=deferred\n"
print("PASS: unavailable genuine central schedule is safe deferred, not candidate or publish")


# A scheduled run delayed past the original strict three-hour TTL must never
# trigger an expensive repository replay or create a candidate. It is
# operationally DEFERRED (same as missing/failed schedule), not a green proof.
expired = deepcopy(run)
expired["created_at"] = iso(now - timedelta(hours=4))
expired["updated_at"] = iso(now - timedelta(hours=4, minutes=-1))
expired["id"] = 99818
def expired_run_check(original):
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1",
                                 "PGEXTWIN_WORKFLOW_SHA": build_sha}):
        with patch.object(m, "api", side_effect=[
            branch(build_sha), contents_payload(registered),
            branch(good_sha), {"workflow_runs": [original]}, original
        ]) as getter:
            try:
                m.run(repo, good_sha, build_sha, "opaque-token")
            except m.Deferred as exc:
                assert str(exc) == "LATEST_GENUINE_CENTRAL_SCAN_EXPIRED"
                assert getter.call_count == 5
            else:
                raise AssertionError("expired central schedule was not safely deferred")
expired_run_check(expired)
bad_clock = deepcopy(expired)
bad_clock["updated_at"] = iso(now + timedelta(days=1))
with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_RUN_ATTEMPT": "1",
                             "PGEXTWIN_WORKFLOW_SHA": build_sha}):
    with patch.object(m, "api", side_effect=[
        branch(build_sha), contents_payload(registered),
        branch(good_sha), {"workflow_runs": [bad_clock]}, bad_clock
    ]):
        try:
            m.run(repo, good_sha, build_sha, "opaque-token")
        except m.Denied:
            pass
        else:
            raise AssertionError("forged future run clock was not hard denied")
bad_actor = deepcopy(expired)
bad_actor["event"] = "workflow_dispatch"
with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                             "GITHUB_REF": "refs/heads/main",
                             "GITHUB_RUN_ATTEMPT": "1",
                             "PGEXTWIN_WORKFLOW_SHA": build_sha}):
    with patch.object(m, "api", side_effect=[
        branch(build_sha), contents_payload(registered),
        branch(good_sha), {"workflow_runs": [bad_actor]}, bad_actor
    ]):
        try:
            m.run(repo, good_sha, build_sha, "opaque-token")
        except m.Denied:
            pass
        else:
            raise AssertionError("forged dispatch accepted as schedule")
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": build_sha,
                                 "PGEXTWIN_WORKFLOW_SHA": build_sha,
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
        if url == m.HOST + m.BUILD + "/contents/metadata/automation-fleet.json?ref=" + build_sha:
            return contents_payload(registered)
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
                                 "GITHUB_RUN_ATTEMPT": "1",
                                 "PGEXTWIN_WORKFLOW_SHA": build_sha}):
        with patch.object(m, "api", side_effect=getter), \
             patch.object(m.subprocess, "run", side_effect=download), \
             patch.object(m, "replay_live_fleet", return_value=replay) as fresh_scan, \
             redirect_stdout(capture):
            try:
                result = m.run(repo, new_head, build_sha, "opaque-token")
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
        outer_metadata["digest"][7:], registry=registered)
    assert good_receipt["centralRunId"] == 12345
    assert good_receipt["centralArtifactId"] == 982
    assert good_receipt["localRunId"] == 23456
    assert good_receipt["registeredFleetCount"] == len(registered["entries"])
    assert good_receipt["originalOuterZipByteVerified"] is True
    assert good_receipt["publicationAuthorized"] is False
    for kind, digest in (("ORIGINAL_OUTER_ZIP_VERIFIED", None),
                         ("INDEPENDENT_GET_ONLY_REPLAY", outer_metadata["digest"][7:]),
                         ("ORIGINAL_EXTRACTED_UNVERIFIED_OUTER_ZIP", outer_metadata["digest"][7:]),
                         ("FORGED_ARCHIVE_KIND", None)):
        try:
            m.candidate_receipt("none", run, outer_metadata, report,
                                branch(build_sha), repo, good_sha, kind, digest,
                                registry=registered)
        except m.Denied:
            pass
        else:
            raise AssertionError("source-kind/digest spoof accepted: " + kind)
    replay = m.candidate_receipt(
        "none", run, outer_metadata, report, branch(build_sha),
        repo, good_sha, "INDEPENDENT_GET_ONLY_REPLAY",
        registry=registered)
    assert replay["originalOuterZipByteVerified"] is False
    assert replay["originalOuterZipSha256Verified"] is None
    assert replay["centralArtifactDigestMetadata"] == outer_metadata["digest"]
    future_receipt = m.candidate_receipt(
        "candidate", run, outer_metadata, future_report, branch(build_sha),
        future_repo, good_sha, "INDEPENDENT_GET_ONLY_REPLAY",
        registry=future_policy)
    assert future_receipt["registeredFleetCount"] == len(future_policy["entries"])
    try:
        m.candidate_receipt("none", run, outer_metadata, report,
                            branch(build_sha), repo, good_sha,
                            "INDEPENDENT_GET_ONLY_REPLAY")
    except m.Denied:
        pass
    else:
        raise AssertionError("candidate_receipt without live registry was accepted")
print("PASS: X02 source-kind and actual central outer ZIP SHA256 hostile fixtures")

# End-to-end m.run() coverage for live-manifest binding and unified caller rule:
# (a) caller registered after pin froze authorized via 5-file code closure;
# (b) live manifest missing HISTORICAL_FLOOR -> DENY;
# (c) code-closure blob mismatch -> DENY;
# (d) detector_sha != workflow_sha -> DENY;
# (e) central report differing from live manifest -> DENY.
def live_run(*, caller_repo=future_repo, manifest=future_policy, snapshot=future_report,
             tree=None, pin=pinned_sha, workflow_sha=pinned_sha,
             download_ok=True, replay_report=None):
    requests = []

    def getter(url, token):
        requests.append(url)
        if url == m.HOST + m.BUILD + "/branches/main":
            return branch(build_sha)
        if url == m.HOST + m.BUILD + "/contents/metadata/automation-fleet.json?ref=" + build_sha:
            return contents_payload(manifest)
        if url == m.HOST + caller_repo + "/branches/main":
            return branch(good_sha)
        if url == m.HOST + m.BUILD + "/actions/runs?event=schedule&per_page=100":
            return {"workflow_runs": [run]}
        if url == m.HOST + m.BUILD + "/actions/runs/12345":
            return run
        if url == m.HOST + m.BUILD + "/actions/runs/12345/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [{
                "id": 982, "name": "fleet-upstream-watch", "expired": False,
                "size_in_bytes": 1234, "digest": outer_metadata["digest"],
            }]}
        if url == m.HOST + m.BUILD + "/git/trees/" + build_sha + "?recursive=1":
            return pristine_tree() if tree is None else tree
        raise AssertionError("unexpected GET during live_run: " + url)

    def run_cmd(command, **kwargs):
        if command[:3] == ["gh", "run", "download"]:
            if not download_ok:
                return SimpleNamespace(returncode=1)
            destination = Path(command[-1])
            (destination / "fleet-upstream-watch.json").write_text(json.dumps(snapshot), "utf-8")
            (destination / "fleet-upstream-watch.md").write_text("central snapshot", "utf-8")
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=1, stdout=b"")

    seen_registry = []
    def fake_replay(token, registry=None):
        seen_registry.append(registry)
        return replay_report if replay_report is not None else snapshot

    receipt = {}
    with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule",
                                 "GITHUB_REF": "refs/heads/main",
                                 "GITHUB_RUN_ATTEMPT": "1",
                                 "GITHUB_RUN_ID": "23456",
                                 "PGEXTWIN_WORKFLOW_SHA": workflow_sha}):
        with patch.object(m, "api", side_effect=getter), \
             patch.object(m.subprocess, "run", side_effect=run_cmd), \
             patch.object(m, "replay_live_fleet", side_effect=fake_replay), \
             redirect_stdout(StringIO()):
            result = m.run(caller_repo, good_sha, pin, "opaque-token", receipt_out=receipt)
    return result, receipt, requests, seen_registry

mode, receipt, requests, seen_registry = live_run()
assert mode == "candidate"
assert seen_registry == []
assert any("/git/trees/" + build_sha in url for url in requests)
assert receipt["registeredFleetCount"] == len(future_policy["entries"])

# Live replay fallback threads the live manifest (not checkout file).
mode, receipt, _, seen_registry = live_run(download_ok=False)
assert mode == "candidate"
assert seen_registry == [future_policy]
assert receipt["registeredFleetCount"] == len(future_policy["entries"])
assert receipt["sourceKind"] == "INDEPENDENT_GET_ONLY_REPLAY"

# Mismatching only metadata/automation-fleet.json in tree does NOT break code-closure check
# when the live manifest itself is fetched via Contents API.
tree_with_extra = pristine_tree()
tree_with_extra["tree"].append({
    "path": "metadata/automation-fleet.json", "type": "blob", "mode": "100644",
    "sha": "9" * 40,
})
mode, _, _, _ = live_run(tree=tree_with_extra)
assert mode == "candidate"

for label, kwargs in (
    ("missing HISTORICAL_FLOOR in live manifest", {
        "manifest": {**future_policy, "entries": future_policy["entries"][1:]},
    }),
    ("code-closure blob mismatch", {
        "tree": bad_tree,
    }),
    ("detector_sha != workflow_sha", {
        "pin": "e" * 40,
    }),
    ("central report differs from live manifest", {
        "snapshot": report,
    }),
):
    try:
        live_run(**kwargs)
    except m.Denied:
        pass
    else:
        raise AssertionError("live_run failed to deny: " + label)

# replay_live_fleet scans with the supplied live registry, never checkout file.
import runpy
scanned_policies = []
def fake_run_path(path, run_name=None):
    def fake_scan(policy, fetch):
        scanned_policies.append(policy)
        return future_report
    return {"scan": fake_scan}
with patch.object(runpy, "run_path", side_effect=fake_run_path):
    assert m.replay_live_fleet("opaque-token", registry=future_policy) == future_report
assert scanned_policies == [future_policy]

# m.main() hard-denies (exit code 2, no output) when detector_sha != workflow_sha.
with TemporaryDirectory() as directory:
    output = Path(directory) / "output"
    receipt_file = Path(directory) / "receipt.json"
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": future_repo,
                                 "GITHUB_SHA": good_sha,
                                 "PGEXTWIN_DETECTOR_SHA": "e" * 40,
                                 "PGEXTWIN_WORKFLOW_SHA": pinned_sha,
                                 "PGEXTWIN_RECEIPT_PATH": str(receipt_file),
                                 "GH_TOKEN": "never-log-secret",
                                 "GITHUB_OUTPUT": str(output)}), \
         redirect_stdout(StringIO()):
        err_capture = StringIO()
        from contextlib import redirect_stderr
        with redirect_stderr(err_capture):
            assert m.main() == 2
        assert "SCHEDULED_FLEET_CANDIDATE=DENY;" in err_capture.getvalue()
    assert not output.exists()
    assert not receipt_file.exists()
print("PASS: live manifest binding, 5-file code closure, and unified caller rule")
