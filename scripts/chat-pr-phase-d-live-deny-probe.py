#!/usr/bin/env python3
"""Issue #75: real-GitHub negative evidence, protected-main read-only pilot.

Runs only from a PINNED trusted-build checkout after the caller has checked
push/main/operator/first-attempt and issued its scoped read-only credentials.
A successful probe means DENY was proved on all requested prerequisites,
NOT that a Release is authorized. No write API, dispatch, token artifact,
Release receipt or GitHub output is emitted.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
REPO = "pgextwin/plpgsql_check"
BRANCH = "auto-candidate/29d1c1984a1b44a55107"
CANDIDATE_PR = 29
CANDIDATE_RUN = 38356899464
ARTIFACT_NAME = "plpgsql_check-pg15-windows-x64"
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
PREDICATE = "https://spdx.dev/Document/v2.3"


class Denied(ValueError):
    pass


def require(ok, description):
    if not ok:
        raise Denied(description)


def load_adapter():
    spec = importlib.util.spec_from_file_location(
        "issue_75_d_adapter", ROOT / "chat-pr-phase-d-github-readonly.py")
    require(spec is not None and spec.loader is not None, "trusted adapter unavailable")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def inspect_authorization(api, expected_sha):
    """Only a real REST HTTP 404 after successful protected main read counts."""
    branch = api.get("repos/" + REPO + "/branches/main")
    require(type(branch) is dict and branch.get("protected") is True
            and type(branch.get("commit")) is dict
            and branch["commit"].get("sha") == expected_sha,
            "protected main SHA no longer matches")
    directory = api.get("repos/" + REPO
                        + "/contents/.github/release-authorizations?ref="
                        + expected_sha, allow_404=True)
    require(directory is None, "unexpected real authorization directory")
    return "AUTHORIZATION_DIRECTORY_ABSENT"


def inspect_candidate(api):
    candidate = api.get("repos/" + REPO + "/pulls/" + str(CANDIDATE_PR))
    require(type(candidate) is dict
            and candidate.get("number") == CANDIDATE_PR
            and candidate.get("state") == "open"
            and candidate.get("draft") is True
            and candidate.get("merged") is False
            and type(candidate.get("head")) is dict
            and candidate["head"].get("ref") == BRANCH
            and type(candidate["head"].get("sha")) is str
            and re.fullmatch(r"[0-9a-f]{40}", candidate["head"]["sha"]),
            "candidate state differs from known unmerged draft")
    run = api.get("repos/" + REPO + "/actions/runs/" + str(CANDIDATE_RUN))
    require(type(run) is dict and run.get("id") == CANDIDATE_RUN
            and run.get("head_sha") == candidate["head"]["sha"]
            and run.get("head_branch") == BRANCH
            and run.get("event") == "workflow_dispatch"
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and type(run.get("repository")) is dict
            and run["repository"].get("full_name") == REPO,
            "candidate Windows run not exact trusted identity")
    return "CANDIDATE_DRAFT_UNMERGED"


def command(argv):
    """No arbitrary command. Caller never gets stdout/stderr or raw errors."""
    allowed = (
        argv[:3] == ("gh", "run", "download")
        or argv[:3] == ("gh", "attestation", "verify")
    )
    require(allowed, "read-only GitHub command allowlist denied")
    try:
        proc = subprocess.run(argv, text=True, capture_output=True,
                              timeout=120, check=False)
        return proc.returncode
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("GitHub read-only CLI unavailable") from None


def inspect_signed_candidate(command_fn=command):
    """Prove signed-candidate acceptance unavailable using actual PG15 ZIP.

    Nonzero attestation verification does not imply a cryptographic claim that
    no signature exists: it means the required trust chain was NOT VERIFIED.
    """
    with tempfile.TemporaryDirectory(prefix="issue75-readonly-deny-") as temp:
        folder = Path(temp)
        rc = command_fn(("gh", "run", "download", str(CANDIDATE_RUN),
                         "--repo", REPO, "--name", ARTIFACT_NAME,
                         "--dir", str(folder)))
        require(rc == 0, "candidate artifact download unavailable")
        zips = [p for p in folder.rglob("*.zip") if p.is_file()]
        require(len(zips) == 1 and zips[0].stat().st_size > 0,
                "candidate ZIP missing/duplicated")
        zip_path = str(zips[0])
        base = ("gh", "attestation", "verify", zip_path,
                "--repo", REPO, "--signer-workflow", SIGNER)
        signer = command_fn(base)
        sbom = command_fn(base + ("--predicate-type", PREDICATE))
        require(type(signer) is int and type(sbom) is int,
                "attestation result ambiguous")
        require(signer != 0 or sbom != 0,
                "candidate unexpectedly has both required signed proofs")
        return "CANDIDATE_SIGNATURE_NOT_VERIFIED"


def negative_adapter_check(adapter):
    """Execute real Phase D adapter; only intended no-auth denial is expected."""
    try:
        adapter.capture()
    except adapter_denial_types(adapter) as exc:
        # Log no error body. Only known fail-closed identity statuses are
        # accepted as EXPECTED; a token/scope/Classic/API failure must not pass.
        require(str(exc) in {
            "no unique real authorization file",
            "authorization squash PR linkage absent/ambiguous",
        }, "unexpected Phase D adapter failure")
        return "REAL_ADAPTER_AUTHORIZATION_DENIED"
    raise Denied("unexpected complete Phase D authorization")


def adapter_denial_types(adapter):
    return (load_adapter().Blocked,)


def verify_live_negative_probe(*, adapter_module, evidence_token, admin_token,
                               event, sha, actor, attempt, repo, ref, event_name):
    require(repo == REPO and ref == "refs/heads/main" and event_name == "push"
            and actor == "ShutenOishi" and attempt == "1"
            and type(sha) is str and re.fullmatch(r"[0-9a-f]{40}", sha),
            "untrusted main-only push context")
    require(type(event) is dict and event.get("ref") == ref
            and event.get("after") == sha
            and type(event.get("repository")) is dict
            and event["repository"].get("full_name") == REPO
            and type(event.get("sender")) is dict
            and event["sender"].get("login") == actor
            and event["sender"].get("type") == "User",
            "GitHub event/operator evidence mismatch")
    reader = adapter_module.PilotReadOnly(evidence_token)
    results = (
        inspect_authorization(reader, sha),
        inspect_candidate(reader),
        inspect_signed_candidate(),
    )
    pilot = adapter_module.PhaseDGitHubAdapter(
        admin_token, evidence_token, event=event, main_sha=sha,
        actor=actor, allowed_operators={actor})
    # Avoid treating the expected missing authorization as a completed probe.
    try:
        pilot.capture()
    except adapter_module.Blocked as exc:
        require(str(exc) in {
            "no unique real authorization file",
            "authorization squash PR linkage absent/ambiguous",
        }, "unexpected real adapter rejection")
    else:
        raise Denied("full Phase D unexpectedly authorized")
    return results + ("REAL_ADAPTER_AUTHORIZATION_DENIED",)


def main():
    try:
        results = verify_live_negative_probe(
            adapter_module=load_adapter(),
            evidence_token=os.environ["EVIDENCE_TOKEN"],
            admin_token=os.environ["ADMIN_TOKEN"],
            event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()),
            sha=os.environ["GITHUB_SHA"], actor=os.environ["GITHUB_ACTOR"],
            attempt=os.environ["GITHUB_RUN_ATTEMPT"],
            repo=os.environ["GITHUB_REPOSITORY"], ref=os.environ["GITHUB_REF"],
            event_name=os.environ["GITHUB_EVENT_NAME"],
        )
        for item in results:
            print("EXPECTED_DENY: " + item)
        print("DRY_RUN_NEGATIVE_PROOF_ONLY; publishableReceipt=false")
        return 0
    except Exception:
        # Credentials, JSON, headers, actor data or errors MUST NOT reach logs.
        print("DENY: authenticated Phase D live probe unverified; publishableReceipt=false")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
