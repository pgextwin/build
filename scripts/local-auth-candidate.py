#!/usr/bin/env python3
"""Derive and authorize a local-auth candidate from protected GitHub state."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.parse import quote

import candidate_branch
import github_contents


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidate = load_script("candidate-update")
fleet = load_script("fleet-control")
live = load_script("local-auth-live")
verifier = live.verifier
ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com/repos/"
BUILD = "pgextwin/build"
WATCH_WORKFLOW = ".github/workflows/fleet-upstream-watch.yml"
AUTHORITY = "metadata/local-candidate-authority.json"
MANIFEST = "metadata/automation-fleet.json"
EXTENSION = "config/extension.json"
LEGACY_WATCH = "config/update-watch.json"
LIFECYCLE = "metadata/postgresql.json"
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
PGTAP_LICENSE_HEADING = re.compile(rb"(?m)^Copyright and License\n-+\n\n")


def need(condition, code):
    if not condition:
        raise verifier.TicketRejected(code)


def file_at(fetch, repository, path, sha):
    need(type(path) is str and path and all(
        part not in ("", ".", "..") for part in path.split("/"))
        and not PurePosixPath(path).is_absolute(), "INVALID_REPOSITORY_PATH")
    return fetch(f"{API}{repository}/contents/{quote(path, safe='/')}?ref={sha}")


def protected_sha(fetch, repository):
    branch = fetch(API + repository + "/branches/main")
    sha = branch["commit"]["sha"]
    verifier._hex(sha, 40, "INVALID_MAIN_SHA")
    need(branch.get("name") == "main" and branch.get("protected") is True, "MAIN_NOT_PROTECTED")
    return sha


def load_authority(fetch):
    central = protected_sha(fetch, BUILD)
    policy = github_contents.decode_json_file(file_at(fetch, BUILD, AUTHORITY, central), AUTHORITY)
    return central, policy


def enforce_policy(policy, now):
    need(policy.get("mode") != "DENY", "DENY_MODE")
    need(policy.get("mode") == "ENFORCE", "MODE_NOT_IMPLEMENTED")
    need(policy.get("issuerKeyId") == live.ISSUER_KEY_ID
         and policy.get("targetSet") == {"path": MANIFEST, "schemaVersion": 1},
         "INVALID_POLICY")
    verifier._policy_key({"policyEpoch": policy["policyEpoch"],
                          "issuerKeyId": policy["issuerKeyId"]}, policy, now)


def build_matrix(extension, now):
    with TemporaryDirectory() as directory:
        config = Path(directory) / "extension.json"
        output = Path(directory) / "outputs"
        config.write_bytes(verifier.canonical_json(extension))
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(ROOT / "scripts/resolve-matrix.ps1"),
             "-ExtensionConfigPath", str(config), "-PostgreSqlConfigPath", str(ROOT / LIFECYCLE),
             "-EffectiveDate", now.date().isoformat()],
            env=dict(os.environ, GITHUB_OUTPUT=str(output)), capture_output=True, timeout=45)
        need(result.returncode == 0, "MATRIX_RESOLUTION_FAILED")
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
    return outputs["verify_upstream_license"], json.loads(outputs["matrix"])["include"]


def versioned_sources(extension, repository, target_sha, fetch, now):
    upstream = extension["upstream"]["repository"]
    need(REPOSITORY.fullmatch(upstream), "INVALID_UPSTREAM_REPOSITORY")
    # Uniform licenses and common unchanged source pins often share blobs.
    blobs = {}

    def license_at(repo, path, sha):
        identity = (repo, path, sha)
        if identity not in blobs:
            blobs[identity] = github_contents.decode_file(file_at(fetch, *identity), path)
        return blobs[identity]

    verify, matrix = build_matrix(extension, now)
    pgtap_readme_license = (verify == "false" and repository == "pgextwin/pgtap"
                            and upstream == "theory/pgtap")
    need(verify == "true" or pgtap_readme_license, "LICENSE_VERIFICATION_REQUIRED")
    sources = []
    for entry in matrix:
        commit = entry["upstreamCommit"]
        verifier._hex(commit, 40, "INVALID_UPSTREAM_COMMIT")
        licenses = []
        upstream_licenses = 0
        for mapping in entry["licenseFiles"]:
            origin = mapping.get("origin")
            if origin is None:
                local, original = mapping["repositoryPath"], mapping["upstreamPath"]
                raw = license_at(upstream, original, commit)
                if pgtap_readme_license:
                    need((local, original) == ("LICENSE", "README.md"), "INVALID_PGTAP_LICENSE_MAPPING")
                    sections = PGTAP_LICENSE_HEADING.split(raw)
                    need(len(sections) == 2, "INVALID_PGTAP_LICENSE_SECTION")
                    # pgTap places the complete license at the end of README.md.
                    raw = sections[1]
                need(raw == license_at(repository, local, target_sha), "VERSIONED_LICENSE_MISMATCH")
                licenses.append(dict(mapping, sha256=hashlib.sha256(raw).hexdigest()))
                upstream_licenses += 1
            elif origin in ("packaging", "build"):
                expected = mapping.get("sha256")
                verifier._hex(expected, 64, "INVALID_LICENSE_SHA256")
                raw = license_at(repository, mapping["repositoryPath"], target_sha)
                need(hashlib.sha256(raw).hexdigest() == expected, "VERSIONED_LICENSE_MISMATCH")
                licenses.append(dict(mapping, sha256=expected))
            else:
                raise verifier.TicketRejected("INVALID_LICENSE_ORIGIN")
        need(licenses and upstream_licenses >= 1, "MISSING_VERSIONED_LICENSE")
        sources.append({"major": entry["major"], "ref": entry["upstreamRef"],
                        "version": entry["upstreamVersion"], "commit": commit,
                        "licenses": licenses})
    need(sources, "MISSING_VERSIONED_SOURCES")
    return sources


def prepare(repository, target_sha, consumer_run_id, *, fetch=candidate.api, now=None):
    now = now or datetime.now(timezone.utc)
    central, policy = load_authority(fetch)
    enforce_policy(policy, now)
    need(candidate.execute("git", "-C", str(ROOT), "rev-parse", "HEAD") == central,
         "CENTRAL_CHECKOUT_CHANGED")
    registry_file = file_at(fetch, BUILD, MANIFEST, central)
    registry = github_contents.decode_json_file(registry_file, MANIFEST)
    entries = fleet.validate(registry)
    need(repository in entries and entries[repository]["candidateEnabled"] is True,
         "REPO_NOT_IN_FLEET")
    need(protected_sha(fetch, repository) == target_sha, "TARGET_MAIN_CHANGED")
    repo = fetch(API + repository)
    need(repo.get("full_name") == repository and repo.get("default_branch") == "main",
         "TARGET_REPOSITORY_MISMATCH")
    verifier._positive_integer(repo["id"], "TARGET_REPOSITORY_MISMATCH")
    verifier._positive_integer(consumer_run_id, "INVALID_CONSUMER_RUN")
    run = fetch(f"{API}{BUILD}/actions/runs/{consumer_run_id}")
    need(run.get("id") == consumer_run_id and run.get("head_sha") == central
         and run.get("head_branch") == "main" and run.get("event") == "schedule"
         and run.get("path") == WATCH_WORKFLOW and run.get("run_attempt") == 1
         and run.get("status") == "in_progress"
         and run.get("repository", {}).get("full_name") == BUILD
         and run.get("head_repository", {}).get("full_name") == BUILD, "INVALID_CONSUMER_RUN")

    extension = github_contents.decode_json_file(
        file_at(fetch, repository, EXTENSION, target_sha), EXTENSION)
    try:
        legacy_watch = github_contents.decode_json_file(
            file_at(fetch, repository, LEGACY_WATCH, target_sha), LEGACY_WATCH)
    except candidate.WatchError as exc:
        if not isinstance(exc.__cause__, HTTPError) or exc.__cause__.code != 404:
            raise
        legacy_watch = None
    watch = candidate.resolve_watch(extension, legacy_watch)
    candidate_policy = candidate.publication_policy.load_candidate_policy(ROOT)
    branch_style = candidate_branch.branch_style_for_repository(repository, extension["name"])
    allowed, _ = fleet.decide(registry, "pgextwin/" + extension["name"], extension, watch,
                              "candidate", candidate_policy)
    need(allowed, "CANDIDATE_DISABLED")
    plan = candidate.plan(extension, watch, candidate_policy, fetch=fetch,
                          lifecycle=candidate.read(ROOT / LIFECYCLE), branch_style=branch_style)
    need(plan["status"] == "candidate" and plan["updates"] and all(
        not update["pinOnly"] and not update["initialOnly"] for update in plan["updates"]),
        "STABLE_UPDATE_REQUIRED")
    updated = candidate.apply(extension, plan, pin_remaining=True, fetch=fetch)
    sources = versioned_sources(updated, repository, target_sha, fetch, now)
    need(protected_sha(fetch, repository) == target_sha and protected_sha(fetch, BUILD) == central,
         "PROTECTED_MAIN_CHANGED")
    inputs = {
        "operation": "candidate", "consumerRunId": consumer_run_id,
        "repository": repository, "plan": {k: v for k, v in plan.items() if k != "detectedAt"},
        "sources": sources,
    }
    bindings = {
        "operation": "candidate", "repository": repository, "repositoryId": repo["id"],
        "targetMainSha": target_sha, "policySha": central, "centralMainSha": central,
        "verifierSha": central, "manifestBlob": registry_file["sha"],
        "upstreamSourcesSha256": hashlib.sha256(verifier.canonical_json(sources)).hexdigest(),
        "issuerKeyId": policy["issuerKeyId"], "policyEpoch": policy["policyEpoch"],
    }
    return policy, frozenset(entries), bindings, verifier.canonical_json(inputs)


def authorize(ticket, inputs, issuance, prepared, *, now, api=live.github_get):
    policy, repositories, expected, fresh_inputs = prepared
    enforce_policy(policy, now)
    evidence = live.verify_live_binding(
        ticket, inputs, policy, repositories, now, issuance_policy=issuance, api=api)
    need(all(ticket.get(field) == value for field, value in expected.items())
         and inputs == fresh_inputs, "CANDIDATE_BINDING_MISMATCH")
    return dict(evidence, status="AUTHORIZED_CANDIDATE", authorized=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--consumer-run", required=True, type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy, _, bindings, inputs = prepare(args.repository, args.target, args.consumer_run)
        args.output.mkdir(exist_ok=True)
        (args.output / "inputs.json").write_bytes(inputs)
        (args.output / "bindings.json").write_bytes(verifier.canonical_json(bindings))
        (args.output / "issuer-public-key.txt").write_text(policy["issuerPublicKey"] + "\n")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print("Local authorization candidate refused: " + str(exc), file=sys.stderr)
        sys.exit(1)
