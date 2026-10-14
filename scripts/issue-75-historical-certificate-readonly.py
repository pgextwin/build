#!/usr/bin/env python3
"""PRE-G4 historical public Release: live read-only certificate/run-attempt audit.

Only callable from the protected build/main push audit workflow. Fixtures are
never evidence, and this code is not imported by any publishing component.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


public = load("verify-public-signed-release-readonly.py", "public_signed")
offline = load("issue-75-attempt-provenance-readonly.py", "offline_attempt")
RUN_ID = 38128142145
ATTEMPT = 1
EXPECTED_WORKFLOW = (
    "pgextwin/build/.github/workflows/issue-75-historical-certificate-readonly.yml"
    "@refs/heads/main"
)
FIELDS = ("issuer", "runnerInvocationURI", "buildSignerURI", "buildSignerDigest",
          "sourceRepositoryURI", "sourceRepositoryDigest", "sourceRepositoryRef",
          "buildTrigger")


class Blocked(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise public.Deny(reason)


def read_only_gh(*args):
    """Permit only installed CLI introspection and one exact build branch GET."""
    require(args in (("--version",), ("attestation", "verify", "--help"),
                     ("api", "repos/pgextwin/build/branches/main")),
            "unallowlisted CLI introspection")
    try:
        p = subprocess.run(("gh",) + args, capture_output=True, text=True,
                           check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("gh CLI unavailable or timeout") from exc
    if p.returncode != 0:
        raise Blocked("gh CLI introspection/API unavailable")
    return p.stdout


def preflight(env, checkout_sha, branch):
    require(env.get("GITHUB_REPOSITORY") == "pgextwin/build"
            and env.get("GITHUB_EVENT_NAME") == "push"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_WORKFLOW_REF") == EXPECTED_WORKFLOW
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is not None
            and env.get("GITHUB_ACTOR", "") != ""
            and env["GITHUB_SHA"] == checkout_sha
            and branch.get("protected") is True
            and (branch.get("commit") or {}).get("sha") == checkout_sha,
            "untrusted audit event/ref/actor/attempt/checkout or unprotected/stale main")


def release_identity(release):
    return (release.get("id"), release.get("tag_name"),
            release.get("target_commitish"), release.get("draft"),
            release.get("prerelease"), release.get("updated_at"),
            sorted((a.get("id"), a.get("name"), a.get("size"), a.get("digest"),
                    a.get("state"), a.get("updated_at"))
                   for a in release.get("assets", [])))


def matching_evidence(results, predicate, name, digest):
    require(type(results) is list, "gh JSON verification result not a list")
    matches = []
    for item in results:
        if type(item) is not dict or type(item.get("verificationResult")) is not dict:
            continue
        statement = item["verificationResult"].get("statement")
        if type(statement) is not dict or statement.get("predicateType") != predicate:
            continue
        subjects = statement.get("subject")
        if type(subjects) is not list:
            continue
        if any(type(s) is dict and s.get("name") == name
               and type(s.get("digest")) is dict
               and s["digest"].get("sha256") == digest for s in subjects):
            matches.append(item)
    require(len(matches) == 1, "missing/ambiguous exact verified ZIP subject")
    return matches[0]


def certified_claims(item, *, predicate, name, digest, sbom, run):
    """Interpret only a verified CLI result, not user-controlled predicate claims.

    Caller MUST obtain item from a successful real gh attestation verify,
    with exact signer/source digests, never from a fixture or untrusted file.
    """
    verified = item["verificationResult"]
    signature = verified.get("signature")
    if type(signature) is not dict or type(signature.get("certificate")) is not dict:
        raise Blocked("verified signature.certificate missing or unknown schema")
    cert = signature["certificate"]
    timestamps = verified.get("verifiedTimestamps")
    if type(timestamps) is not list or not timestamps:
        raise Blocked("verifiedTimestamps missing/empty")
    if any(field not in cert for field in FIELDS):
        raise Blocked("verified certificate required fields missing: "
                      + ",".join(k for k in FIELDS if k not in cert)
                      + "; actual certificate keys: " + ",".join(sorted(cert)))
    uri = cert["runnerInvocationURI"]
    if type(uri) is not str:
        raise Blocked("runnerInvocationURI not a string")
    match = re.fullmatch(
        r"https://github\.com/pgextwin/plpgsql_check/actions/runs/([1-9][0-9]*)"
        r"/attempts/([1-9][0-9]*)", uri)
    if match is None:
        raise Blocked("certificate runnerInvocationURI lacks canonical /attempts/N")
    require((int(match[1]), int(match[2])) == (RUN_ID, ATTEMPT),
            "certificate run ID/attempt differs from fixed historical run")
    offline.check_run(run, public.REPO, public.TAG_SHA, RUN_ID, ATTEMPT)
    with_sbom = sbom if predicate == public.SPDX else {}
    offline.check_statement([item], predicate, name, digest, with_sbom,
                            public.REPO, public.TAG_SHA, offline.SIGNER_SHA, uri)
    return {field: cert[field] for field in FIELDS} | {
        "verifiedTimestampCount": len(timestamps)}


def version_and_flags():
    version = read_only_gh("--version").splitlines()[0]
    help_text = read_only_gh("attestation", "verify", "--help")
    flags = ("--repo", "--signer-workflow", "--signer-digest",
             "--source-digest", "--source-ref", "--predicate-type",
             "--format")
    if not all(flag in help_text for flag in flags):
        raise Blocked("installed gh CLI does not document all strict verify flags")
    print(json.dumps({"ghVersion": version, "strictFlags": list(flags),
                      "signerDigest": offline.SIGNER_SHA,
                      "sourceDigest": public.TAG_SHA}, sort_keys=True), flush=True)


def run_audit():
    checkout = subprocess.run(("git", "rev-parse", "HEAD"), capture_output=True,
                              text=True, check=True, timeout=30).stdout.strip()
    branch = public.read_json(read_only_gh(
        "api", "repos/pgextwin/build/branches/main"))
    preflight(os.environ, checkout, branch)
    version_and_flags()
    first = public.api("releases/tags/" + public.TAG)
    tag_before = public.api("git/ref/tags/" + public.TAG)
    require((tag_before.get("object") or {}).get("type") == "commit"
            and (tag_before["object"]).get("sha") == public.TAG_SHA,
            "historical tag moved")
    run = offline.fetch_twice(public.api, RUN_ID)
    offline.check_run(run, public.REPO, public.TAG_SHA, RUN_ID, ATTEMPT)
    require(run.get("conclusion") == "failure", "unexpected historical run conclusion")
    records = []
    failures = []
    with tempfile.TemporaryDirectory(prefix="pgextwin-cert-readonly-") as tmp:
        folder = Path(tmp)
        public.gh("release", "download", public.TAG, "--repo", public.REPO,
                  "--dir", str(folder))
        hashes = public.inventory(folder, first)

        def live_attest(zip_path, sbom_path, digest):
            with ZipFile(zip_path) as archive:
                package = public.read_json(archive.read("PACKAGE-INFO.json").decode("utf-8-sig"))
            major = package["postgresql"]["major"]
            offline.check_pkg(package, major, public.REPO, public.TAG_SHA,
                              public.UPSTREAM_SHA, offline.SIGNER_SHA, RUN_ID, ATTEMPT)
            sbom = public.read_json(sbom_path.read_text(encoding="utf-8-sig"))
            for predicate, short in ((public.PROVENANCE, "SLSA-v1"),
                                     (public.SPDX, "SPDX-2.3")):
                try:
                    args = ("attestation", "verify", str(zip_path),
                            "--repo", public.REPO, "--signer-workflow", public.SIGNER,
                            "--signer-digest", offline.SIGNER_SHA,
                            "--source-digest", public.TAG_SHA,
                            "--source-ref", "refs/heads/main",
                            "--predicate-type", predicate, "--format", "json")
                    results = public.read_json(public.gh(*args))
                    chosen = matching_evidence(results, predicate, zip_path.name, digest)
                    claims = certified_claims(
                        chosen, predicate=predicate, name=zip_path.name,
                        digest=digest, sbom=sbom, run=run)
                    if predicate == public.SPDX:
                        # Existing independent validator checks semantic JSON equality.
                        with tempfile.TemporaryDirectory(prefix="pgextwin-predicate-") as temp:
                            proof_file = Path(temp) / "verified.json"
                            proof_file.write_text(json.dumps([chosen]), encoding="utf-8")
                            public.validate_command(
                                "verify-sbom-attestation.py", "--verification-json",
                                str(proof_file), "--sbom", str(sbom_path),
                                "--zip", str(zip_path))
                    record = {"pg": major, "predicate": short, "zipSha256": digest,
                              "runId": RUN_ID, "attempt": ATTEMPT, "certificate": claims,
                              "status": "CERTIFICATE_JOIN_VERIFIED"}
                    records.append(record)
                    print(json.dumps(record, sort_keys=True), flush=True)
                except (Blocked, public.Unavailable) as exc:
                    failure = {"pg": major, "predicate": short,
                               "status": "BLOCKED_NOT_CRYPTOGRAPHICALLY_ATTESTED",
                               "zipSha256": digest, "reason": str(exc)}
                    failures.append(failure)
                    print(json.dumps(failure, sort_keys=True), flush=True)
                except (public.Deny, offline.Deny, ValueError, TypeError,
                        KeyError, IndexError, OSError) as exc:
                    failure = {"pg": major, "predicate": short,
                               "status": "DENY_HISTORICAL_CERTIFICATE_AUDIT",
                               "zipSha256": digest, "reason": str(exc)}
                    failures.append(failure)
                    print(json.dumps(failure, sort_keys=True), flush=True)

        proof = public.check_packages(
            folder, hashes, public.TAG_SHA, get_run=lambda _path: run,
            attest=live_attest)
        second = public.api("releases/tags/" + public.TAG)
        tag_after = public.api("git/ref/tags/" + public.TAG)
        run_after = offline.fetch_twice(public.api, RUN_ID)
        require(release_identity(first) == release_identity(second)
                and tag_before == tag_after and run == run_after,
                "release/tag/run TOCTOU between independent GETs")
        if failures:
            print(json.dumps({"matrixChecked": len(records) + len(failures),
                              "certificateJoins": len(records),
                              "failed": len(failures),
                              "decision": ("DENY_HISTORICAL_CERTIFICATE_AUDIT"
                                           if any(x["status"].startswith("DENY") for x in failures)
                                           else "BLOCKED_NOT_CRYPTOGRAPHICALLY_ATTESTED"),
                              "publishableReceipt": False,
                              "mutationsEnabled": False,
                              "publication": "DENY"}, sort_keys=True), flush=True)
            if any(x["status"].startswith("DENY") for x in failures):
                raise public.Deny("one or more verified certificate claims or subject checks denied")
            raise Blocked("incomplete authentic certificate-to-run binding matrix")
        require(len(records) == 10 and {
            (r["pg"], r["predicate"]) for r in records
        } == {(pg, pred) for pg in public.MAJORS
             for pred in ("SLSA-v1", "SPDX-2.3")},
            "incomplete PG-major/predicate certificate matrix")
        print(json.dumps({
            "decision": "PASS_HISTORICAL_CERTIFICATE_RUN_ATTEMPT_BINDING_ONLY",
            "verifiedCertificateJoins": len(records), "releaseId": public.RELEASE_ID,
            "historicalRunConclusion": run["conclusion"], "runId": RUN_ID,
            "runAttempt": ATTEMPT, "zipSha256ByMajor": proof["zipSha256ByMajor"],
            "publishableReceipt": False, "mutationsEnabled": False,
            "publication": "DENY", "g4": "NO_GO", "g5": "NO_GO"
        }, sort_keys=True), flush=True)


def main():
    try:
        run_audit()
    except (Blocked, public.Unavailable) as exc:
        print("BLOCKED_NOT_CRYPTOGRAPHICALLY_ATTESTED: " + str(exc), file=sys.stderr)
        raise SystemExit(3)
    except (public.Deny, offline.Deny, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, OSError, ValueError, TypeError,
            KeyError, IndexError, json.JSONDecodeError) as exc:
        print("DENY_HISTORICAL_CERTIFICATE_AUDIT: " + str(exc), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
