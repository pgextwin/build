#!/usr/bin/env python3
"""Verify K3 admission against pinned policy, issuer claims and trusted PR-B5 artifacts.

The caller supplies the trusted issuance policy and selects the PR-B5 artifact
downloads for the expected Run. The result is read-only, nonpublishing evidence.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from importlib import import_module
import json
import lzma
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

from jsonschema import Draft202012Validator

import github_contents
import local_auth_central
from candidate_branch import parse_branch

live = local_auth_central.live_verifier
ticket_verifier = live.verifier
auth = import_module("central-signing-auth")
audit = import_module("central-signed-main-audit")
claims = audit.verify
fleet_policy = import_module("fleet-policy")
central_extension = import_module("central-extension")
issuer_workflow_id = import_module("local-auth-issuance").WORKFLOW_ID

REPOSITORY = auth.REPOSITORY
CENTRAL_API = f"repos/{REPOSITORY}"
MAIN_ENDPOINT = f"{CENTRAL_API}/branches/main"
AUTHORITY_PATH = local_auth_central.AUTHORITY_PATH
FLEET_PATH = "metadata/automation-fleet.json"
ADMISSION_PATH = "metadata/postgresql-admission.json"
LIFECYCLE_PATH = "metadata/postgresql.json"
ENTRYPOINT = "scripts/verify-central-k3-admission.py"
RESULT_SCHEMA = Path(__file__).resolve().parents[1] / "schema/central-k3-admission-result.schema.json"
FIXED_CONTENTS = {AUTHORITY_PATH, FLEET_PATH, ADMISSION_PATH, LIFECYCLE_PATH, auth.CALLER}
MANIFEST_PATH = re.compile(r"extensions/([a-z][a-z0-9_]{0,63})/extension\.json")
BOUNDARIES = {"candidateManualOnlyInferred", "releaseOptInInferred",
              "environmentInferred", "admissionInferred"}
AUTHORITY_FIELDS = {"schemaVersion", "mode", "policyEpoch", "issuerKeyId", "issuerPublicKey",
                    "note", "revokedPolicyEpochs", "delegationStartsAt", "delegationEndsAt",
                    "targetSet", "allowedOperations", "publication", "boundaries", "rateLimits"}
RATE_LIMITS = {"maxUnresolvedCandidatesPerRepository": 1,
               "candidateAuthorizationsPerRepositoryPer15Minutes": 1,
               "candidateAuthorizationsPerRepositoryPerHour": 4}
INPUT_FIELDS = {"operation", "consumerRunId", "repository", "plan", "sources", "centralScope"}
AUDIT_FILES = {"audit.json", "claims.json", "run.json", "slsa.json", "spdx.json"}
CHECKS = ("authorityPresent", "targetExtension", "postgresqlSeries", "operation",
          "validityWindow", "signature", "targetSha", "signingRunBinding", "nonPublishing")
STATUS = "K3_ADMISSION_VERIFIED_NONPUBLISHING"


class Denied(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise Denied(code)


@contextmanager
def reject_as(code):
    """Translate failures from readers and existing verifiers at a stage boundary."""
    try:
        yield
    except Denied:
        raise
    except (ValueError, OSError, TypeError, KeyError, AttributeError, RecursionError):
        raise Denied(code) from None


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def positive_integer(value):
    return type(value) is int and 0 < value <= ticket_verifier.MAX_SAFE_INTEGER


def github_get(endpoint):
    """Read only the protected-main anchor and the six pinned content paths."""
    allowed = False
    if isinstance(endpoint, str) and endpoint.startswith(f"{CENTRAL_API}/contents/"):
        path, separator, ref = endpoint.removeprefix(f"{CENTRAL_API}/contents/").partition("?ref=")
        manifest = MANIFEST_PATH.fullmatch(path)
        allowed = separator and auth.matches(auth.SHA, ref) and (
            path in FIXED_CONTENTS or manifest and local_auth_central.valid_extension_name(manifest[1]))
    require(endpoint == MAIN_ENDPOINT or allowed, "K3_ENDPOINT_DENIED")
    env = dict(os.environ, GH_PROMPT_DISABLED="1")
    env.pop("GH_DEBUG", None)
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
            capture_output=True, env=env, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("K3_FETCH_FAILED") from None
    require(result.returncode == 0 and 0 < len(result.stdout) <= 2 * github_contents.MAX_FILE_BYTES,
            "K3_FETCH_FAILED")
    with reject_as("K3_FETCH_FAILED"):
        return json_object(result.stdout)


def json_object(raw):
    value = auth.parse_json(raw.decode("utf-8"))
    if type(value) is not dict:
        raise ValueError("expected JSON object")
    # Also reject exponents that overflow the JSON decoder's float representation.
    json.dumps(value, allow_nan=False)
    return value


def verify_main(api, sha, code):
    try:
        branch = auth.object_or_empty(api(MAIN_ENDPOINT))
    except (ValueError, OSError, KeyError):
        raise Denied(code) from None
    commit = auth.object_or_empty(branch.get("commit"))
    require(branch.get("name") == "main" and branch.get("protected") is True
            and commit.get("sha") == sha, code)


def file_reference(repository, commit, path, blob, raw):
    return {"repository": repository, "ref": commit, "commitSha": commit,
            "path": path, "blobSha": blob, "contentSha256": sha256(raw)}


def fetch_central_protected_snapshot(api, sha, path, references, key, code, *, binary=False):
    """Read one immutable file at the stage that needs it and record its provenance."""
    try:
        source = auth.object_or_empty(api(f"{CENTRAL_API}/contents/{path}?ref={sha}"))
        require(source.get("type") == "file" and type(source.get("size")) is int
                and "target" not in source and "submodule_git_url" not in source, code)
        raw = github_contents.decode_file(source, path)
        result = raw if binary else json_object(raw)
    except (ValueError, OSError, KeyError, RecursionError):
        raise Denied(code) from None
    references[key] = file_reference(REPOSITORY, sha, path, source["sha"], raw)
    return result


def has_j05(value):
    if isinstance(value, dict):
        return any("j05" in key.casefold() or (key in BOUNDARIES and nested is not False)
                   or has_j05(nested) for key, nested in value.items())
    return isinstance(value, list) and any(has_j05(nested) for nested in value)


def validate_authority(authority):
    require(authority.get("mode") != "DENY", "K3_AUTHORITY_DENY_MODE")
    require(authority.get("mode") == "ENFORCE", "K3_AUTHORITY_MODE_INVALID")
    require(authority.get("publication") is False, "K3_PUBLICATION_FORBIDDEN")
    require(not has_j05(authority), "K3_J05_FORBIDDEN")
    code = "K3_AUTHORITY_INVALID"
    # A missing or malformed delegation timestamp has a separate window error.
    required = AUTHORITY_FIELDS - {"delegationStartsAt", "delegationEndsAt"}
    require(required <= authority.keys() <= AUTHORITY_FIELDS
            and type(authority["schemaVersion"]) is int and authority["schemaVersion"] == 1
            and authority["allowedOperations"] == ["candidate", "requalify"]
            and authority["issuerKeyId"] == live.ISSUER_KEY_ID
            and auth.matches(auth.DIGEST, authority["issuerPublicKey"]), code)
    boundaries = auth.object_or_empty(authority["boundaries"])
    require(boundaries.keys() == BOUNDARIES | {"note"}, code)
    require(all(boundaries[key] is False for key in BOUNDARIES), "K3_J05_FORBIDDEN")
    revoked = authority["revokedPolicyEpochs"]
    rates = auth.object_or_empty(authority["rateLimits"])
    require(positive_integer(authority["policyEpoch"]) and isinstance(revoked, list)
            and all(positive_integer(epoch) for epoch in revoked)
            and len(set(revoked)) == len(revoked)
            and claims.same_json(rates, RATE_LIMITS)
            and all(isinstance(note, str) and 20 <= len(note) <= 1000
                    for note in (authority["note"], boundaries["note"])), code)


def resolve_target_set(authority, fleet, extension):
    code = "K3_AUTHORITY_TARGET_NOT_ALLOWED"
    require(claims.same_json(authority["targetSet"], {"path": FLEET_PATH, "schemaVersion": 1}), code)
    # Give a case collision the same target error as the central path validator.
    rows = fleet.get("entries")
    if isinstance(rows, list):
        names = [row.get("repository") for row in rows if isinstance(row, dict)]
        require(not any(isinstance(name, str) and name != name.lower()
                        for name in names), "K3_TARGET_EXTENSION_MISMATCH")
    with reject_as(code):
        entries = fleet_policy.validate_registry(fleet)
    require(entries.get(REPOSITORY, {}).get("candidateEnabled") is True, code)
    registered = local_auth_central.registered_extensions(entries.keys() - {REPOSITORY})
    require(extension in registered, "K3_EXTENSION_NOT_ADMITTED")
    return frozenset(entries), registered


def validate_window(authority, now):
    code = "K3_AUTHORITY_EXPIRED_OR_OUTSIDE_WINDOW"
    with reject_as(code):
        start = ticket_verifier._timestamp(authority.get("delegationStartsAt"))
        end = ticket_verifier._timestamp(authority.get("delegationEndsAt"))
    require(start <= now < end, code)


LA1_ERRORS = {
    **dict.fromkeys(("BAD_TIMESTAMP", "INVALID_LIFETIME", "LIFETIME_TOO_LONG", "INVALID_TIME_ORDER",
                     "NOT_YET_VALID", "EXPIRED"), "K3_TICKET_EXPIRED_OR_INVALID_WINDOW"),
    "OPERATION_NOT_ALLOWED": "K3_OPERATION_NOT_ALLOWED",
    "ISSUER_MISMATCH": "K3_AUTHORITY_INVALID",
    "BAD_SIGNATURE": "K3_SIGNATURE_INVALID",
    "INPUTS_HASH_MISMATCH": "K3_SHA_MISMATCH",
    "REPO_NOT_IN_FLEET": "K3_TARGET_EXTENSION_MISMATCH",
}


def verify_claim(ticket, inputs_bytes, authority, repositories, now, issuance_policy, issuer_api):
    # Keep the exact verified claim file for X-02; don't fetch it a second time.
    fetched = {}

    def capture(endpoint):
        value = issuer_api(endpoint)
        if "/contents/" in endpoint:
            fetched["claim"] = value
        return value

    try:
        evidence = live.verify_live_binding(ticket, inputs_bytes, authority, repositories, now,
                                            issuance_policy=issuance_policy, api=capture)
        claim_file = fetched["claim"]
        raw_claim = github_contents.decode_file(claim_file, "claim.json")
        claim = json_object(raw_claim)
    except ticket_verifier.TicketRejected as error:
        raise Denied(LA1_ERRORS.get(error.code, "K3_CLAIM_INVALID")) from None
    except (ValueError, OSError, KeyError, RecursionError):
        raise Denied("K3_CLAIM_INVALID") from None
    return evidence, claim, file_reference(live.ISSUER_REPOSITORY, evidence["claimCommitSha"],
                                           "claim.json", claim_file["sha"], raw_claim)


def verify_scope(ticket, inputs, extension, manifest, ticket_base_sha, manifest_blob,
                 authority, registered, now, evidence):
    code = "K3_TARGET_EXTENSION_MISMATCH"
    require(ticket["repository"] == REPOSITORY, code)
    require(all(ticket[key] == ticket_base_sha
                for key in ("policySha", "centralMainSha", "targetMainSha", "verifierSha"))
            and ticket["manifestBlob"] == manifest_blob, "K3_SHA_MISMATCH")
    require(not has_j05(inputs), "K3_J05_FORBIDDEN")
    require(inputs.get("operation") == "candidate", "K3_OPERATION_NOT_ALLOWED")
    require(inputs.keys() == INPUT_FIELDS and inputs["repository"] == REPOSITORY, code)
    plan = auth.object_or_empty(inputs["plan"])
    scope = auth.object_or_empty(inputs["centralScope"])
    require(isinstance(inputs["centralScope"], dict), code)
    require(scope.get("publication") is False, "K3_PUBLICATION_FORBIDDEN")
    with reject_as(code):
        branch = parse_branch(plan.get("branch"), expected_extension=extension, allow_legacy=False)
    require(plan.get("extension") == extension and plan.get("candidateId") == branch.candidate_id
            and scope == local_auth_central.central_scope(extension, branch.branch)
            and positive_integer(inputs["consumerRunId"]), code)
    require(sha256(ticket_verifier.canonical_json(inputs["sources"])) == ticket["upstreamSourcesSha256"],
            "K3_SHA_MISMATCH")
    with reject_as(code):
        local_auth_central.enforce_central_candidate(
            policy=authority, repository=REPOSITORY, extension=extension,
            registered_extensions=registered, branch=branch.branch,
            changes=[{"filename": manifest, "status": "modified"}],
            expected_candidate_id=branch.candidate_id, now=now, require_binding=True,
            auth_binding={"ticket": ticket, "inputs_obj": inputs, "live_evidence": evidence,
                          "consumer_run_id": inputs["consumerRunId"]})
    return branch


def verify_series(declaration, admission, lifecycle, inputs, extension, now):
    identity = import_module("fleet-release-identity")
    require(not has_j05(declaration), "K3_J05_FORBIDDEN")
    with reject_as("K3_DECLARATION_INVALID"):
        require(not central_extension.validate_declaration(declaration, expected_name=extension)
                and declaration["license"]["verifyAgainstUpstream"] is True, "K3_DECLARATION_INVALID")
    with reject_as("K3_PG_SERIES_NOT_ADMITTED"):
        configured = identity.configured_majors(declaration, admission=admission)
        require(type(lifecycle.get("schemaVersion")) is int and lifecycle["schemaVersion"] == 1
                and isinstance(lifecycle.get("postgresql"), list), "K3_PG_SERIES_NOT_ADMITTED")
        lifecycle_majors = {entry["major"] for entry in lifecycle["postgresql"]}
        require(set(configured) <= lifecycle_majors, "K3_PG_SERIES_NOT_ADMITTED")
    with reject_as("K3_PG_SERIES_EOL"):
        maintained = identity.maintained_majors(declaration, lifecycle, today=now.date(),
                                               admission=admission)
    with reject_as("K3_DECLARATION_INVALID"):
        declared = identity.sources(declaration, require_pins=True, admission=admission)
    rows = inputs["sources"]
    require(type(rows) is list and rows
            and all(type(row) is dict and type(row.get("major")) is int for row in rows),
            "K3_PG_SERIES_MISMATCH")
    by_major = {row["major"]: row for row in rows}
    require(set(by_major) <= identity.admission_majors(extension, admission=admission)
            and set(by_major) <= lifecycle_majors, "K3_PG_SERIES_NOT_ADMITTED")
    require(not (set(by_major) & (set(configured) - set(maintained))), "K3_PG_SERIES_EOL")
    require(len(by_major) == len(rows) and set(by_major) == set(maintained), "K3_PG_SERIES_MISMATCH")
    require(all(all(by_major[major].get(key) == value for key, value in declared[major].items())
                for major in maintained), "K3_SHA_MISMATCH")
    return {major: declared[major] for major in maintained}


def safe_path(path, code):
    path = Path(path).absolute()
    require(not any(part.is_symlink() for part in (path, *path.parents)), code)
    return path


def read_bytes(path, limit, code):
    with reject_as(code):
        path = safe_path(path, code)
        require(path.is_file(), code)
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        require(0 < len(raw) <= limit, code)
    return raw


def series_files(root, extension, majors, filename, allowed_files):
    code = "K3_SIGNING_BINDING_MISMATCH"
    with reject_as(code):
        root = safe_path(root, code)
        matches = [path for path in root.iterdir() if path.name.casefold() == extension.casefold()]
        require([path.name for path in matches] == [extension], code)
        target = safe_path(matches[0], code)
        require(target.is_dir(), code)
        folders = {path.name: path for path in target.iterdir()}
        require(folders.keys() == {str(major) for major in majors}, code)
        for major in majors:
            folder = safe_path(folders[str(major)], code)
            require(folder.is_dir(), code)
            entries = {path.name: path for path in folder.iterdir()}
            require(filename in entries and entries.keys() <= allowed_files
                    and all(not path.is_symlink() and path.is_file() for path in entries.values()), code)
            yield major, entries[filename]


def verify_signing(workflow, extension, main_sha, pin_sha, run_id, event, sources, intent_dir, audit_dir):
    with reject_as("K3_SIGNING_PIN_MISMATCH"):
        pins = re.findall(rf"^    uses: {re.escape(REPOSITORY + '/' + auth.REUSABLE)}@({auth.SHA})$",
                          workflow.decode("utf-8"), re.MULTILINE)
        require(pins == [pin_sha], "K3_SIGNING_PIN_MISMATCH")
    code = "K3_SIGNING_BINDING_MISMATCH"
    common = {"extension_name": extension, "head_sha": main_sha, "reusable_pin_sha": pin_sha,
              "authentic_event": event, "run_id": run_id, "run_attempt": 1}
    intents = series_files(intent_dir, extension, sources, auth.INTENT_NAME, {auth.INTENT_NAME})
    audits = series_files(audit_dir, extension, sources, "audit.json", AUDIT_FILES)
    first = None
    tarballs = {}
    verified = {}
    with reject_as(code):
        for (major, intent_path), (_, audit_path) in zip(intents, audits, strict=True):
            intent = auth.validate_intent(json_object(read_bytes(intent_path, 64 * 1024, code)))
            require(all(intent[key] == expected for key, expected in common.items()), code)
            shared = tuple(intent[key] for key in ("extension_source_sha", "actor_login", "issue_comment_id"))
            if first is None:
                first = shared
            require(shared == first, code)
            tarball = intent["upstream_tarball_sha256"]
            require(tarballs.setdefault(sources[major]["commit"], tarball) == tarball, code)

            report = json_object(read_bytes(audit_path, github_contents.MAX_FILE_BYTES, code))
            require(report.keys() == {"schema_version", "publishing_allowed", "run", "verification"}
                    and type(report["schema_version"]) is int and report["schema_version"] == 1
                    and report["publishing_allowed"] is False, code)
            run = auth.object_or_empty(report["run"])
            require(run.get("repository") == REPOSITORY and run.get("path") == auth.CALLER
                    and run.get("run_invocation_uri") == intent["run_invocation_uri"], code)
            # Reuse the PR-B5 checks against the normalized audit representation.
            audit.audit({**run, "repository": {"full_name": run["repository"]}},
                        intent, report["verification"])
            verified[major] = intent, report["verification"]["subject"]
    return verified


def zip_identity(path):
    code = "K3_ZIP_MISSING_OR_EXTRA"
    with reject_as(code):
        path = safe_path(path, code)
        require(path.is_file(), code)
        with path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            require(size > 0, code)
            digest = hashlib.file_digest(stream, "sha256")
    return digest.hexdigest(), size


def verify_zip_metadata(path, intent, source, upstream):
    code = "K3_ZIP_METADATA_MISMATCH"
    try:
        with zipfile.ZipFile(safe_path(path, code)) as archive:
            # Reject additional copies even under a different directory or casing.
            for name in ("PACKAGE-INFO.json", auth.INTENT_NAME):
                matching = [entry.filename for entry in archive.infolist()
                            if entry.filename.replace("\\", "/").split("/")[-1].casefold() == name.casefold()]
                require(matching == [name], code)
            require(archive.testzip() is None, code)
            embedded = auth.validate_intent(claims.zip_json(archive, auth.INTENT_NAME))
            package = auth.object_or_empty(claims.zip_json(archive, "PACKAGE-INFO.json"))
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError, EOFError,
            lzma.LZMAError, struct.error, zlib.error):
        raise Denied(code) from None
    expected = {
        "buildMode": "release-attested",
        "source": {"packagingRepository": REPOSITORY, "packagingCommit": intent["head_sha"]},
        "buildInfrastructure": {"repository": REPOSITORY, "commit": intent["reusable_pin_sha"],
                                "workflow": auth.REUSABLE},
        "workflowRun": {"id": intent["run_id"], "attempt": 1, "event": intent["authentic_event"],
                        "ref": auth.REF, "url": intent["run_invocation_uri"].rsplit("/attempts/", 1)[0]},
        "upstream": {"repository": upstream, **{key: source[key] for key in ("ref", "version", "commit")}},
    }
    with reject_as(code):
        major = auth.object_or_empty(package.get("postgresql")).get("major")
        require(embedded == intent and type(major) is int and major == source["major"]
                and auth.object_or_empty(package.get("package")).get("name") == intent["extension_name"]
                and all(claims.same_json(package.get(key), value) for key, value in expected.items()), code)


def verify_zips(dist_dir, declaration, admission, sources, signing):
    code = "K3_ZIP_MISSING_OR_EXTRA"
    identity = import_module("fleet-release-identity")
    names = {major: identity.asset_stem(declaration, major, admission=admission) + ".zip"
             for major in sources}
    upstream = declaration["upstream"]["repository"]
    with reject_as(code):
        dist = safe_path(dist_dir, code)
        paths = {path.name: path for path in dist.iterdir() if path.suffix.lower() == ".zip"}
        require(paths.keys() == set(names.values()), code)
    identities = {major: zip_identity(paths[name]) for major, name in names.items()}
    for major, name in names.items():
        intent, subject = signing[major]
        require(subject == {"name": name, "digest": {"sha256": identities[major][0]}}, "K3_SHA_MISMATCH")
        verify_zip_metadata(paths[name], intent, sources[major], upstream)
    with reject_as(code):
        require({path.name for path in dist.iterdir() if path.suffix.lower() == ".zip"}
                == paths.keys(), code)
    require(all(zip_identity(paths[name]) == identities[major] for major, name in names.items()),
            "K3_SHA_MISMATCH")
    return {major: (name, *identities[major]) for major, name in names.items()}


def build_result(*, now, references, authority, ticket, ticket_base_sha, inputs, branch, claim,
                 evidence, issuance_policy, upstream, sources, signing, identities):
    first_intent = next(iter(signing.values()))[0]
    main_sha = first_intent["head_sha"]
    pin_sha = first_intent["reusable_pin_sha"]
    issuer_commit = evidence["issuerMainSha"]
    claim_commit = evidence["claimCommitSha"]
    epoch = authority["policyEpoch"]
    request_id = ticket["requestId"]
    run = {
        "signingRunId": first_intent["run_id"],
        "signingRunAttempt": first_intent["run_attempt"],
        "signingRunInvocationUri": first_intent["run_invocation_uri"],
    }
    references.update({
        "issuerMain": {"repository": live.ISSUER_REPOSITORY, "ref": "refs/heads/main",
                       "commitSha": issuer_commit},
        "issuerClaimRef": {"repository": live.ISSUER_REPOSITORY, "ref": f"refs/claims/{request_id}",
                           "commitSha": claim_commit},
    })
    results = []
    for major, source in sources.items():
        name, digest, size = identities[major]
        results.append({
            "zipName": name, "zipSha256": digest, "zipSizeBytes": size,
            "extension": branch.extension, "postgresqlMajor": major,
            "upstreamRepository": upstream, "upstreamRef": source["ref"],
            "upstreamVersion": source["version"], "upstreamCommitSha": source["commit"],
            "upstreamTarballSha256": signing[major][0]["upstream_tarball_sha256"],
            "packagingCommitSha": main_sha, "extensionSourceSha": first_intent["extension_source_sha"],
            "reusablePinSha": pin_sha, **run, "signingAuditVerified": True,
            "claimRequestId": request_id, "claimCommitSha": claim_commit, "authorityPolicyEpoch": epoch,
            "authorityCommitSha": main_sha, "postgresqlAdmissionCommitSha": main_sha,
            "k3Status": "VERIFIED_NONPUBLISHING", "checks": dict.fromkeys(CHECKS, True),
        })
    result = {
        "schemaVersion": 1, "status": STATUS, "verified": True,
        "publicationAuthorized": False, "publishableReceipt": False, "verifierEntrypoint": ENTRYPOINT,
        "verifiedAt": now.isoformat().replace("+00:00", "Z"),
        "canonicalReferences": references,
        "principal": {
            "authorityRepository": REPOSITORY, "issuerRepository": live.ISSUER_REPOSITORY,
            "issuerWorkflowPath": live.ISSUER_WORKFLOW, "issuerWorkflowId": issuance_policy["workflowId"],
            "issuerRunId": evidence["issuerRunId"], "issuerRunAttempt": evidence["issuerRunAttempt"],
            "issuerKeyId": authority["issuerKeyId"], "issuerPublicKey": authority["issuerPublicKey"],
            "policyEpoch": epoch, "signingRepository": REPOSITORY, "signingCallerPath": auth.CALLER,
            "signingReusablePath": auth.REUSABLE, "signingReusablePinSha": pin_sha, **run,
            "signingEvent": first_intent["authentic_event"], "signingActor": first_intent["actor_login"],
        },
        "admission": {
            "extension": branch.extension, "operation": "candidate", "publication": False,
            "branch": branch.branch, "candidateId": branch.candidate_id, "requestId": request_id,
            "ticketSha256": evidence["ticketSha256"], "inputsSha256": ticket["inputsSha256"],
            "upstreamSourcesSha256": ticket["upstreamSourcesSha256"],
            "consumerRunId": inputs["consumerRunId"],
            "delegationWindow": {"startsAt": authority["delegationStartsAt"],
                                 "endsAt": authority["delegationEndsAt"]},
            "ticketWindow": {key: ticket[key] for key in ("issuedAt", "notBefore", "expiresAt")},
            "claimRecordedAt": claim["recordedAt"], "admittedMajors": list(sources),
            "verifiedMajors": [row["postgresqlMajor"] for row in results],
        },
        "shaBindings": {
            "centralMainSha": main_sha, "ticketBaseSha": ticket_base_sha, "policySha": ticket["policySha"],
            "targetMainSha": ticket["targetMainSha"], "verifierSha": ticket["verifierSha"],
            "manifestBlobSha": ticket["manifestBlob"], "extensionSourceSha": first_intent["extension_source_sha"],
            "reusablePinSha": pin_sha, "issuerMainSha": issuer_commit, "claimCommitSha": claim_commit,
        },
        "zipResults": results,
    }
    schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    require(Draft202012Validator(schema).is_valid(result), "K3_RESULT_SCHEMA_INVALID")
    return result


def verify_central_k3_admission(*, extension, central_main_sha, reusable_pin_sha, signing_run_id,
                                expected_event, raw_ticket_text, raw_inputs_bytes, issuance_policy,
                                dist_dir, intent_dir, audit_dir, now, ticket_base_sha=None,
                                signing_run_attempt=1, central_api=github_get, issuer_api=live.github_get):
    """Return schema-validated, ZIP-wise evidence when every stage succeeds."""
    # 1. Inputs and live protected-main anchor.
    require(local_auth_central.valid_extension_name(extension), "K3_TARGET_EXTENSION_MISMATCH")
    if ticket_base_sha is None:
        ticket_base_sha = central_main_sha
    require(all(auth.matches(auth.SHA, sha) for sha in
                (central_main_sha, ticket_base_sha, reusable_pin_sha)), "K3_SHA_MISMATCH")
    require(positive_integer(signing_run_id) and type(signing_run_attempt) is int
            and signing_run_attempt == 1 and isinstance(expected_event, str)
            and expected_event in auth.CENTRAL_AUTHENTIC_EVENTS, "K3_SIGNING_BINDING_MISMATCH")
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() == timedelta(0),
            "K3_INVALID_CLOCK")
    with reject_as("K3_ISSUANCE_POLICY_INVALID"):
        live._validate_issuance_policy(issuance_policy)
        require(issuance_policy["workflowId"] == issuer_workflow_id, "K3_ISSUANCE_POLICY_INVALID")
    verify_main(central_api, central_main_sha, "K3_MAIN_NOT_PROTECTED")
    references = {}
    manifest = f"extensions/{extension}/extension.json"

    # 2. Authority, target, delegation and epoch before any issuer request.
    authority = fetch_central_protected_snapshot(central_api, central_main_sha, AUTHORITY_PATH,
                                                 references, "authority", "K3_AUTHORITY_ABSENT")
    validate_authority(authority)
    if ticket_base_sha != central_main_sha:
        fetch_central_protected_snapshot(central_api, ticket_base_sha, AUTHORITY_PATH,
                                         references, "ticketBaseAuthority", "K3_AUTHORITY_ABSENT")
    fleet = fetch_central_protected_snapshot(central_api, central_main_sha, FLEET_PATH,
                                             references, "fleetRegistry", "K3_AUTHORITY_TARGET_NOT_ALLOWED")
    repositories, registered = resolve_target_set(authority, fleet, extension)
    validate_window(authority, now)
    try:
        ticket = ticket_verifier.parse_ticket(raw_ticket_text)
    except ticket_verifier.TicketRejected as error:
        raise Denied(LA1_ERRORS.get(error.code, "K3_SIGNATURE_INVALID")) from None
    require(ticket["policyEpoch"] not in authority["revokedPolicyEpochs"], "K3_AUTHORITY_EPOCH_REVOKED")
    require(ticket["policyEpoch"] == authority["policyEpoch"], "K3_AUTHORITY_EPOCH_MISMATCH")

    # 3. Verify the LA1 signature and independently resolve the issuer claim.
    evidence, claim, references["issuerClaimFile"] = verify_claim(
        ticket, raw_inputs_bytes, authority, repositories, now, issuance_policy, issuer_api)

    # 4. Bind the ticket to the trusted candidate base and run the central scope checks.
    declaration = fetch_central_protected_snapshot(central_api, central_main_sha, manifest,
                                                   references, "extensionDeclaration", "K3_DECLARATION_INVALID")
    binding = "extensionDeclaration"
    if ticket_base_sha != central_main_sha:
        binding = "ticketBaseDeclaration"
        fetch_central_protected_snapshot(central_api, ticket_base_sha, manifest,
                                         references, binding, "K3_SHA_MISMATCH")
    inputs = json_object(raw_inputs_bytes)
    branch = verify_scope(ticket, inputs, extension, manifest, ticket_base_sha,
                          references[binding]["blobSha"], authority, registered, now, evidence)

    # 5. Verify the declared versions and the exact admitted, maintained series.
    admission_raw = fetch_central_protected_snapshot(central_api, central_main_sha, ADMISSION_PATH,
                                                     references, "postgresqlAdmission",
                                                     "K3_PG_SERIES_NOT_ADMITTED", binary=True)
    identity = import_module("fleet-release-identity")
    with reject_as("K3_PG_SERIES_NOT_ADMITTED"):
        admission = identity.parse_admission(admission_raw)
    lifecycle = fetch_central_protected_snapshot(central_api, central_main_sha, LIFECYCLE_PATH,
                                                 references, "postgresqlLifecycle", "K3_PG_SERIES_NOT_ADMITTED")
    sources = verify_series(declaration, admission, lifecycle, inputs, extension, now)

    # 6. Bind the protected caller pin, PR-B5 intents and claims audits.
    workflow = fetch_central_protected_snapshot(central_api, central_main_sha, auth.CALLER,
                                                references, "callerWorkflow", "K3_SIGNING_PIN_MISMATCH",
                                                binary=True)
    signing = verify_signing(workflow, extension, central_main_sha, reusable_pin_sha,
                             signing_run_id, expected_event, sources, intent_dir, audit_dir)

    # 7. Bind every audited subject and embedded metadata to the actual ZIP bytes.
    upstream = declaration["upstream"]["repository"]
    identities = verify_zips(dist_dir, declaration, admission, sources, signing)

    # 8. Discard all evidence on protected-main drift.
    verify_main(central_api, central_main_sha, "K3_PROTECTED_MAIN_DRIFT")

    # 9. Produce deterministic schema-checked evidence.
    with reject_as("K3_RESULT_SCHEMA_INVALID"):
        return build_result(now=now, references=references, authority=authority, ticket=ticket,
                            ticket_base_sha=ticket_base_sha, inputs=inputs, branch=branch, claim=claim,
                            evidence=evidence, issuance_policy=issuance_policy, upstream=upstream,
                            sources=sources, signing=signing, identities=identities)


def write_result(path, result):
    code = "K3_OUTPUT_INVALID"
    with reject_as(code):
        path = safe_path(path, code)
        require(path.parent.is_dir() and (not path.exists() or path.is_file()), code)
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
            safe_path(path, code)
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise Denied("K3_INPUT_INVALID")


def main(argv=None):
    parser = ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("extension", "central-main-sha", "reusable-pin-sha", "expected-event"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--signing-run-id", type=int, required=True)
    parser.add_argument("--signing-run-attempt", type=int, default=1)
    parser.add_argument("--ticket-base-sha")
    parser.add_argument("--now", help="UTC timestamp for deterministic evaluation")
    for name in ("ticket", "inputs", "issuance-policy", "dist-dir", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--intent-dir", type=Path, required=True,
                        help="root of the downloaded intent artifact (<extension>/<major>/central-signed-main-intent.json)")
    parser.add_argument("--audit-dir", type=Path, required=True,
                        help="root with each central-claims artifact unpacked into <extension>/<major>/")
    try:
        args = parser.parse_args(argv)
        with reject_as("K3_INVALID_CLOCK"):
            now = datetime.now(timezone.utc) if args.now is None else datetime.fromisoformat(args.now)
        with reject_as("K3_SIGNATURE_INVALID"):
            raw_ticket = read_bytes(args.ticket, ticket_verifier.MAX_TICKET_BYTES,
                                    "K3_SIGNATURE_INVALID").decode("utf-8")
        raw_inputs = read_bytes(args.inputs, ticket_verifier.MAX_INPUTS_BYTES, "K3_CLAIM_INVALID")
        with reject_as("K3_ISSUANCE_POLICY_INVALID"):
            issuance = json_object(read_bytes(args.issuance_policy, ticket_verifier.MAX_TICKET_BYTES,
                                              "K3_ISSUANCE_POLICY_INVALID"))
        result = verify_central_k3_admission(
            extension=args.extension, central_main_sha=args.central_main_sha,
            ticket_base_sha=args.ticket_base_sha, reusable_pin_sha=args.reusable_pin_sha,
            signing_run_id=args.signing_run_id, signing_run_attempt=args.signing_run_attempt,
            expected_event=args.expected_event, raw_ticket_text=raw_ticket, raw_inputs_bytes=raw_inputs,
            issuance_policy=issuance, dist_dir=args.dist_dir, intent_dir=args.intent_dir,
            audit_dir=args.audit_dir, now=now)
        write_result(args.output, result)
    except Denied as error:
        print(json.dumps({"error_code": error.code}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
