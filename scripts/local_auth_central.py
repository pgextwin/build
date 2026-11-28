"""Enforce the nonpublishing local-auth scope for central candidates."""

import ast
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from functools import lru_cache
import hashlib
from importlib import import_module
from pathlib import Path
import re

from candidate_branch import CENTRAL_REPOSITORY, format_branch, parse_branch, validate_extension_name

live_verifier = import_module("local-auth-live")
verifier = live_verifier.verifier
TicketRejected = verifier.TicketRejected
canonical_json = verifier.canonical_json
BUILD_ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_PATH = "metadata/local-candidate-authority.json"

GIT_STATUSES = {
    "A": "added", "C": "copied", "D": "removed",
    "M": "modified", "R": "renamed", "T": "changed",
}
CHANGE_STATUSES = frozenset(GIT_STATUSES.values()) | {"unchanged"}
PAIRED_STATUSES = frozenset({"renamed", "copied"})
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
P5_ROOTS = frozenset({"metadata"})
P5_FILES = frozenset({"schema/local-candidate-authority.schema.json"})
P5_WORKFLOWS = frozenset({
    "central-signed-main.yml",
    "central-extension-attested.yml",
    "local-authorized-candidate.yml", "fleet-candidate.yml", "fleet-upstream-watch.yml",
    "candidate-update.yml", "build-extension-attested.yml", "chat-signed-main-source.yml",
    "publisher-candidate-intake.yml", "publisher-app-proof.yml", "promote-verified-release.yml",
    "promote-legacy-verified-release.yml", "requalify-merged-candidate-signed.yml",
    "verified-pin-automerge.yml", "verify-signed-candidate-readonly.yml",
    "external-direct-get-issuer.yml", "publication-policy-projection.yml",
})
P5_SCRIPT_PATTERNS = (
    "local-auth*", "local_auth*", "*local-authorized-candidate*", "*publisher*",
    "*signing*", "*signed*", "*attest*", "*admission*", "*release-authorization*",
    "*publication-policy*", "*unattended-policy*", "*fleet-control*", "*fleet-policy*",
    "*fleet-publish*", "*verify-scheduled-fleet-candidate*", "*fleet_candidate_origin*",
    "*fleet-candidate*",
)
P3_ROOTS = frozenset({"scripts", "common", "windows", "tests", "schema"})
PATH_DENIAL_ORDER = ("P5", "P7", "P4", "P3", "P6")
BINDING_MISMATCH = "RUN_CLAIM_CHANGE_BINDING_MISMATCH"


def need(condition, code):
    if not condition:
        raise TicketRejected(code)


@lru_cache(maxsize=1)
def _windows_name_check():
    # The existing Windows check is stdlib-only. Load its definitions from
    # central-extension.py because that script's schema validator needs
    # jsonschema, which the issuer and the early resolver steps do not install.
    path = Path(__file__).with_name("central-extension.py")
    source = ast.parse(path.read_bytes(), filename=str(path))
    constants = {"WINDOWS_RESERVED_SEGMENT", "WINDOWS_INVALID_NAME_CHARS"}
    definitions = [
        node for node in source.body
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants)
        or (isinstance(node, ast.FunctionDef) and node.name == "windows_name_error")
    ]
    namespace = {"re": re}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["windows_name_error"]


def valid_extension_name(extension):
    try:
        validate_extension_name(extension)
    except ValueError:
        return False
    return _windows_name_check()(extension) is None


def changes_from_name_status(data):
    """Parse the NUL-delimited output of git diff --name-status -z -M -C."""
    need(isinstance(data, (bytes, bytearray, str)), "MALFORMED_CHANGE")
    try:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        stream = raw.decode("utf-8")
    except UnicodeError as exc:
        raise TicketRejected("MALFORMED_CHANGE") from exc

    need(not stream or stream.endswith("\0"), "MALFORMED_CHANGE")
    fields = iter(stream.split("\0")[:-1])
    changes = []
    for token in fields:
        letter, score = token[:1], token[1:]
        need(letter in GIT_STATUSES, "MALFORMED_CHANGE")
        status = GIT_STATUSES[letter]
        if status in PAIRED_STATUSES:
            need(re.fullmatch(r"[0-9]{1,3}", score) and int(score) <= 100, "MALFORMED_CHANGE")
            previous = next(fields, "")
            need(previous and not CONTROL.search(previous), "MALFORMED_CHANGE")
        else:
            need(not score, "MALFORMED_CHANGE")
        filename = next(fields, "")
        need(filename and not CONTROL.search(filename), "MALFORMED_CHANGE")
        change = {"filename": filename, "status": status}
        if status in PAIRED_STATUSES:
            change["previous_filename"] = previous
        changes.append(change)
    return changes


def _path_parts(path, registered_casefold):
    need(isinstance(path, str) and path and "\\" not in path and not CONTROL.search(path),
         "INVALID_PATH")
    parts = path.split("/")
    windows_name_error = _windows_name_check()
    # Also reject a space immediately before an extension dot (NC-07).
    need(all(part not in ("", ".", "..") and windows_name_error(part) is None
             and " ." not in part for part in parts), "INVALID_PATH")
    if parts[0].casefold() == "extensions":
        need(parts[0] == "extensions", "INVALID_PATH")
        if len(parts) >= 2:
            names = registered_casefold.get(parts[1].casefold(), ())
            need(not names or all(name == parts[1] for name in names), "INVALID_PATH")
    return parts


def _classify_parts(parts):
    if parts[0] == "extensions" and len(parts) >= 3 and valid_extension_name(parts[1]):
        return "P1", parts[1]

    folded = [part.casefold() for part in parts]
    workflows = len(parts) >= 3 and folded[:2] == [".github", "workflows"]
    if (len(parts) >= 2 and folded[0] in P5_ROOTS
            or "/".join(folded) in P5_FILES
            or workflows and folded[-1] in P5_WORKFLOWS
            or len(parts) >= 2 and folded[0] == "scripts"
            and any(fnmatchcase(folded[-1], pattern) for pattern in P5_SCRIPT_PATTERNS)):
        return "P5", None
    if len(parts) >= 3 and parts[:2] == [".github", "workflows"]:
        return "P4", None
    if len(parts) >= 2 and parts[0] in P3_ROOTS:
        return "P3", None
    if len(parts) >= 2 and parts[0] == "docs":
        return "P6", None
    return "P7", None


def classify_central_path(path):
    """Return (path class, extension name or None) for a single safe path."""
    return _classify_parts(_path_parts(path, {}))


def require_enforce_mode(mode):
    need(mode != "DENY", "DENY_MODE")
    need(mode == "ENFORCE", "MODE_NOT_IMPLEMENTED")


def validate_policy(policy, now, ticket=None):
    need(type(policy) is dict, "INVALID_POLICY")
    require_enforce_mode(policy.get("mode"))
    need(policy.get("publication") is False, "PUBLICATION_DENIED")
    need(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() == timedelta(0),
         "INVALID_CLOCK")
    ticket = ticket if type(ticket) is dict else {}
    verifier._policy_key({
        "policyEpoch": ticket.get("policyEpoch", policy.get("policyEpoch")),
        "issuerKeyId": ticket.get("issuerKeyId", policy.get("issuerKeyId")),
    }, policy, now)


def load_policy(root=BUILD_ROOT):
    try:
        path = root / AUTHORITY_PATH
        return verifier._parse_json(path.read_text(encoding="utf-8"), verifier.MAX_INPUTS_BYTES)
    except (OSError, ValueError) as exc:
        raise TicketRejected("INVALID_POLICY") from exc


def registered_extensions(repositories):
    return frozenset(repo.split("/", 1)[1] for repo in repositories)


def central_scope(extension, branch):
    manifest = f"extensions/{extension}/extension.json"
    return {"extension": extension, "manifestPath": manifest, "branch": branch,
            "allowedPaths": [manifest], "operation": "candidate", "publication": False}


def _check_branch(branch, extension, expected_candidate_id, allow_legacy_reuse):
    try:
        parsed = parse_branch(branch, expected_extension=None, allow_legacy=allow_legacy_reuse,
                              allow_central=True)
    except ValueError as exc:
        if not allow_legacy_reuse and _is_legacy_branch(branch):
            raise TicketRejected("LEGACY_BRANCH_NOT_ALLOWED") from exc
        raise TicketRejected("INVALID_CANDIDATE_BRANCH") from exc
    need(parsed.style != "central" or parsed.extension == extension, "BRANCH_EXTENSION_MISMATCH")
    need(expected_candidate_id is None or parsed.candidate_id == expected_candidate_id,
         "BRANCH_CANDIDATE_ID_MISMATCH")


def _is_legacy_branch(branch):
    try:
        return parse_branch(branch, allow_central=False).style == "legacy"
    except ValueError:
        return False


def _manifest_only(changes, extension):
    return (len(changes) == 1 and changes[0]["status"] == "modified"
            and changes[0]["filename"] == f"extensions/{extension}/extension.json"
            and changes[0].get("previous_filename") is None)


def evaluate_central_changes(changes, *, extension, registered_extensions,
                             scope_mode="candidate_manifest"):
    """Validate the change structure and scope, returning paths and path classes."""
    need(isinstance(changes, list), "MALFORMED_CHANGE")
    need(changes, "EMPTY_CHANGE_SET")
    paths = set()
    for change in changes:
        need(isinstance(change, dict), "MALFORMED_CHANGE")
        filename, status = change.get("filename"), change.get("status")
        need(isinstance(filename, str) and filename and isinstance(status, str)
             and status in CHANGE_STATUSES, "MALFORMED_CHANGE")
        paths.add(filename)
        if status in PAIRED_STATUSES:
            previous = change.get("previous_filename")
            need(isinstance(previous, str) and previous, "MALFORMED_CHANGE")
            paths.add(previous)
        else:
            need("previous_filename" not in change, "MALFORMED_CHANGE")
    need(all(change["status"] != "changed" for change in changes), "TYPECHANGE_DENIED")

    registered_casefold = {}
    for name in registered_extensions:
        registered_casefold.setdefault(name.casefold(), set()).add(name)
    kinds, p1_extensions = set(), set()
    for path in paths:
        kind, name = _classify_parts(_path_parts(path, registered_casefold))
        kinds.add(kind)
        if kind == "P1":
            p1_extensions.add(name)
    for kind in PATH_DENIAL_ORDER:
        need(kind not in kinds, f"PATH_CLASS_{kind}_DENIED")
    need(len(p1_extensions) <= 1, "PATH_CLASS_P2_DENIED")
    need(p1_extensions == {extension}, "CROSS_EXTENSION_DENIED")
    need(scope_mode == "extension_subtree"
         or scope_mode == "candidate_manifest" and _manifest_only(changes, extension),
         "CANDIDATE_CHANGE_DENIED")
    return sorted(paths), sorted(kinds)


def _check_binding(binding, policy, extension, branch, changes, *, allow_legacy_reuse=False):
    need(type(binding) is dict, BINDING_MISMATCH)
    ticket, inputs, live = (binding.get(key) for key in ("ticket", "inputs_obj", "live_evidence"))
    need(all(type(obj) is dict for obj in (ticket, inputs, live)), BINDING_MISMATCH)
    verifier._positive_integer(ticket.get("policyEpoch"), BINDING_MISMATCH)
    need(ticket.get("operation") == inputs.get("operation") == "candidate"
         and ticket.get("repository") == inputs.get("repository") == CENTRAL_REPOSITORY
         and ticket.get("policyEpoch") == policy["policyEpoch"]
         and ticket.get("issuerKeyId") == policy["issuerKeyId"], BINDING_MISMATCH)
    run_id = binding.get("consumer_run_id")
    verifier._positive_integer(run_id, BINDING_MISMATCH)
    need(type(inputs.get("consumerRunId")) is int and inputs["consumerRunId"] == run_id,
         BINDING_MISMATCH)

    verifier._hex(ticket.get("requestId"), 32, BINDING_MISMATCH)
    need(live.get("authorized") is False and live.get("publication") is False
         and live.get("requestId") == ticket["requestId"], BINDING_MISMATCH)
    verifier._positive_integer(live.get("issuerRunId"), BINDING_MISMATCH)
    need(live.get("issuerRepository") == live_verifier.ISSUER_REPOSITORY
         and type(live.get("issuerRunAttempt")) is int and live["issuerRunAttempt"] == 1,
         BINDING_MISMATCH)
    verifier._hex(live.get("claimCommitSha"), 40, BINDING_MISMATCH)
    verifier._hex(live.get("ticketSha256"), 64, BINDING_MISMATCH)

    expected_branch = branch
    if allow_legacy_reuse:
        parsed = parse_branch(branch)
        if parsed.style == "legacy":
            expected_branch = format_branch(extension, parsed.candidate_id, "central")
    scope = inputs.get("centralScope")
    need(type(scope) is dict and scope == central_scope(extension, expected_branch)
         and scope["publication"] is False and _manifest_only(changes, extension), BINDING_MISMATCH)
    try:
        inputs_sha = hashlib.sha256(canonical_json(inputs)).hexdigest()
    except ValueError as exc:
        raise TicketRejected(BINDING_MISMATCH) from exc
    need(ticket.get("inputsSha256") == inputs_sha, BINDING_MISMATCH)


def build_run_claim_change_evidence(policy, extension, branch, scope_mode, paths, kinds, auth_binding):
    consumer_run = issuer_run = claim = None
    if auth_binding is not None:
        live = auth_binding["live_evidence"]
        consumer_run = {"repository": CENTRAL_REPOSITORY, "runId": auth_binding["consumer_run_id"]}
        issuer_run = {"repository": live["issuerRepository"], "runId": live["issuerRunId"],
                      "attempt": live["issuerRunAttempt"]}
        claim = {key: live[key] for key in ("requestId", "claimCommitSha", "ticketSha256")}
    return {
        "schemaVersion": 1, "status": "AUTHORIZED_CENTRAL_CANDIDATE",
        "authorized": True, "publication": False, "operation": "candidate",
        "repository": CENTRAL_REPOSITORY,
        "policy": {key: policy[key] for key in ("mode", "policyEpoch", "issuerKeyId")},
        "consumerRun": consumer_run, "issuerRun": issuer_run, "claim": claim,
        "target": {"extension": extension, "branch": branch, "scopeMode": scope_mode,
                   "paths": paths, "pathClasses": kinds},
    }


def enforce_central_candidate(*, policy, repository, extension, registered_extensions, branch, changes,
                              now=None, operation="candidate", publication=False, expected_candidate_id=None,
                              allow_legacy_reuse=False, scope_mode="candidate_manifest", auth_binding=None,
                              require_binding=False):
    """Enforce policy, operation, identity, branch, changes and live binding in order."""
    ticket = auth_binding.get("ticket") if type(auth_binding) is dict else None
    validate_policy(policy, datetime.now(timezone.utc) if now is None else now, ticket)
    need(publication is False, "PUBLICATION_DENIED")
    need(operation == "candidate", "OPERATION_NOT_ALLOWED")
    need(repository == CENTRAL_REPOSITORY, "CENTRAL_REPOSITORY_MISMATCH")
    need(valid_extension_name(extension), "INVALID_EXTENSION_NAME")
    need(isinstance(registered_extensions, (set, frozenset))
         and extension in registered_extensions
         and all(isinstance(name, str) for name in registered_extensions), "EXTENSION_NOT_REGISTERED")
    _check_branch(branch, extension, expected_candidate_id, allow_legacy_reuse)
    paths, kinds = evaluate_central_changes(changes, extension=extension,
                                          registered_extensions=registered_extensions,
                                          scope_mode=scope_mode)
    if require_binding or auth_binding is not None:
        _check_binding(auth_binding, policy, extension, branch, changes,
                       allow_legacy_reuse=allow_legacy_reuse)
    return build_run_claim_change_evidence(policy, extension, branch, scope_mode, paths, kinds, auth_binding)
