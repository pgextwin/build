#!/usr/bin/env python3
"""Stage-2 foundation: LOCAL_AUTH_REQUEST_V1 verification, never execution.

Environment verified 2026-11-17: cryptography and PyNaCl are NOT installed.
The bundled pure-Python Ed25519 path is therefore active here. When available,
cryptography is preferred. The fallback is verification-only; constant-time is
NOT guaranteed (verification of public data only). No subprocesses or network.
RFC 8032 sections 5.1/7.1: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7

Canonical form is UTF-8 JSON, UTF-16-sorted object keys, no insignificant
whitespace, no floats, safe integers only, and no lone Unicode surrogates. This
is the integer-only subset of RFC 8785; request fields themselves are ASCII.
Raw ticket text and separately supplied input bytes must already be canonical.
The signature covers canonical ticket bytes with ONLY 'signature' removed.

verify_ticket returns evidence only, including under injected OBSERVE/ENFORCE
test policies. authorize is the production gate: DENY always rejects, and other
modes are NOT implemented. This module cannot authorize PRs, signatures,
publication or workflow dispatch. The CLI reads files and emits rejection JSON.

Repository ID is only checked as a positive integer; live GitHub ID/main/policy
SHA/verifier/source bindings, detailed input semantics, per-repository opt-in,
issuer service, rate limits, durable one-time claims and replay protection are
later stages. Signed SHA fields are checked for format and signature integrity,
not against live main. Repeated pure verification does not consume a ticket.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    Ed25519PublicKey = None

SIGNATURE_BACKEND = "cryptography" if Ed25519PublicKey is not None else "pure-python"
MAX_SAFE_INTEGER = 2**53 - 1
MAX_TICKET_BYTES = 16384
MAX_INPUTS_BYTES = 1048576
WORKFLOW_PATH = ".github/workflows/local-authorized-candidate.yml"
TICKET_FIELDS = frozenset({
    "schemaVersion", "sourceKind", "issuerKeyId", "policyEpoch", "policySha",
    "requestId", "nonce", "issuedAt", "notBefore", "expiresAt", "operation",
    "repository", "repositoryId", "targetMainSha", "centralMainSha",
    "workflowPath", "verifierSha", "inputsSha256", "manifestBlob",
    "upstreamSourcesSha256", "signature",
})
HEX_LENGTHS = {
    "policySha": 40, "requestId": 32, "nonce": 64, "targetMainSha": 40,
    "centralMainSha": 40, "verifierSha": 40, "inputsSha256": 64,
    "manifestBlob": 40, "upstreamSourcesSha256": 64, "signature": 128,
}
TIMESTAMP_PATTERN = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"


class TicketRejected(ValueError):
    """Fail-closed rejection carrying a stable machine-readable code."""

    def __init__(self, code, detail=""):
        self.code = code
        super().__init__(detail or code)


def _reject(code, detail=""):
    raise TicketRejected(code, detail)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("DUPLICATE_KEY", key)
        result[key] = value
    return result


def _no_float(_value):
    _reject("FLOAT_NOT_ALLOWED")


def _normalize_json(value, depth=0):
    if depth > 32:
        _reject("JSON_TOO_DEEP")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            _reject("INTEGER_OUT_OF_RANGE")
        return value
    if type(value) is float:
        _reject("FLOAT_NOT_ALLOWED")
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            _reject("INVALID_UNICODE")
        return value
    if type(value) is list:
        return [_normalize_json(item, depth + 1) for item in value]
    if type(value) is dict:
        for key in value:
            if type(key) is not str:
                _reject("INVALID_JSON_TYPE")
            _normalize_json(key, depth + 1)
        return {key: _normalize_json(value[key], depth + 1)
                for key in sorted(value, key=lambda key: key.encode("utf-16-be"))}
    _reject("INVALID_JSON_TYPE")


def canonical_json(value):
    """Return deterministic integer-only canonical UTF-8 JSON bytes."""
    return json.dumps(_normalize_json(value), ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _parse_json(text, limit):
    if type(text) is not str:
        _reject("INVALID_JSON_TYPE")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        _reject("INVALID_UNICODE")
    if size > limit:
        _reject("TOO_LARGE")
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_float=_no_float, parse_constant=_no_float)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, TicketRejected):
            raise
        _reject("INVALID_JSON")
    _normalize_json(value)
    return value


def _positive_integer(value, code="TYPE_MISMATCH"):
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        _reject(code)


def _hex(value, length, code="BAD_FORMAT"):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        _reject(code)


def _timestamp(value, code="BAD_TIMESTAMP"):
    if type(value) is not str or re.fullmatch(TIMESTAMP_PATTERN, value) is None:
        _reject(code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _reject(code)


def _validate_ticket_shape(ticket):
    if type(ticket) is not dict:
        _reject("NON_OBJECT")
    if set(ticket) - TICKET_FIELDS:
        _reject("UNKNOWN_FIELD")
    if TICKET_FIELDS - set(ticket):
        _reject("MISSING_FIELD")
    if len(canonical_json(ticket)) > MAX_TICKET_BYTES:
        _reject("TOO_LARGE")
    if type(ticket["schemaVersion"]) is not int or ticket["schemaVersion"] != 1:
        _reject("SCHEMA_MISMATCH")
    if ticket["sourceKind"] != "LOCAL_AUTH_REQUEST_V1":
        _reject("SCHEMA_MISMATCH")
    if ticket["operation"] != "candidate":
        _reject("OPERATION_NOT_ALLOWED")
    if ticket["workflowPath"] != WORKFLOW_PATH:
        _reject("WORKFLOW_MISMATCH")
    for field in ("policyEpoch", "repositoryId"):
        _positive_integer(ticket[field])
    for field, length in HEX_LENGTHS.items():
        _hex(ticket[field], length)
    if (type(ticket["issuerKeyId"]) is not str or
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", ticket["issuerKeyId"]) is None):
        _reject("BAD_FORMAT")
    repository = ticket["repository"]
    if (type(repository) is not str or len(repository) > 140 or
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", repository) is None):
        _reject("BAD_FORMAT")
    for field in ("issuedAt", "notBefore", "expiresAt"):
        _timestamp(ticket[field])


def parse_ticket(text):
    """Strict parse: exact fields, duplicate/float rejection, canonical raw text."""
    ticket = _parse_json(text, MAX_TICKET_BYTES)
    _validate_ticket_shape(ticket)
    if text.encode("utf-8") != canonical_json(ticket):
        _reject("NON_CANONICAL_TICKET")
    return ticket


# Verification-only Edwards25519 arithmetic, RFC 8032 sections 5.1 and 6.
# Extended coordinates (X:Y:Z:T), x=X/Z, y=Y/Z, T=XY/Z.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _point_add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mul(scalar, point):
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(left, right):
    return ((left[0] * right[2] - right[0] * left[2]) % _P == 0 and
            (left[1] * right[2] - right[1] * left[2]) % _P == 0)


def _decode_point(encoded):
    if len(encoded) != 32:
        raise ValueError("point length")
    packed = int.from_bytes(encoded, "little")
    sign, y = packed >> 255, packed & (2**255 - 1)
    if y >= _P:
        raise ValueError("noncanonical point")
    yy = y * y % _P
    denominator = (_D * yy + 1) % _P
    if denominator == 0:
        raise ValueError("invalid point")
    xx = (yy - 1) * pow(denominator, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if x * x % _P != xx:
        x = x * _SQRT_M1 % _P
    if x * x % _P != xx or (x == 0 and sign):
        raise ValueError("invalid point")
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BASE = _decode_point(bytes.fromhex("58" + "66" * 31))


def _signature_parts(public_key, signature):
    if type(public_key) is not bytes or type(signature) is not bytes:
        raise ValueError("byte strings required")
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("invalid lengths")
    a = _decode_point(public_key)
    r = _decode_point(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        raise ValueError("noncanonical scalar")
    # Fail closed for identity/small-order and mixed-order points. Apply the
    # same strict subgroup rules before either backend to avoid disagreement.
    for point in (a, r):
        if (_point_equal(point, _IDENTITY) or
                not _point_equal(_scalar_mul(_L, point), _IDENTITY)):
            raise ValueError("not a nonidentity prime-order point")
    return a, r, s


def verify_ed25519_pure(public_key, message, signature):
    """Verify [S]B = R + [SHA512(R || A || M)]A; never sign or generate keys."""
    if type(message) is not bytes:
        return False
    try:
        a, r, s = _signature_parts(public_key, signature)
    except ValueError:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _point_equal(_scalar_mul(s, _BASE),
                        _point_add(r, _scalar_mul(challenge, a)))


def verify_ed25519(public_key, message, signature):
    if Ed25519PublicKey is None:
        return verify_ed25519_pure(public_key, message, signature)
    try:
        _signature_parts(public_key, signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (ValueError, InvalidSignature):
        return False
    return True


def _policy_key(ticket, policy, now):
    if type(policy) is not dict:
        _reject("INVALID_POLICY")
    if (type(policy.get("schemaVersion")) is not int or policy["schemaVersion"] != 1 or
            policy.get("mode") not in ("DENY", "OBSERVE", "ENFORCE")):
        _reject("INVALID_POLICY")
    _positive_integer(policy.get("policyEpoch"), "INVALID_POLICY")
    revoked = policy.get("revokedPolicyEpochs")
    if type(revoked) is not list:
        _reject("INVALID_POLICY")
    for epoch in revoked:
        _positive_integer(epoch, "INVALID_POLICY")
    if ticket["policyEpoch"] in revoked:
        _reject("EPOCH_REVOKED")
    if ticket["policyEpoch"] != policy["policyEpoch"]:
        _reject("EPOCH_MISMATCH")
    if policy.get("issuerPublicKey") is None or policy.get("issuerKeyId") is None:
        _reject("KEY_UNSET")
    _hex(policy["issuerPublicKey"], 64, "INVALID_POLICY")
    if ticket["issuerKeyId"] != policy["issuerKeyId"]:
        _reject("ISSUER_MISMATCH")
    if (policy.get("allowedOperations") != ["candidate", "requalify"] or
            policy.get("publication") is not False):
        _reject("INVALID_POLICY")
    if policy.get("delegationStartsAt") is None or policy.get("delegationEndsAt") is None:
        _reject("DELEGATION_UNSET")
    start = _timestamp(policy["delegationStartsAt"], "INVALID_POLICY")
    end = _timestamp(policy["delegationEndsAt"], "INVALID_POLICY")
    if end <= start:
        _reject("INVALID_POLICY")
    if not start <= now < end:
        _reject("OUTSIDE_DELEGATION")
    return bytes.fromhex(policy["issuerPublicKey"])


def verify_ticket(ticket_obj, inputs_bytes, policy, fleet_repositories, now):
    """Pure evidence verification. A successful result grants NO authority."""
    _validate_ticket_shape(ticket_obj)
    if (not isinstance(now, datetime) or now.tzinfo is None or
            now.utcoffset() != timedelta(0)):
        _reject("INVALID_CLOCK")
    ticket = ticket_obj
    issued = _timestamp(ticket["issuedAt"])
    not_before = _timestamp(ticket["notBefore"])
    expires = _timestamp(ticket["expiresAt"])
    if expires <= issued:
        _reject("INVALID_LIFETIME")
    if expires - issued > timedelta(minutes=15):
        _reject("LIFETIME_TOO_LONG")
    if issued > not_before or not_before >= expires:
        _reject("INVALID_TIME_ORDER")
    if not_before > now + timedelta(seconds=60):
        _reject("NOT_YET_VALID")
    if now >= expires:
        _reject("EXPIRED")
    public_key = _policy_key(ticket, policy, now)
    if type(fleet_repositories) not in (set, frozenset) or not all(type(repo) is str for repo in fleet_repositories):
        _reject("INVALID_FLEET")
    if ticket["repository"] not in fleet_repositories:
        _reject("REPO_NOT_IN_FLEET")
    if type(inputs_bytes) is not bytes:
        _reject("INVALID_INPUTS")
    if len(inputs_bytes) > MAX_INPUTS_BYTES:
        _reject("TOO_LARGE")
    if hashlib.sha256(inputs_bytes).hexdigest() != ticket["inputsSha256"]:
        _reject("INPUTS_HASH_MISMATCH")
    try:
        inputs_text = inputs_bytes.decode("utf-8")
    except UnicodeDecodeError:
        _reject("INVALID_INPUTS")
    inputs = _parse_json(inputs_text, MAX_INPUTS_BYTES)
    if type(inputs) is not dict:
        _reject("INVALID_INPUTS")
    if canonical_json(inputs) != inputs_bytes:
        _reject("NON_CANONICAL_INPUTS")
    unsigned = canonical_json({key: value for key, value in ticket.items() if key != "signature"})
    if not verify_ed25519(public_key, unsigned, bytes.fromhex(ticket["signature"])):
        _reject("BAD_SIGNATURE")
    return {"status": "VERIFIED_TICKET_ONLY", "authorized": False,
            "publication": False, "requestId": ticket["requestId"],
            "ticketSha256": hashlib.sha256(canonical_json(ticket)).hexdigest(),
            "signatureBackend": SIGNATURE_BACKEND}


def authorize(ticket_obj, inputs_bytes, policy, fleet_repositories, now):
    """Production gate. DENY takes precedence even over malformed tickets."""
    if type(policy) is not dict:
        _reject("INVALID_POLICY")
    if policy.get("mode") == "DENY":
        _reject("DENY_MODE")
    # Changing mode in JSON must never activate a later-stage execution path.
    _reject("MODE_NOT_IMPLEMENTED")


def _read_text(path, limit):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        _reject("TOO_LARGE")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        _reject("INVALID_UNICODE")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ticket", type=Path, required=True, help="canonical ticket JSON file")
    parser.add_argument("--inputs", type=Path, required=True, help="canonical inputs JSON file")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        policy = _parse_json(_read_text(root / "metadata/local-candidate-authority.json", 65536), 65536)
        fleet = _parse_json(_read_text(root / "metadata/automation-fleet.json", MAX_INPUTS_BYTES), MAX_INPUTS_BYTES)
        if type(policy) is not dict:
            _reject("INVALID_POLICY")
        reference = policy.get("targetSet")
        if (type(fleet) is not dict or type(fleet.get("schemaVersion")) is not int or
                reference != {"path": "metadata/automation-fleet.json", "schemaVersion": fleet["schemaVersion"]}):
            _reject("INVALID_FLEET")
        entries = fleet.get("entries")
        if (type(entries) is not list or not entries or
                any(type(entry) is not dict or type(entry.get("repository")) is not str for entry in entries)):
            _reject("INVALID_FLEET")
        repositories = {entry["repository"] for entry in entries}
        ticket = parse_ticket(_read_text(args.ticket, MAX_TICKET_BYTES))
        with args.inputs.open("rb") as stream:
            inputs_bytes = stream.read(MAX_INPUTS_BYTES + 1)
        if len(inputs_bytes) > MAX_INPUTS_BYTES:
            _reject("TOO_LARGE")
        authorize(ticket, inputs_bytes, policy, repositories, datetime.now(timezone.utc))
    except TicketRejected as exc:
        print(json.dumps({"status": "REJECTED", "code": exc.code}), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "REJECTED", "code": "LOAD_ERROR"}), file=sys.stderr)
        return 1
    # No success path exists in the stage-2 production gate.
    return 1


if __name__ == "__main__":
    sys.exit(main())
