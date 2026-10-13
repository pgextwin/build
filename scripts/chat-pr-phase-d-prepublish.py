#!/usr/bin/env python3
"""Issue #75 Phase D: inert, fail-closed just-in-time identity/TOCTOU recheck.

This is a pure coordinator for independently validated, AUTHENTICATED inputs
supplied in two consecutive reads by a FUTURE trusted runner. It does not
fetch GitHub APIs, accept user-supplied JSON, enable a publisher, verify ZIP
signatures, mint tokens, write Releases, or issue publishable receipts.

No live authorization request exists in the pilot: test fixtures are synthetic.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    if spec is None or spec.loader is None:
        raise PhaseDDenied("trusted candidate/approval helper unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PhaseDDenied(ValueError):
    """Missing or changing authoritative evidence is never accepted."""


approval_module = load_module("phase_d_chat_auth", "chat-pr-authorization.py")
classic_module = load_module("phase_d_classic", "classic-protection-audit.py")

EXPECTED_KEYS = frozenset({
    "mainSha", "tagRef", "release", "candidateReceipt", "approval",
    "classicComposite", "artifactSignatures",
})


def require(condition, reason):
    if not condition:
        raise PhaseDDenied(reason)


def _round(snapshot, *, expected_main_sha, expected_operator):
    require(type(snapshot) is dict and frozenset(snapshot) == EXPECTED_KEYS,
            "missing/unexpected JIT input fields")
    require(snapshot["mainSha"] == expected_main_sha,
            "main changed or diverged from event SHA")
    require(snapshot["tagRef"] == "ABSENT" and snapshot["release"] == "ABSENT",
            "occupied, unknown or changed tag/Release state")

    classic = snapshot["classicComposite"]
    require(type(classic) is dict
            and classic.get("schemaVersion") == 1
            and type(classic.get("schemaVersion")) is int
            and classic.get("status") == "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY"
            and classic.get("repository") == "pgextwin/plpgsql_check"
            and classic.get("branch") == "main"
            and classic.get("mainSha") == expected_main_sha
            and type(classic.get("snapshotCount")) is int
            and classic["snapshotCount"] == 2
            and classic.get("bypassEvidence") == "GRAPHQL_ZERO_FOR_REST_OMISSION"
            and classic.get("pushEvidence") == "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION"
            and classic.get("independentEffectiveRefZero") is True
            and classic.get("independentPushUnrestricted") is True
            and classic.get("requiredChecksAppId") == 15368
            and type(classic.get("requiredChecksAppId")) is int
            and type(classic.get("requiredChecks")) is list
            and len(classic["requiredChecks"]) == 8
            and set(classic["requiredChecks"]) == classic_module.REQUIRED_CONTEXTS
            and classic.get("strict") is True
            and classic.get("pullRequestRequired") is True
            and classic.get("requiredApprovals") == 0
            and type(classic.get("requiredApprovals")) is int
            and classic.get("adminEnforced") is True
            and classic.get("actorBypass") is False
            and classic.get("forcePushAllowed") is False
            and classic.get("deletionAllowed") is False
            and classic.get("publishableReceipt") is False,
            "fresh effective Classic branch protection unproven")

    # Phase D does NOT verify signed ZIP/attestation bytes. A mere scalar
    # "verified" assertion from a PR or synthetic fixture MUST be rejected.
    require(snapshot["artifactSignatures"] == "NOT_INDEPENDENTLY_VERIFIED",
            "artifact/signed provenance must remain explicitly unverified")

    candidate = snapshot["candidateReceipt"]
    authorization = snapshot["approval"]
    require(type(candidate) is dict and type(authorization) is dict
            and authorization.get("event") == "push"
            and authorization.get("operator") == expected_operator
            and authorization.get("repository") == "pgextwin/plpgsql_check"
            and authorization.get("authorizationCommit") == expected_main_sha
            and candidate.get("operator") == expected_operator
            and candidate.get("repository") == "pgextwin/plpgsql_check",
            "trusted event/operator/approval context missing")
    try:
        context = approval_module.bind_verified_receipt(candidate, authorization)
    except (approval_module.Denied, KeyError, TypeError, ValueError):
        raise PhaseDDenied("candidate and PR authorization identities disagree") from None
    require(context.get("status") == "DRY_RUN_CONTEXT_ONLY"
            and context.get("publishingEnabled") is False
            and context.get("publishableReceipt") is False
            and context.get("signedArtifactsVerified") is False,
            "candidate/authorization join not safely inert")
    return context


def verify_inert_prepublication_recheck(reader, *, expected_main_sha, expected_operator):
    """Require two independent complete snapshots immediately before the boundary.

    FUTURE ADAPTER OBLIGATION (not implemented here): every capture must read
    actual current main and Git tag/Release absence, and re-run independently
    verified candidate gate, GitHub merged-PR authorization gate and the same-
    token, effective-main Classic REST+GraphQL composite gate. Neither a
    self-asserted callback nor offline fixtures prove live GitHub provenance.

    Races at any point cause DENY. This function NEVER returns an accepted
    publisher receipt, even if all synthetic tests pass.
    """
    require(type(expected_main_sha) is str
            and classic_module.SHA.fullmatch(expected_main_sha) is not None
            and approval_module.human(expected_operator),
            "invalid trusted SHA or human operator")
    require(callable(getattr(reader, "capture", None)),
            "no trusted double-read adapter")
    first = reader.capture()
    joined_first = _round(first, expected_main_sha=expected_main_sha,
                          expected_operator=expected_operator)
    second = reader.capture()
    joined_second = _round(second, expected_main_sha=expected_main_sha,
                           expected_operator=expected_operator)
    # Require the *underlying* snapshots, not just an equal-looking receipt,
    # to be stable; this catches candidate, tag and protection TOCTOU.
    require(first == second and joined_first == joined_second,
            "prepublication main, candidate, PR, tag or Classic evidence raced")
    return {
        "schemaVersion": 1,
        "status": "DRY_RUN_PHASE_D_RECHECK_ONLY",
        "repository": "pgextwin/plpgsql_check",
        "mainSha": expected_main_sha,
        "authorizationPr": joined_second["authorizationPr"],
        "candidatePr": joined_second["candidatePr"],
        "candidateRunId": joined_second["candidateRunId"],
        "decisionRunId": joined_second["decisionRunId"],
        "snapshotCount": 2,
        "freshClassicCompositeEachRound": True,
        "tagAndReleaseAbsentEachRound": True,
        "candidateArtifactsAndSignatures": "NOT_INDEPENDENTLY_VERIFIED",
        "publishingEnabled": False,
        "publishableReceipt": False,
        "signedArtifactsVerified": False,
    }
