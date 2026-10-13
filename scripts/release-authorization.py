#!/usr/bin/env python3
"""Strict typed Release receipt / PACKAGE-INFO event contract (Phase B).

No event handler, release writer or authorization endpoint. A Chat-PR receipt
can ONLY be issued by a separate independent live GitHub-PR + candidate gate.
"""
import re

SHA = re.compile(r"^[0-9a-f]{40}$")
HUMAN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
TYPES = {
    "manual-dispatch": ("VERIFIED_MANUAL_DISPATCH", "workflow_dispatch"),
    "chat-pr-authorization": ("VERIFIED_CHAT_PR_AUTHORIZATION", "push"),
}


class Denied(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Denied(reason)


def validate_receipt(receipt, *, repository, commit, actor, event):
    require(type(receipt) is dict and receipt.get("schemaVersion") == 1
            and type(receipt.get("schemaVersion")) is int,
            "invalid receipt schema")
    mode = receipt.get("authorizationMode")
    require(isinstance(mode, str) and mode in TYPES,
            "unsupported authorization mode")
    status, expected_event = TYPES[mode]
    require(receipt.get("status") == status and event == expected_event,
            "authorization receipt status / execution event mismatch")
    require(isinstance(actor, str) and HUMAN.fullmatch(actor)
            and not actor.lower().endswith("bot")
            and receipt.get("operator") == actor
            and receipt.get("repository") == repository
            and isinstance(commit, str) and SHA.fullmatch(commit)
            and receipt.get("trustedCommit") == commit,
            "receipt operator, repository or exact commit mismatch")
    require(isinstance(receipt.get("releaseTag"), str)
            and isinstance(receipt.get("majors"), list)
            and len(receipt["majors"]) > 0
            and isinstance(receipt.get("sources"), list),
            "incomplete signed Release authorization")
    if mode == "chat-pr-authorization":
        # A green Windows run or a synthetic ID join does not prove signed
        # ZIP/SBOM/attestation bytes. A future trusted verifier MUST explicitly
        # establish this evidence before issuing a typed receipt. Never accept
        # a read-only pilot context, even if its status has been relabelled.
        require(receipt.get("signedArtifactsVerified") is True
                and receipt.get("publishingEnabled") is not False
                and receipt.get("publishableReceipt") is not False,
                "independent signed artifacts unproven or dry-run context")
        require(type(receipt.get("authorizationPr")) is int
                and receipt["authorizationPr"] > 0
                and receipt.get("authorizationCommit") == commit
                and isinstance(receipt.get("authorizationHeadSha"), str)
                and SHA.fullmatch(receipt["authorizationHeadSha"])
                and isinstance(receipt.get("authorizationBaseSha"), str)
                and SHA.fullmatch(receipt["authorizationBaseSha"])
                and receipt.get("authorizationBaseSha") != commit
                and isinstance(receipt.get("candidateHeadSha"), str)
                and SHA.fullmatch(receipt["candidateHeadSha"])
                and type(receipt.get("candidatePr")) is int
                and receipt.get("candidatePr") > 0
                and type(receipt.get("candidateRunId")) is int
                and receipt.get("candidateRunId") > 0
                and type(receipt.get("decisionRunId")) is int
                and receipt.get("decisionRunId") > 0,
                "Chat PR mode requires exact merged approval and candidate receipt identities")
    return expected_event
