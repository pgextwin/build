#!/usr/bin/env python3
"""Existing authenticated connected-Chat candidate identity, never authority.

The protected-main event verifier and the explicit policy declaration share
this one allowlist. A declaration is not evidence that an actor, App or merge
actually occurred; the live verifier still authenticates the original event,
PR, exact-head checks, immutable source and independently audited artifacts.
"""
from __future__ import annotations

MODE = "authenticated-connected-chat"
ALLOWED_ACTORS = frozenset({"ShutenOishi"})


class Denied(ValueError):
    pass


def declaration():
    return {"mode": MODE, "actors": sorted(ALLOWED_ACTORS),
            "requireSamePushAndMergeActor": True}


def validate(value):
    if not (type(value) is dict and set(value) == set(declaration())
            and value.get("mode") == MODE
            and type(value.get("actors")) is list
            and all(type(actor) is str for actor in value["actors"])
            and value["actors"] == sorted(ALLOWED_ACTORS)
            and value.get("requireSamePushAndMergeActor") is True):
        raise Denied("candidate identity differs from the trusted live merge gate")
    return tuple(value["actors"])
