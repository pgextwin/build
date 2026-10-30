#!/usr/bin/env python3
"""Hostile no-network verification of exact archived R10 negative original bytes."""
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("r10_negative_archive", Path("scripts/issue311-r10-negative-protected.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
raw = m.restore()
assert len(raw) == 72255
def deny(name, content):
    try:
        m.restore(content)
    except (ValueError, OSError):
        print("R10_NEGATIVE_PROTECTED_DENY", name)
        return
    raise AssertionError("R10_NEGATIVE_PROTECTED_FALSE_ACCEPT " + name)
archive = m.ARCHIVE.read_bytes()
deny("modified digest", archive[:-3] + b"AA\n")
deny("extra newline", archive + b"\n")
deny("truncation", archive[:50] + b"\n")
deny("bad base64", b"!\n")
assert b'"accepted": false' in raw
assert b'"missingEvidenceReason": "NO_DISPATCH_INPUT_BINDING_OR_ORIGINAL_CHILD_ZIP"' in raw
print("R10_NEGATIVE_PROTECTED_OFFLINE_PASS no App keys no network no publication")
