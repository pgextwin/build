#!/usr/bin/env python3
"""No-network hostile proof for the SHA-pinned permanent R10-02 Git report."""
import importlib.util
from pathlib import Path

p = Path("scripts/issue311-r10-protected-report.py")
spec = importlib.util.spec_from_file_location("r10_archive", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
raw = m.restore()
assert len(raw) == 76647
def deny(name, data):
    try:
        m.restore(data)
    except (ValueError, OSError):
        print("R10_PROTECTED_REPORT_DENY", name)
        return
    raise AssertionError("R10_PROTECTED_REPORT_FALSE_ACCEPT " + name)
archive = m.ARCHIVE.read_bytes()
deny("changed compressed digest", archive[:-2] + b"B\n")
deny("extra line", archive + b"\n")
deny("truncated", archive[:99] + b"\n")
deny("bad base64", b"!\n")
print("R10_PROTECTED_REPORT_OFFLINE_PASS no keys no network no publish")
