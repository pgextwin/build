"""Reuse existing original GitHub ZIP reader without gaining download authority."""
from __future__ import annotations
import importlib.util
from pathlib import Path


def verify_original_bytes(catalog, candidate):
    path = Path(catalog) / "scripts/issue112-external-zip-pilot.py"
    spec = importlib.util.spec_from_file_location("original_zip_pilot", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    expected = {(r["sourceRepo"], r["releaseId"], r["assetId"]): r
                for r in candidate["records"]}
    if len(expected) != 2:
        raise ValueError("Unexpected external candidate count")
    # Ensure the existing independently tested ZIP reader's exact pins
    # correspond to the newly signed, immutable Catalog source records.
    for item in mod.SOURCES:
        key = (item["repo"], item["releaseId"], item["assetId"])
        if key not in expected:
            raise ValueError("Untrusted original ZIP source")
        row = expected[key]
        if (item["bytes"] != row["originalBytes"]
                or item["sha256"] != row["originalSha256"]
                or item["tag"] != row["releaseTag"]
                or item["asset"] != row["assetName"]):
            raise ValueError("Original ZIP reader does not match signed source")
    # Actual external-provider original bytes are downloaded only in this
    # independent, nonpublishing central CI job; never mirrored or extracted.
    mod.run()
    return [{"sourceRepo": row["sourceRepo"], "releaseId": row["releaseId"],
             "assetId": row["assetId"], "bytesVerified": True}
            for row in candidate["records"]]
