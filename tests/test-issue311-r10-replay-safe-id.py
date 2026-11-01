#!/usr/bin/env python3
"""R10 replay-safe ID hostile tests; pure ID gate is not a live App CAS proof."""
import importlib.util
from pathlib import Path

src=Path(__file__).resolve().parents[1]/"scripts/issue311-r10-replay-safe-id.py"
spec=importlib.util.spec_from_file_location("r10_local_ids",src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=dict(central_request_id="r-20261101-r06prepareoriginal01",
          source_run_id=41200000000,source_head_sha="a"*40,
          source_zip_sha256="b"*64,target_repo="pgextwin/orafce",
          target_main_sha="c"*40)
rid=m.derive(**base)
assert m.RID.fullmatch(rid)
assert rid==m.derive(**base), "replay must reuse identical ID, not mint a second request"
allids={m.derive(**{**base,"target_repo":"pgextwin/"+name}) for name in m.TARGETS}
assert len(allids)==17, "all 17 targets must have independent IDs"
for k,v in [
    ("source_run_id",41200000001),("source_head_sha","d"*40),
    ("source_zip_sha256","e"*64),("target_main_sha","f"*40),
    ("central_request_id","r-20261101-r06prepareoriginal02")]:
    assert m.derive(**{**base,k:v})!=rid
inputs=dict(request_id=rid,central_request_id=base["central_request_id"],
    source_run_id=str(base["source_run_id"]),source_head_sha=base["source_head_sha"],
    source_zip_sha256=base["source_zip_sha256"],
    target_repo=base["target_repo"],local_main_sha=base["target_main_sha"])
assert m.verify(inputs)==rid
for bad in [
    {**inputs,"request_id":"r-20261030-r06coordlocalpilot01"},
    {**inputs,"source_run_id":"0"+inputs["source_run_id"]},
    {**inputs,"extra":"no"},
    {**inputs,"target_repo":"pgextwin/unknown"},
    {**inputs,"source_zip_sha256":"not-a-hash"},
    {**inputs,"source_head_sha":"f"*40}
]:
    try: m.verify(bad)
    except ValueError: pass
    else: raise AssertionError("untrusted/local replay input was accepted")
print("R10_REPLAY_SAFE_DERIVATION_HOSTILE_PASS: NOT A LIVE DISPATCH OR STATE CAS")
