#!/usr/bin/env python3
"""Offline hostile contract for durable original PRE-WRITE dispatch inputs.

Never treats an original journal as an authenticated POST ACK or App CAS.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
spec = importlib.util.spec_from_file_location("r10source",
    Path(__file__).resolve().parents[1]/"scripts/issue311-coordinator-fleet-local-prepare.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
name="orafce"
r={"sourceRunId":41000000001,"sourceHeadSha":"a"*40,
   "sourceArtifactId":123456789,"sourceZipSha256":"b"*64,
   "localMainSha":"c"*40}
inputs={"request_id":m.LOCAL_IDS[name],"source_run_id":str(r["sourceRunId"]),
        "source_head_sha":r["sourceHeadSha"],
        "source_artifact_id":str(r["sourceArtifactId"]),
        "source_zip_sha256":r["sourceZipSha256"],
        "central_request_id":m.REQUEST_ID,"local_main_sha":r["localMainSha"]}
payload={"ref":"main","inputs":inputs}
with TemporaryDirectory() as d:
    root=Path(d)
    receipt=m.journal_dispatch(name,payload,r,root)
    original=(root/"orafce.json").read_bytes()
    assert original.endswith(b"\\n")
    stored=json.loads(original)
    wire=base64.b64decode(stored["requestBodyBase64"],validate=True)
    assert wire==json.dumps(payload,separators=(",",":")).encode()
    assert stored["requestBodySha256"]==hashlib.sha256(wire).hexdigest()
    assert stored["writeAckEstablished"] is False
    assert stored["originalChildEstablished"] is False
    assert stored["publicationAuthorized"] is False
    assert "PRIVATE_KEY" not in original.decode()
    assert receipt==stored
    try: m.journal_dispatch(name,payload,r,root)
    except (ValueError,OSError): pass
    else: raise AssertionError("replay journal overwritten")
    for bad in ({"ref":"release","inputs":inputs},
                {"ref":"main","inputs":dict(inputs,local_main_sha="d"*40)},
                {"ref":"main","inputs":dict(inputs,token="secret")}):
        try: m.journal_dispatch(name,bad,r,root/("bad"+str(len(list(root.iterdir())))))
        except (ValueError,OSError): pass
        else: raise AssertionError("untrusted dispatch input admitted")
print("R10_ORIGINAL_DISPATCH_PREWRITE_JOURNAL_HOSTILE_PASS_NOT_LIVE_CAS")
