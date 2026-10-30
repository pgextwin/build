#!/usr/bin/env python3
"""Offline contract: real workflow_run completed -> independent App CAS; deny forged events."""
import hashlib
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r06_auto",ROOT/"scripts/issue311-r06-app-fleet-cas-terminal.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
source_id=41011122233
main="b"*40
original_head="a"*40
start=datetime.now(timezone.utc).replace(microsecond=0)-timedelta(minutes=12)
stamp=lambda d:d.strftime("%Y-%m-%dT%H:%M:%SZ")
source={"id":source_id,"name":mod.SOURCE_NAME,"path":mod.SOURCE_PATH,"event":"workflow_run",
        "head_branch":"main","run_attempt":1,"status":"completed","conclusion":"success",
        "head_sha":original_head,"actor":{"login":"ShutenOishi"},
        "run_started_at":stamp(start-timedelta(minutes=8)),"updated_at":stamp(start)}
central_request="r-20261030-r06preparecoordfleet03"
original={"schemaVersion":1,"requestId":central_request,
          "sourceKind":"AUTHENTIC_APP_BOT_17_LOCAL_ORIGINAL_NONPUBLISHING",
          "result":"CHILDREN_17_ORIGINAL_ZIP_VERIFIED_CAS_PENDING",
          "runtimeEnabled":False,"durableCasVerified":False,
          "publicReleaseAuthorized":False,"publicationAuthorized":False,
          "publisherSourceKindAuthorized":False,"candidateAdmissionAuthorized":False,
          "children":[{} for _ in range(17)],
          "central":{"sourceRunId":41011122222,"sourceHeadSha":original_head,
                     "sourceZipSha256":"c"*64}}
art={"total_count":1,"artifacts":[{"id":12953810357,"name":mod.SOURCE_ARTIFACT,
      "expired":False,"workflow_run":{"id":source_id},"digest":"sha256:"+"d"*64}]}
event={"action":"completed","repository":{"full_name":"pgextwin/build"},
       "workflow_run":dict(source)}
def fake_get(url):
    if url.endswith("/"+str(source_id)):return dict(source)
    if url.endswith("/"+str(source_id)+"/artifacts?per_page=100"):return dict(art)
    if url.endswith("/branches/main"):return {"protected":True,"commit":{"sha":main}}
    raise AssertionError("unexpected URL "+url)
env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_EVENT_NAME":"workflow_run",
     "GITHUB_REF":"refs/heads/main","GITHUB_WORKFLOW":mod.WORKFLOW,
     "GITHUB_RUN_ATTEMPT":"1","GITHUB_SHA":main}
with TemporaryDirectory() as tmp:
    file=Path(tmp)/"event.json"
    file.write_text(json.dumps(event))
    env["GITHUB_EVENT_PATH"]=str(file)
    with patch.dict(os.environ,env,clear=True),patch.object(mod.bridge,"get_json",side_effect=fake_get),patch.object(mod.bridge,"original_zip",return_value=(original,"d"*64)),patch.object(mod.subprocess,"check_output",return_value=main+"\n"),patch.object(mod.subprocess,"run",return_value=SimpleNamespace(returncode=0)):
        r,sha,head=mod.request_proof()
        assert r["sourceRunId"]==source_id and r["centralRunId"]==41011122222
        assert mod.REQ==r["requestId"] and mod.CENTRAL_REQUEST==central_request
        assert r["sourceZipSha256"]=="d"*64 and head==main
        assert len(sha)==64 and r["runtimeEnabled"] is False and r["publicReleaseAuthorized"] is False
        for mutate in (
            {"action":"requested"},
            {"workflow_run":{"event":"workflow_dispatch"}},
            {"workflow_run":{"conclusion":"failure"}},
            {"workflow_run":{"run_attempt":2}},
            {"workflow_run":{"actor":{"login":"attacker"}}},
            {"workflow_run":{"path":"untrusted.yml"}},
            {"workflow_run":{"head_sha":"0"*40}},
            {"repository":{"full_name":"pgextwin/other"}},
        ):
            bad=json.loads(json.dumps(event))
            bad.update({k:({**bad[k],**v} if k in bad and isinstance(v,dict) else v) for k,v in mutate.items()})
            file.write_text(json.dumps(bad))
            try:mod.request_proof()
            except (ValueError,KeyError):pass
            else:raise AssertionError("untrusted completion accepted: "+str(mutate))
        file.write_text(json.dumps(event))
        with patch.object(mod.bridge,"original_zip",return_value=({**original,"publicReleaseAuthorized":True},"d"*64)):
            try:mod.request_proof()
            except ValueError:pass
            else:raise AssertionError("published source was accepted")
        with patch.object(mod.bridge,"get_json",side_effect=lambda url: {**source,"run_attempt":2} if url.endswith("/"+str(source_id)) else fake_get(url)):
            try:mod.request_proof()
            except ValueError:pass
            else:raise AssertionError("REST source attempt mismatch accepted")
        with patch.object(mod.bridge,"get_json",side_effect=lambda url: {**source,"updated_at":stamp(start-timedelta(hours=2))} if url.endswith("/"+str(source_id)) else fake_get(url)):
            try:mod.request_proof()
            except ValueError:pass
            else:raise AssertionError("stale completion accepted")
print("ISSUE311_R06_UNATTENDED_COMPLETED_EVENT_NEGATIVE_PASS_OFFLINE_ONLY")
