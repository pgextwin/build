#!/usr/bin/env python3
"""R06 real 17 App CAS nonpublishing negative guard tests (OFFLINE ONLY)."""
import ast
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch
root=Path(__file__).resolve().parents[1]
p=root/"scripts/issue311-r06-app-fleet-cas-terminal.py"
source=p.read_text(encoding="utf-8")
compile(source,str(p),"exec")
assert "r-20261030-r06appcas17terminal001" in source
assert "r-20261030-r06preparecoordfleet03" in source
assert "issue311-state" not in source  # only approved CAS adapter owns state path
assert "writer.mint_token" in source and "writer.revoke_and_prove_401" in source
assert "childlib.artifact(" in source and "bridge.original_zip(" in source
assert "max_events=100" in source and "BOUNDED_WATCHDOG" in source
assert "fakeSourceKind" in source and "afterTerminalReplay" in source
assert 'state["publisherAuthorized"] is False' in source
for forbidden in ("PUBLISH_ELIGIBLE","actions/workflows/issue311-fleet-local-prepare.yml/dispatches","/releases"):
    assert forbidden not in source
spec=importlib.util.spec_from_file_location("r06app17cas",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
central={"sourceRunId":41000527397,"sourceHeadSha":"380e3054e2ccd8568e124339963e2b0082d60841",
 "sourceZipSha256":"05aaabfb7be2ec7ea1d38819ce73a71ca0678504ec4e21f6f8eca4c402fc26ab"}
r={
 "schemaVersion":1,"sourceKind":mod.LOCAL_SOURCE_KIND,"result":"NO_UPDATE",
 "requestId":"r-20261030-r06coordlocalpilot01","actualBotLogin":mod.BOT,
 "actualBotUserId":mod.BOT_ID,"localOriginalEvent":"workflow_dispatch",
 "localRunId":41000702019,"localRunAttempt":1,
 "localProtectedMainSha":"9df4ed7cde72f103d4e412cfaa7304e7a8db8af2",
 "centralSourceRunId":41000527397,"centralSourceHeadSha":central["sourceHeadSha"],
 "centralSourceRequestId":mod.CENTRAL_REQUEST,
 "centralOriginalOuterZipSha256Verified":central["sourceZipSha256"],
 "publicationAuthorized":False,"publicReleaseAuthorized":False,"candidateCreated":False,
 "genuineSchedule":False,"originalScanReexecuted":False,
 "publisherSourceKindAuthorized":False,"runtimeEnabled":False
}
item={"localRunId":41000702019}
assert mod.strict_child_receipt(r,item,central,r["localProtectedMainSha"]) is True
for change in [
 {"sourceKind":"FAKE_SCHEDULE"},
 {"localRunAttempt":2},
 {"actualBotUserId":0},
 {"candidateCreated":True},
 {"publisherSourceKindAuthorized":True},
 {"publicReleaseAuthorized":True},
 {"runtimeEnabled":True},
 {"centralSourceRunId":0},
 {"localOriginalEvent":"push"},
]:
 d={**r,**change}
 try:mod.strict_child_receipt(d,item,central,r["localProtectedMainSha"])
 except ValueError as e:assert "R06_APP_CAS_DENY" in str(e)
 else:raise AssertionError("unsafe original receipt accepted "+str(change))
with patch.dict(os.environ,{
 "GITHUB_REPOSITORY":"pgextwin/build",
 "GITHUB_EVENT_NAME":"pull_request",
 "GITHUB_REF":"refs/heads/main",
 "GITHUB_ACTOR":"ShutenOishi",
 "GITHUB_WORKFLOW":mod.WORKFLOW,
 "GITHUB_RUN_ATTEMPT":"1"},clear=True):
 try:mod.request_proof()
 except ValueError as e:assert "R06_APP_CAS_DENY" in str(e)
 else:raise AssertionError("untrusted PR accepted as state writer")
state=mod.life.new(mod.REQ,"a"*64,"b"*40,["pgextwin/orafce"],"2026-10-30T18:00:00Z")
bound=mod.life.bind_source(state,0,"real-source",run_id=41000595525,attempt=1,head_sha="b"*40)
assert bound["revision"]==1 and bound["sourceRun"]["id"]==41000595525
def terminal(d):
 d["targets"]={"pgextwin/orafce":"SUCCESS"}
 d["terminal"]="NO_UPDATE"
 d["completionRun"]={"id":41000999999,"attempt":1}
 d["eventTransport"]="BOUNDED_WATCHDOG"
finished=mod.life._apply(bound,1,"real-original-terminal",{"kind":"PREPARE"},terminal)
proof=mod.terminal_replay_denials(
 finished,{**central,"targetMainSha":{"pgextwin/orafce":"a"*40}},
 {"pgextwin/orafce":{"runId":41000702019}})
assert len(proof)==3 and set(proof.values())=={"DENY"}
print("ISSUE311_R06_APP_FLEET_ORIGINAL_CAS_NEGATIVE_PASS_OFFLINE_ONLY")
