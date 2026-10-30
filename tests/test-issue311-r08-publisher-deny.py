#!/usr/bin/env python3
"""R08-02 App -> independent Publisher DENY exhaustive hostile fixtures.

This is OFFLINE source/actor/scope/policy denial, not a third real Sigstore or
an authorization to publish. The protected push job separately GETs originals.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "r08_app_publisher_deny",root/"scripts/issue311-r08-publisher-deny.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
central_sha="a"*40
local_sha="b"*40
names=sorted(m.APPROVED_17)
def fixture():
    central={"id":11,"run_attempt":1,"head_sha":central_sha,
             "path":m.CENTRAL_WORKFLOW,"event":"push","head_branch":"main",
             "actor":{"login":"ShutenOishi"},"status":"completed","conclusion":"success"}
    fleet={"id":22,"run_attempt":1,"head_sha":central_sha,
           "path":m.FLEET_WORKFLOW,"event":"workflow_run",
           "status":"completed","conclusion":"success"}
    local={"id":33,"run_attempt":1,"head_sha":local_sha,
           "path":m.LOCAL_WORKFLOW,"event":"workflow_dispatch",
           "status":"completed","conclusion":"success",
           "actor":{"login":m.BOT,"id":m.BOT_ID},
           "triggering_actor":{"login":m.BOT}}
    request={"schemaVersion":1,"kind":"pgextwin-execution-request",
             "mode":"PREPARE","allowFutureUpdates":False,
             "approval":{"publicReleaseAuthorized":False,"publicationGrants":[]},
             "source":{"centralMainSha":"f"*40},
             "targets":[{"repo":name,"mainSha":local_sha if name==m.REPOSITORY else "c"*40}
                        for name in names]}
    state={"schemaVersion":1,"revision":2,"terminal":"NO_UPDATE",
           "eventTransport":"workflow_run.completed",
           "sourceRun":{"id":22,"attempt":1},"sourceHeadSha":central_sha,
           "publisherAuthorized":False,"writeOutcomeUnknown":False,
           "targets":{name:"SUCCESS" for name in names}}
    jobs=[{"name":name,"status":"completed","conclusion":"success"} for name in m.R08_JOBS]
    jobs +=[{"name":f"R07-01 authenticated App original Windows PG14-18 / PostgreSQL {n} / Windows x64","status":"completed","conclusion":"success"} for n in range(14,19)]
    artifacts=[{"id":i+100,"name":name,"expired":False,"digest":"sha256:"+"d"*64}
               for i,name in enumerate(sorted(m.R08_ARTIFACTS))]
    return {"local":local,"central":central,"fleet":fleet,
            "local_branch":{"protected":True,"name":"main","commit":{"sha":local_sha}},
            "state":state,"state_blob":"e"*40,
            "request":request,"request_raw_sha":"f"*64,
            "jobs":{"jobs":jobs,"total_count":len(jobs)},
            "artifacts":{"artifacts":artifacts,"total_count":len(artifacts)},
            "boundary":{"schemaVersion":1,"mode":"ENFORCE",
                        "publisherAppId":m.PUBLISHER_APP_ID,
                        "publisherInstallationId":m.PUBLISHER_INSTALLATION_ID,
                        "signerAppId":m.SIGNER_APP_ID},
            "central_run_id":11,"fleet_run_id":22,"local_run_id":33,
            "central_sha":central_sha,"local_sha":local_sha,
            "source_kind":m.SOURCE}

positive=fixture()
good=m.assess(**deepcopy(positive))
assert good["decision"]=="PUBLISH_DENY"
assert good["publisherAppSeparated"] is True
assert good["publisherWriteAuthorized"] is False
assert good["publisherTokenRequested"] is False
assert good["releasePostAttempted"] is False
assert good["publicationAuthorized"] is False
assert good["cryptographicVerificationRepeatedByThisJob"] is False
count=0

def reject(path,value):
    global count
    d=deepcopy(positive)
    if len(path)==1: d[path[0]]=value
    elif len(path)==2:d[path[0]][path[1]]=value
    else: d[path[0]][path[1]][path[2]]=value
    try:m.assess(**d)
    except m.Denied:count+=1;return
    raise AssertionError("unsafe R08 Publisher admission accepted "+str(path))

for path,value in [
    (("source_kind",),"MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"),
    (("source_kind",),"UNTRUSTED_WORKFLOW_DISPATCH"),
    (("central_sha",),"bad"),
    (("central","event"),"schedule"),
    (("central","run_attempt"),2),
    (("central","conclusion"),"failure"),
    (("central","head_sha"),"0"*40),
    (("central","path"),".github/workflows/other.yml"),
    (("fleet","event"),"push"),
    (("fleet","run_attempt"),2),
    (("fleet","conclusion"),"failure"),
    (("fleet","head_sha"),"0"*40),
    (("local","event"),"schedule"),
    (("local","run_attempt"),2),
    (("local","actor"),{"login":"ShutenOishi","id":1}),
    (("local","actor"),{"login":m.BOT,"id":1}),
    (("local","triggering_actor"),{"login":"ShutenOishi"}),
    (("local","head_sha"),"1"*40),
    (("local","conclusion"),"failure"),
    (("local_branch","protected"),False),
    (("local_branch","commit"),{"sha":"0"*40}),
    (("state","revision"),1),
    (("state","terminal"),"QUARANTINED"),
    (("state","sourceHeadSha"),"0"*40),
    (("state","sourceRun"),{"id":111,"attempt":1}),
    (("state","publisherAuthorized"),True),
    (("state","writeOutcomeUnknown"),True),
    (("state","eventTransport"),"FORGED_EVENT"),
    (("state","targets"),{**positive["state"]["targets"],"pgextwin/orafce":"QUARANTINED"}),
    (("request","mode"),"PUBLISH_ELIGIBLE"),
    (("request","allowFutureUpdates"),True),
    (("request","approval"),{"publicReleaseAuthorized":True,"publicationGrants":[]}),
    (("request","approval"),{"publicReleaseAuthorized":False,"publicationGrants":[{"repo":m.REPOSITORY}]}),
    (("request","source"),{"centralMainSha":central_sha}),
    (("request","targets"),positive["request"]["targets"][:-1]),
    (("boundary","publisherAppId"),m.APP_ID),
    (("boundary","signerAppId"),m.PUBLISHER_APP_ID),
    (("boundary","mode"),"DENY"),
    (("artifacts","total_count"),9),
    (("jobs","total_count"),99),
]:
    reject(path,value)
# Exact supported source is nonpublishable even when a reported original
# signed ZIP looks clean, and any missing PG/SPDX/Grype/audit is never admitted.
for key in ("issue311-r08-signed-second-nonpublishing","orafce-pg16-windows-x64"):
    d=deepcopy(positive)
    d["artifacts"]["artifacts"]=[a for a in d["artifacts"]["artifacts"] if a["name"]!=key]
    d["artifacts"]["total_count"]=len(d["artifacts"]["artifacts"])
    try:m.assess(**d)
    except m.Denied:count+=1
    else:raise AssertionError("missing original signed ZIP/audit admitted")
assert count>=40
script=(root/"scripts/issue311-r08-publisher-deny.py").read_text()
for token in ('"--method","GET"','publisherTokenRequested','releasePostAttempted',
              'APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY',
              'APPROVED_17','writeOutcomeUnknown'):
    assert token in script,token
for forbidden in ('gh release create','gh release upload','git push','POST /repos/','contents: write'):
    assert forbidden not in script,forbidden
print(f"ISSUE311_R08_APP_PUBLISHER_DENY_SCOPE_NEGATIVE_PASS cases={count}; NO_CREDENTIALS_NO_RELEASE")
