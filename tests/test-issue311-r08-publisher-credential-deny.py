#!/usr/bin/env python3
"""Pure hostile R08-02 credentialed Publisher admission tests (NO CREDENTIALS)."""
import importlib.util
from pathlib import Path
from copy import deepcopy
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r08_credential_policy",root/"scripts/issue311-r08-publisher-credential-deny.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
good={
 "schemaVersion":1,
 "status":"APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY",
 "decision":"PUBLISH_DENY",
 "sourceKind":"APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY",
 "centralRunId":41073991273,"appFleetRunId":41074138918,
 "signedLocalRunId":41074341848,
 "originalAppId":5534389,"originalAppBotId":350058024,
 "signerAppId":15368,"publisherAppId":5451798,
 "publisherAppSeparated":True,"realIndependentSourceMetadataGets":True,
 "cryptographicVerificationRepeatedByThisJob":False,
 "publisherSourceKindAuthorized":False,"publisherTokenRequested":False,
 "publisherWriteAuthorized":False,"publicationAuthorized":False,
 "publishableReceipt":False,"writeOutcomeUnknown":False,
 "runtimeEnabled":False,"releasePostAttempted":False,
 "stateGitBlobSha":"a"*40,"requestRawSha256":"b"*64}
v=m.evaluate(good,app_id=5451798,installation_id=174720074)
assert v["decision"]=="PUBLISH_DENY"
assert v["publisherTokenRequested"] is False
assert v["releasePostAttempted"] is False
count=0
for key,bad in (
 ("status","PUBLISH_AUTHORIZED"),("decision","ALLOW"),
 ("sourceKind","MERGED_BOT_SCHEDULED_REQUALIFICATION_SIGNED_BUILD"),
 ("centralRunId",41073991274),("appFleetRunId",41074138917),
 ("signedLocalRunId",41074341849),("originalAppId",15368),
 ("originalAppBotId",1),("signerAppId",5451798),
 ("publisherAppId",5534389),("publisherAppSeparated",False),
 ("realIndependentSourceMetadataGets",False),
 ("cryptographicVerificationRepeatedByThisJob",True),
 ("publisherSourceKindAuthorized",True),
 ("publisherTokenRequested",True),("publisherWriteAuthorized",True),
 ("publicationAuthorized",True),("publishableReceipt",True),
 ("writeOutcomeUnknown",True),("runtimeEnabled",True),
 ("releasePostAttempted",True),("stateGitBlobSha","bad"),
 ("requestRawSha256","bad")):
    candidate=deepcopy(good);candidate[key]=bad
    try:m.evaluate(candidate,app_id=5451798,installation_id=174720074)
    except m.Denied:count+=1
    else:raise AssertionError("unsafe Publisher evidence accepted: "+key)
for app,installation in ((5534389,174720074),(15368,174720074),(5451798,0),(5451798,174720075)):
    try:m.evaluate(good,app_id=app,installation_id=installation)
    except m.Denied:count+=1
    else:raise AssertionError("unsafe independent Publisher identity accepted")
print("ISSUE311_R08_CREDENTIALED_APP_FAIL_CLOSED_PASS; cases="+str(count)+"; NO_TOKEN_NO_RELEASE")
