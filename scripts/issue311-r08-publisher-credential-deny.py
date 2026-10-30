#!/usr/bin/env python3
"""Credentialed, separate Publisher App identity DENY for a real R08 PREPARE.

This protected-main Environment job reads only /app and /app/installations.
It NEVER requests an installation token or attempts any Git object/tag/Release
write. Its purpose is to prove a real independent Publisher actor will reject
a nonpublishing signed App source before any write credential is issued.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("r08_publisher_app_probe",ROOT/"probe-publisher-app.py")
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
scope=probe.scope_token

class Denied(ValueError):
    pass

def require(ok,why):
    if not ok:
        raise Denied(why)

def evaluate(evidence, *, app_id, installation_id):
    require(type(evidence) is dict, "missing read-only original admission")
    require(evidence.get("schemaVersion")==1
        and evidence.get("status")=="APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY"
        and evidence.get("decision")=="PUBLISH_DENY"
        and evidence.get("sourceKind")=="APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY"
        and evidence.get("centralRunId")==41073991273
        and evidence.get("appFleetRunId")==41074138918
        and evidence.get("signedLocalRunId")==41074341848
        and evidence.get("originalAppId")==5534389
        and evidence.get("originalAppBotId")==350058024
        and evidence.get("signerAppId")==15368
        and evidence.get("publisherAppId")==5451798
        and evidence.get("publisherAppSeparated") is True
        and evidence.get("realIndependentSourceMetadataGets") is True
        and evidence.get("cryptographicVerificationRepeatedByThisJob") is False
        and evidence.get("publisherSourceKindAuthorized") is False
        and evidence.get("publisherTokenRequested") is False
        and evidence.get("publisherWriteAuthorized") is False
        and evidence.get("publicationAuthorized") is False
        and evidence.get("publishableReceipt") is False
        and evidence.get("writeOutcomeUnknown") is False
        and evidence.get("runtimeEnabled") is False
        and evidence.get("releasePostAttempted") is False
        and re.fullmatch("[a-f0-9]{40}",str(evidence.get("stateGitBlobSha","")))
        and re.fullmatch("[a-f0-9]{64}",str(evidence.get("requestRawSha256",""))),
        "source is not exact unauthorised, nonpublishing original")
    require(type(app_id) is int and app_id==5451798 and app_id!=15368
        and app_id!=5534389 and type(installation_id) is int
        and installation_id==174720074,
        "Publisher identity/installation mismatched")
    return {
      "schemaVersion":1,
      "status":"R08_ACTUAL_CREDENTIALED_SEPARATE_PUBLISHER_APP_DENIED",
      "sourceKind":evidence["sourceKind"],
      "centralRunId":evidence["centralRunId"],
      "appFleetRunId":evidence["appFleetRunId"],
      "signedLocalRunId":evidence["signedLocalRunId"],
      "requestRawSha256":evidence["requestRawSha256"],
      "stateGitBlobSha":evidence["stateGitBlobSha"],
      "authenticatedPublisherAppId":app_id,
      "authenticatedPublisherInstallationId":installation_id,
      "prepareAppId":5534389,"signerAppId":15368,
      "publisherTokenRequested":False,
      "publisherWriteAuthorized":False,
      "releasePostAttempted":False,
      "tagOrRefWriteAttempted":False,
      "publicationAuthorized":False,
      "runtimeEnabled":False,
      "decision":"PUBLISH_DENY",
      "verification":"LIVE_PUBLISHER_JWT_GET_APP_AND_INSTALLATION_ONLY",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    try:
        require(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
          and os.environ.get("GITHUB_REF")=="refs/heads/main"
          and os.environ.get("GITHUB_EVENT_NAME")=="push"
          and os.environ.get("GITHUB_RUN_ATTEMPT")=="1"
          and os.environ.get("GITHUB_ACTOR")=="ShutenOishi",
          "not authentic protected original postmerge")
        app=int(os.environ["PUBLISHER_APP_ID"])
        installation=int(os.environ["PUBLISHER_INSTALLATION_ID"])
        raw=Path(a.source).read_bytes()
        require(0<len(raw)<16384 and Path(a.source).is_file(),
                "missing or oversized original input")
        # All nonpublishing gates must pass BEFORE even opening the App key.
        result=evaluate(json.loads(raw),app_id=app,installation_id=installation)
        key=os.environ.pop("PUBLISHER_PRIVATE_KEY",None)
        require(type(key) is str and bool(key),"separate Publisher secret unavailable")
        # JWT issuer performs ONLY authenticated GET /app and /app/installations/id;
        # do not mint a write-capable installation token for this denied request.
        scope.issuer(probe.api,probe.jwt,key,app,installation)
        Path(a.output).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n","utf-8")
        print("REAL_PUBLISHER_APP_IDENTITY_VERIFIED; NO_TOKEN; PUBLISH_DENY; NO_RELEASE")
        return 0
    except Exception as exc:
        # Never echo secrets, API payloads or private exception messages.
        print("R08_CREDENTIALLED_PUBLISHER_DENY ("+type(exc).__name__+"); NO_RELEASE",
              file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
