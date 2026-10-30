#!/usr/bin/env python3
"""R09-01 live nonpublishing evidence join, never a Catalog/Release publisher.

Uses protected read-only GitHub GET and immutable original R08 Publisher DENY.
Current already-published Catalog/CLI/EN/JA paths are inspected; no unpublished
PREPARE is promoted to a public Release, feed, Catalog record or download URL.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE_KIND="APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY"
REQUEST_SHA="174b48df34a82ef147b599b1b33a86964990ea6ee4fb6932b365e338dd23410f"
STATE_BLOB="e588b93f5f607dc05e240e07c3351d75e1f34727"
CATALOG_FILES={
 "index.json",
 "extensions/orafce.json",
 "config/cli-feed-majors.json",
 "scripts/cli_signed_feed.py",
 "dotnet/src/PgExtWin.Cli/Program.cs",
 "dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs",
}
WEBSITE_FILES={"app.js","catalog-view.js",
               "en/index.html","ja/index.html","en/cli.html","ja/cli.html",
               "scripts/published-cli-contract.mjs"}
SHA40=re.compile("[a-f0-9]{40}\\Z")
SHA64=re.compile("[a-f0-9]{64}\\Z")
class Denied(ValueError):pass
def need(ok,reason):
    if not ok:raise Denied(reason)
def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,"duplicated JSON evidence key")
        result[k]=v
    return result
def parse(raw):
    return json.loads(raw,object_pairs_hook=unique)
def gitblob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def safe_source(source):
    need(type(source) is dict and source.get("schemaVersion")==1
         and source.get("status")=="APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY"
         and source.get("sourceKind")==SOURCE_KIND
         and source.get("decision")=="PUBLISH_DENY"
         and source.get("requestRawSha256")==REQUEST_SHA
         and source.get("stateGitBlobSha")==STATE_BLOB
         and source.get("centralRunId")==41073991273
         and source.get("appFleetRunId")==41074138918
         and source.get("signedLocalRunId")==41074341848
         and source.get("originalAppId")==5534389
         and source.get("signerAppId")==15368
         and source.get("publisherAppId")==5451798
         and source.get("publisherAppSeparated") is True
         and all(source.get(k) is False for k in (
           "publisherSourceKindAuthorized","publisherTokenRequested",
           "publisherWriteAuthorized","publicationAuthorized","publishableReceipt",
           "writeOutcomeUnknown","runtimeEnabled","releasePostAttempted")),
         "R08 original source not exact, signed, separate and denied")
def assess(source, catalog_branch, website_branch, files, public_release):
    safe_source(source)
    need(type(catalog_branch) is dict and type(website_branch) is dict
         and catalog_branch.get("protected") is True
         and website_branch.get("protected") is True
         and SHA40.fullmatch(str(catalog_branch.get("sha","")))
         and SHA40.fullmatch(str(website_branch.get("sha",""))),
         "Catalog or Website current main not protected/exact")
    need(type(files) is dict and set(files)==
         {("catalog",p) for p in CATALOG_FILES} |
         {("website",p) for p in WEBSITE_FILES},
         "Catalog/CLI/feed/EN/JA source set missing or changed")
    need(all(type(b) is bytes and 0<len(b)<2_000_000 for b in files.values()),
         "empty or oversized original source")
    catalog=parse(files["catalog","index.json"])
    record=parse(files["catalog","extensions/orafce.json"])
    matrix=parse(files["catalog","config/cli-feed-majors.json"])
    need(catalog.get("schemaVersion")==2
         and type(catalog.get("extensions")) is list
         and len(catalog["extensions"])==17
         and catalog["extensions"]==sorted(set(catalog["extensions"]))
         and "orafce" in catalog["extensions"],
         "Catalog protected cohort is not 17")
    need(record.get("schemaVersion")==2
         and record.get("name")=="orafce"
         and record.get("repository")=="pgextwin/orafce"
         and type(record.get("latest")) is dict
         and re.fullmatch(r"v[A-Za-z0-9][A-Za-z0-9._-]+-windows\.[1-9][0-9]*",
                          str(record["latest"].get("releaseTag","")))
         and record["latest"].get("releaseTag")=="v4.16.13-windows.1"
         and record["latest"].get("publishedAt")=="2026-10-10T15:49:07Z",
         "this dry-run must not replace historical published Catalog release")
    need(matrix=={"schemaVersion":1,
          "postgresqlMajors":["14","15","16","17","18"]}
         and set(record.get("postgresql",{}))==set(matrix["postgresqlMajors"]),
         "signed public Catalog feed five-major schema changed")
    need(type(public_release) is dict
         and public_release.get("tag_name")==record["latest"]["releaseTag"]
         and public_release.get("published_at")==record["latest"]["publishedAt"]
         and public_release.get("draft") is False
         and public_release.get("prerelease") is False,
         "current historical public release not independently authenticated")
    cat_feed=files["catalog","scripts/cli_signed_feed.py"].decode()
    cli=files["catalog","dotnet/src/PgExtWin.Cli/Program.cs"].decode()
    signed_feed=files["catalog","dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs"].decode()
    need("def build_feed(" in cat_feed and "source_bytes(" in cat_feed
         and "MAJORS" in cat_feed and "class Program" in cli or
         ("def build_feed(" in cat_feed and "source_bytes(" in cat_feed
         and "MAJORS" in cat_feed and "download-all" in cli),
         "existing public CLI/feed source contract missing")
    need("class SignedPublicCatalogFeed" in signed_feed or
         "SignedPublicCatalogFeed" in signed_feed,
         "signed feed consumer source missing")
    app=files["website","app.js"].decode()
    view=files["website","catalog-view.js"].decode()
    need("https://raw.githubusercontent.com/pgextwin/catalog/main" in app
         and "validateCatalogRecord" in view,
         "website does not point to protected public Catalog")
    for lang in ("en","ja"):
        home=files["website",f"{lang}/index.html"].decode()
        page=files["website",f"{lang}/cli.html"].decode()
        need(f'<html lang="{lang}">' in home and
             f'<html lang="{lang}">' in page
             and "pgextwin.exe" in page
             and "cli" in home.lower(),
             "bilingual site/CLI published source contract absent")
    need("verifyPublishedCli" in
         files["website","scripts/published-cli-contract.mjs"].decode(),
         "bilingual CLI published contract missing")
    digests={repo+"/"+p:hashlib.sha256(data).hexdigest()
       for (repo,p),data in sorted(files.items())}
    return {
      "schemaVersion":1,"status":"R09_01_NONPUBLISHING_EVIDENCE_KEY_DRY_RUN_ONLY",
      "sourceKind":SOURCE_KIND,"sourceRequestSha256":REQUEST_SHA,
      "originalCentralRunId":41073991273,
      "originalFleetRunId":41074138918,
      "originalSignedRunId":41074341848,
      "originalStateBlobSha":STATE_BLOB,
      "catalogMainSha":catalog_branch["sha"],
      "websiteMainSha":website_branch["sha"],
      "extensionCount":17,
      "postgresqlMajors":matrix["postgresqlMajors"],
      "historicalPublicCatalogReleaseTag":record["latest"]["releaseTag"],
      "catalogShadowProposal":{
        "schemaVersion":1,"extension":"orafce",
        "requestRawSha256":REQUEST_SHA,
        "sourceStateBlobSha":STATE_BLOB,
        "status":"BLOCKED_PREPARE_NOT_A_RELEASE",
        "proposedPublicRecord":False,
        "recordMutationAuthorized":False,
        "catalogPRCreatedByThisJob":False},
      "cliFeedReadOnlySourceChecked":True,
      "websiteEnglishSourceChecked":True,
      "websiteJapaneseSourceChecked":True,
      "sourceSha256":digests,
      "publishedReleaseClaim":False,
      "newPublicFeedClaim":False,
      "publisherTokenRequested":False,
      "catalogWriteAttempted":False,
      "websiteWriteAttempted":False,
      "releasePostAttempted":False,
      "runtimeEnabled":False,"decision":"PUBLISH_DENY",
      "next":"Native protected Catalog shadow PR and real CLI/feed EN/JA preview validation before R09-01 acceptance",
    }
def call(repo,route):
    need(os.environ.get("GH_TOKEN"),"read-only token required")
    need(repo in ("pgextwin/catalog","pgextwin/website","pgextwin/orafce"),
         "unknown read-only repository")
    full="repos/"+repo+"/"+route
    need(route=="branches/main"
         or repo=="pgextwin/orafce" and route=="releases/tags/v4.16.13-windows.1"
         or re.fullmatch(r"contents/.+\?ref=[a-f0-9]{40}",route),
         "unapproved read-only GET route")
    cp=subprocess.run(["gh","api","--method","GET",full],
                      capture_output=True,text=True,timeout=45,check=False)
    need(cp.returncode==0 and 0<len(cp.stdout)<4_000_000,
         "authenticated GitHub read-only GET failed")
    return parse(cp.stdout)
def branch(repo):
    b=call(repo,"branches/main")
    need(b.get("name")=="main" and b.get("protected") is True
         and SHA40.fullmatch(str(b.get("commit",{}).get("sha",""))),
         "main unprotected")
    return {"sha":b["commit"]["sha"],"protected":True}
def original_bytes(repo,path,sha):
    f=call("pgextwin/"+repo,f"contents/{path}?ref={sha}")
    need(f.get("encoding")=="base64" and type(f.get("content")) is str
         and f.get("type")=="file",
         "Git contents original not a file")
    raw=base64.b64decode(f["content"].replace("\n",""),validate=True)
    need(gitblob(raw)==f.get("sha"),"Git blob mismatches independent bytes")
    return raw
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    try:
        need(os.environ.get("GITHUB_REPOSITORY")=="pgextwin/build"
             and os.environ.get("GITHUB_REF")=="refs/heads/main"
             and os.environ.get("GITHUB_EVENT_NAME")=="push"
             and os.environ.get("GITHUB_RUN_ATTEMPT")=="1"
             and os.environ.get("GITHUB_ACTOR")=="ShutenOishi",
             "not original exact protected read-only proof")
        root=call("pgextwin/catalog","branches/main")
        web=call("pgextwin/website","branches/main")
        need(root.get("protected") is True and web.get("protected") is True,
             "source refs not protected")
        cb=branch("pgextwin/catalog");wb=branch("pgextwin/website")
        need(root["commit"]["sha"]==cb["sha"] and web["commit"]["sha"]==wb["sha"],
             "branch changed during evidence read")
        source=parse(Path(a.source).read_text("utf-8"))
        safe_source(source)
        files={}
        for repo,paths,b in (("catalog",CATALOG_FILES,cb),
                             ("website",WEBSITE_FILES,wb)):
            for path in sorted(paths):
                files[repo,path]=original_bytes(repo,path,b["sha"])
        release=call("pgextwin/orafce","releases/tags/v4.16.13-windows.1")
        report=assess(source,cb,wb,files,release)
        Path(a.output).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n","utf-8")
        print("R09_01_LIVE_READ_ONLY_CATALOG_CLI_FEED_EN_JA_SHADOW; NO_PUBLICATION")
        return 0
    except Exception as exc:
        print("R09_01_PRIVATE_JOIN_DENY ("+type(exc).__name__+"); NO_PUBLICATION",
              file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
