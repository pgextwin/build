#!/usr/bin/env python3
"""R09 private evidence key and Catalog/CLI/EN/JA hostile tests (NO PUBLICATION)."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r09",root/"scripts/issue311-r09-private-chain.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source={
 "schemaVersion":1,"status":"APP_R08_SIGNED_SOURCE_PUBLISH_DENY_ADMISSION_ONLY",
 "sourceKind":m.SOURCE_KIND,"decision":"PUBLISH_DENY",
 "requestRawSha256":m.REQUEST_SHA,"stateGitBlobSha":m.STATE_BLOB,
 "centralRunId":41073991273,"appFleetRunId":41074138918,
 "signedLocalRunId":41074341848,"originalAppId":5534389,
 "signerAppId":15368,"publisherAppId":5451798,
 "publisherAppSeparated":True}
for name in ("publisherSourceKindAuthorized","publisherTokenRequested",
 "publisherWriteAuthorized","publicationAuthorized","publishableReceipt",
 "writeOutcomeUnknown","runtimeEnabled","releasePostAttempted"):
    source[name]=False
catalog={"sha":"a"*40,"protected":True}
website={"sha":"b"*40,"protected":True}
def payload(x):return (json.dumps(x)+"\n").encode()
files={}
for path in m.CATALOG_FILES:files["catalog",path]=b"source\n"
for path in m.WEBSITE_FILES:files["website",path]=b"source\n"
files["catalog","index.json"]=payload({"schemaVersion":2,"extensions":
    sorted(["hypopg","orafce","pg_bigm","pg_cron","pg_hint_plan","pgaudit","set_user",
         "pg_repack","pg_ivm","pg_qualstats","plpgsql_check","wal2json",
         "pg_partman","pg_stat_monitor","pgtap","pg_variables","pg_store_plans"])})
files["catalog","extensions/orafce.json"]=payload({
    "schemaVersion":2,"name":"orafce","repository":"pgextwin/orafce",
    "latest":{"releaseTag":"v4.16.13-windows.1","publishedAt":"2026-10-10T15:49:07Z"},
    "postgresql":{str(i):{"available":True} for i in range(14,19)}})
files["catalog","config/cli-feed-majors.json"]=payload({
    "schemaVersion":1,"postgresqlMajors":[str(i) for i in range(14,19)]})
files["catalog","scripts/cli_signed_feed.py"]=b"MAJORS; def build_feed(a): source_bytes(a)\n"
files["catalog","dotnet/src/PgExtWin.Cli/Program.cs"]=b"class Program\n"
files["catalog","dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs"]=b"class SignedPublicCatalogFeed\n"
files["website","app.js"]=b"https://raw.githubusercontent.com/pgextwin/catalog/main"
files["website","catalog-view.js"]=b"validateCatalogRecord"
for lang in ("en","ja"):
    files["website",f"{lang}/index.html"]=f'<html lang="{lang}">CLI</html>'.encode()
    files["website",f"{lang}/cli.html"]=f'<html lang="{lang}">pgextwin.exe</html>'.encode()
files["website","scripts/published-cli-contract.mjs"]=b"verifyPublishedCli"
release={"tag_name":"v4.16.13-windows.1","published_at":"2026-10-10T15:49:07Z",
         "draft":False,"prerelease":False}
report=m.assess(source,catalog,website,files,release)
assert report["decision"]=="PUBLISH_DENY"
assert report["catalogShadowProposal"]["proposedPublicRecord"] is False
assert report["publishedReleaseClaim"] is False
assert report["newPublicFeedClaim"] is False
assert report["websiteEnglishSourceChecked"] and report["websiteJapaneseSourceChecked"]
count=0
def reject(src=None,c=None,w=None,f=None,r=None):
    global count
    try:m.assess(src or source,c or catalog,w or website,f or files,r or release)
    except m.Denied:count+=1
    else:raise AssertionError("unsafe source/private Catalog chain accepted")
for name,bad in (("sourceKind","schedule"),("decision","ALLOW"),
                 ("requestRawSha256","0"*64),("stateGitBlobSha","0"*40),
                 ("publicationAuthorized",True),("publisherTokenRequested",True),
                 ("releasePostAttempted",True)):
    x=deepcopy(source);x[name]=bad;reject(src=x)
x=deepcopy(catalog);x["protected"]=False;reject(c=x)
x=deepcopy(website);x["sha"]="broken";reject(w=x)
x=deepcopy(files);x["catalog","index.json"]=payload({"schemaVersion":2,"extensions":["orafce"]});reject(f=x)
x=deepcopy(files);x.pop(("website","ja/cli.html"));reject(f=x)
x=deepcopy(files);x["website","en/cli.html"]=b"invalid";reject(f=x)
x=deepcopy(release);x["draft"]=True;reject(r=x)
print("ISSUE311_R09_NONPUBLISHING_CHAIN_HOSTILE_PASS cases="+str(count))
