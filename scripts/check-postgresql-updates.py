#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, re, sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from update_watch_lib import WatchError, utc_now

VERSIONING_URL="https://www.postgresql.org/support/versioning/"
BETA_URL="https://www.postgresql.org/developer/beta/"

class TableParser(HTMLParser):
    def __init__(self): super().__init__(); self.in_cell=False; self.cell=[]; self.row=[]; self.rows=[]
    def handle_starttag(self, tag, attrs):
        if tag=="tr": self.row=[]
        if tag in {"td","th"}: self.in_cell=True; self.cell=[]
    def handle_data(self,data):
        if self.in_cell: self.cell.append(data)
    def handle_endtag(self,tag):
        if tag in {"td","th"} and self.in_cell:
            self.row.append(" ".join("".join(self.cell).split())); self.in_cell=False
        if tag=="tr" and self.row: self.rows.append(self.row)

def fetch_text(url: str) -> str:
    try:
        with urlopen(Request(url,headers={"User-Agent":"pgextwin-update-watch/1"}),timeout=30) as r: return r.read().decode("utf-8")
    except (HTTPError,URLError,TimeoutError,OSError) as exc: raise WatchError(f"official PostgreSQL query failed: {exc}") from exc

def parse_versioning(html: str) -> dict[int,dict]:
    p=TableParser(); p.feed(html); result={}
    for row in p.rows:
        if len(row)<5 or not re.fullmatch(r"\d+",row[0]): continue
        major=int(row[0]); current=row[1]; eol=row[-1]
        if not re.fullmatch(rf"{major}\.\d+",current): continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}",eol): continue
        result[major]={"major":major,"currentMinor":current,"eol":eol}
    if not result: raise WatchError("could not parse supported PostgreSQL versions from official Versioning Policy")
    return result

def parse_prerelease(html: str) -> dict | None:
    text=" ".join(re.sub(r"<[^>]+>"," ",html).split())
    m=re.search(r"PostgreSQL\s+(\d+)\s+(Beta\s*\d+|RC\s*\d+)",text,re.I)
    if not m: return None
    return {"major":int(m.group(1)),"label":re.sub(r"\s+","",m.group(2)).replace("beta","Beta").replace("rc","RC")}

def detect_postgresql(metadata: dict, version_html: str, beta_html: str, detected_at: str, watcher_repo: str, watcher_sha: str) -> dict:
    official=parse_versioning(version_html); configured={int(x["major"]):x for x in metadata["postgresql"]}
    drift=[]
    for major,c in configured.items():
        if major not in official: continue
        o=official[major]
        if c.get("minor")!=o["currentMinor"] or c.get("eol")!=o["eol"]:
            drift.append({"major":major,"currentMinor":c.get("minor"),"officialMinor":o["currentMinor"],"currentEol":c.get("eol"),"officialEol":o["eol"]})
    new=[{"major":m,"officialMinor":o["currentMinor"],"officialEol":o["eol"]} for m,o in official.items() if m not in configured]
    pre=parse_prerelease(beta_html)
    return {"schemaVersion":1,"kind":"postgresql","status":"update-available" if drift or new else "up-to-date","drift":drift,"newMajors":sorted(new,key=lambda x:x["major"]),"prerelease":pre,"detectedAt":detected_at,"watcher":{"repository":watcher_repo,"sha":watcher_sha},"sources":{"versioning":VERSIONING_URL,"beta":BETA_URL}}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--metadata",required=True); p.add_argument("--output",required=True); p.add_argument("--watcher-repository",required=True); p.add_argument("--watcher-sha",required=True); args=p.parse_args(); out=Path(args.output)
    try:
        md=json.loads(Path(args.metadata).read_text(encoding="utf-8")); result=detect_postgresql(md,fetch_text(VERSIONING_URL),fetch_text(BETA_URL),utc_now(),args.watcher_repository,args.watcher_sha); out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); print(json.dumps(result)); return 0
    except (WatchError,OSError,json.JSONDecodeError,KeyError,TypeError,ValueError) as exc:
        result={"schemaVersion":1,"kind":"postgresql","status":"indeterminate","error":str(exc),"detectedAt":utc_now(),"watcher":{"repository":args.watcher_repository,"sha":args.watcher_sha},"sources":{"versioning":VERSIONING_URL,"beta":BETA_URL}}; out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); print(f"PostgreSQL detection failed: {exc}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
