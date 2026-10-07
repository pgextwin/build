#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path

def fmt(v):
    if v is None:return "none"
    if isinstance(v,dict):return "`"+json.dumps(v,sort_keys=True,separators=(",",":"))+"`"
    return str(v)
def main():
    p=argparse.ArgumentParser();p.add_argument("--result",required=True);p.add_argument("--reconcile");p.add_argument("--summary",required=True);a=p.parse_args();r=json.loads(Path(a.result).read_text());d=json.loads(Path(a.reconcile).read_text()) if a.reconcile and Path(a.reconcile).exists() else {"action":"not-run"}
    lines=["## pgextwin update watch","",f"- Kind: `{r.get('kind','unknown')}`",f"- Extension: `{r.get('extension','PostgreSQL')}`",f"- Configured upstream: `{r.get('repository','postgresql.org')}`",f"- Current: {fmt(r.get('current'))}",f"- Detected candidate: {fmt(r.get('candidate') or r.get('newMajors') or r.get('drift'))}",f"- Final status: **{r.get('status','indeterminate')}**",f"- Issue action: **{d.get('action','not-run')}**"]
    if r.get("prerelease"):lines.append(f"- Pre-release informational state: {fmt(r['prerelease'])}")
    if r.get("error"):lines.append(f"- Operational error: `{r['error']}`")
    with open(a.summary,"a",encoding="utf-8") as f:f.write("\n".join(lines)+"\n")
if __name__=="__main__":main()
