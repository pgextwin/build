#!/usr/bin/env python3
from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile
path=Path(__file__).resolve().parents[1]/"scripts/verify-candidate.py"
spec=importlib.util.spec_from_file_location("verifier",path)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
ext={"name":"test","postgresql":{"majors":[14,15,19]},"upstream":{"repository":"example/test","ref":"v1.0","version":"1.0","commit":"b"*40}}
life={"schemaVersion":1,"postgresql":[{"major":14,"eol":"2026-11-12"},{"major":15,"eol":"2027-11-11"}]}
assert v.eligible(ext,life,date(2026,11,12))==[14,15]
assert v.eligible(ext,life,date(2026,11,13))==[15]
with tempfile.TemporaryDirectory() as d:
 root=Path(d)
 for major in [14,15]:
  folder=root/f"test-pg{major}-windows-x64";folder.mkdir()
  metadata={"buildMode":"normal","package":{"name":"test"},"postgresql":{"major":major},
   "upstream":{"repository":"example/test","ref":"v1.0","version":"1.0","commit":"b"*40},
   "source":{"packagingRepository":"pgextwin/test","packagingCommit":"a"*40},
   "workflowRun":{"id":100,"event":"workflow_dispatch","ref":"refs/heads/auto-candidate/"+"1"*20}}
  with ZipFile(folder/"output.zip","w") as z:z.writestr("PACKAGE-INFO.json",json.dumps(metadata))
  (folder/"output.spdx.json").write_text(json.dumps({"spdxVersion":"SPDX-2.3"}))
  (folder/"output.vulnerabilities.json").write_text(json.dumps({"matches":[]}))
 r=v.audit(root,ext,life,100,"a"*40,"auto-candidate/"+"1"*20,"success",date(2026,10,9))
 assert r["status"]=="VERIFIED" and len(r["majors"])==2
 assert v.audit(root,ext,life,100,"a"*40,"auto-candidate/"+"1"*20,"failed",date(2026,10,9))["status"]=="FAILED"
 (root/"test-pg14-windows-x64"/"output.spdx.json").unlink()
 assert v.audit(root,ext,life,100,"a"*40,"auto-candidate/"+"1"*20,"success",date(2026,10,9))["status"]=="FAILED"
# Candidate audit comments use the scoped issues REST endpoint instead of
# GraphQL addComment, which does not accept this workflow's issues:write token.
with tempfile.TemporaryDirectory() as d:
 report={"extension":"test","branch":"auto-candidate/"+"1"*20,
         "runId":100,"status":"VERIFIED","matrixResult":"success",
         "majors":[{"major":14,"status":"SUCCESS","sourceSha":"b"*40,
                    "zipSha256":"c"*64}]}
 calls=[]
 def fake_gh(*args):
  calls.append(args)
  if args[:2]==("pr","list"):
   return json.dumps([{"number":12,"body":"<!-- pgextwin-candidate:v1:"+"1"*20+" -->"}])
  return "{}"
 v.gh=fake_gh
 v.comment(report,"pgextwin/test",Path(d)/"candidate-comment.md")
 assert calls[1][0:3]==("api","--method","POST")
 assert calls[1][3]=="repos/pgextwin/test/issues/12/comments"
 assert calls[1][4]=="-f" and calls[1][5].startswith("body=<!-- pgextwin-candidate-run:100 -->")

 assert Path(d,"candidate-comment.md").is_file()
 # Only the known comment-only 403 is nonfatal. It must remain visible and
 # must never turn a FAILED audit into a VERIFIED artifact.
 def denied_403(*args):
  if args[:2]==("pr","list"):
   return json.dumps([{"number":12,"body":"<!-- pgextwin-candidate:v1:"+"1"*20+" -->"}])
  raise ValueError("GitHub CLI call failed: gh: Resource not accessible by integration (HTTP 403)")
 v.gh=denied_403
 assert v.comment(report,"pgextwin/test",Path(d)/"denied-comment.md")=="REPORT_ONLY_403"
 assert Path(d,"denied-comment.md").is_file()
 def denied_401(*args):
  if args[:2]==("pr","list"):
   return json.dumps([{"number":12,"body":"<!-- pgextwin-candidate:v1:"+"1"*20+" -->"}])
  raise ValueError("GitHub CLI call failed: HTTP 401 Unauthorized")
 v.gh=denied_401
 try:
  v.comment(report,"pgextwin/test",Path(d)/"unauthorized.md")
  raise AssertionError("unexpected successful comment on HTTP 401")
 except ValueError as e:
  assert "401" in str(e)
 # Ownership mismatch/missing marker is always a hard error, even on 403.
 v.gh=lambda *args: json.dumps([{"number":12,"body":"unrelated PR"}])
 try:
  v.comment(report,"pgextwin/test",Path(d)/"unowned.md")
  raise AssertionError("unowned candidate PR unexpectedly accepted")
 except ValueError as e:
  assert "no unique automation-owned" in str(e)


print("Step 20 candidate artifacts fixtures passed")
