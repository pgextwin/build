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
print("Step 20 candidate artifacts fixtures passed")
