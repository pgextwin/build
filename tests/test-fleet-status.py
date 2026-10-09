#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import json
import sys
r=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(r/"scripts"))
spec=importlib.util.spec_from_file_location("fleet_status",r/"scripts/fleet-status.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert m.compact_run(None) is None
a=m.compact_run({"id":2,"html_url":"https://github.com/pgextwin/build/actions/runs/2","status":"completed","conclusion":"failure","head_branch":"auto-candidate/123"})
assert a["conclusion"]=="failure" and a["branch"]=="auto-candidate/123"
state={"generatedAt":"2026-10-09T00:00:00Z","extensions":[{"extension":"test",
"mode":"WATCH","lastWatch":{"conclusion":"failure"},"detectedCandidate":None,
"lastCandidateStatus":"FAILED","lastSuccessfulCandidate":{"packagingCommit":"1"*40}}]}
output=m.render(state)
assert "| test | WATCH | failure |" in output
assert "| FAILED | "+"1"*40+" |" in output
assert "Latest run failures" in output
print("Step 20 fleet status fixtures passed")
