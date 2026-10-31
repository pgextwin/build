#!/usr/bin/env python3
"""R10 v2.3: prevent reintroduction of a fictitious second human approval gate."""
import json
from pathlib import Path

data = json.loads(Path("metadata/issue311-remaining-work-v22.json").read_text())
doc = Path("docs/issue311-remaining-work-v22.md").read_text()
assert data["contract"] == "v2.3-single-user-execution"
assert (data["acceptedCount"], data["totalCount"]) == (85, 94)
assert data["publicationAuthorized"] is False and data["runtimeEnabled"] is False
w = {x["id"]: x for x in data["workPackages"]}
assert w["W10-A"]["accepted"] is False
assert w["W10-C"]["accepted"] is False
a = w["W10-A"]; c = w["W10-C"]
assert "NOT_REQUIRED" in "\n".join(a["passWhen"])
assert "NOT_REQUIRED" in "\n".join(c["passWhen"])
assert "REQUIRED_AND_MISSING" in "\n".join(c["passWhen"])
assert "only when genuinely required" in "\n".join(c["passWhen"])
assert all(x in "\n".join(c["passWhen"]) for x in (
    "17-target", "State blob/revision", "revoke401",
    "independent keyless readback", "W10-B"))
assert all(x in "\n".join(c["failWhen"]) for x in (
    "NOT_REQUIRED", "Mock State", "PUBLISH_DENY"))
assert any("do not invoke record_approval_block" in x for x in c["procedure"])
assert any("no second human intent" in x for x in c["procedure"])
assert "REQUIRED_AND_MISSING" in doc and "**NOT_REQUIRED:**" in doc
assert "85/94" in doc and "W10-B" in doc
assert "元ZIP実SHA" in doc and "鍵なしreadback" in doc
assert "この契約補正は実原本の受入そのものではなく" in doc
print("R10_V23_EFFECTIVE_POLICY_CONDITIONAL_GATE_PASS")
