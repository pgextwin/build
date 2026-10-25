"""Frozen historical manual fixtures, independent of live activation metadata.

Actual checked-out policy files are validated separately by the deployment
contract and by current/manual/automatic projection tests in required CI.
"""
import json
from pathlib import Path

def manual_policy(filename):
    data=json.loads((Path(__file__).parent/"fixtures/manual-publication-policy.json").read_text())
    return data[filename]
