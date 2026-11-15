"""Frozen historical manual fixtures, independent of live activation metadata.

Actual checked-out policy files are validated separately by the deployment
contract and by current/manual/automatic projection tests in required CI.
"""
from copy import deepcopy
import json
from pathlib import Path

POLICY_FILES = (
    "automation-fleet.json",
    "release-promotion.json",
    "unattended-publication.json",
    "publisher-write-boundary.json",
)


def manual_policy(filename):
    data=json.loads((Path(__file__).parent/"fixtures/manual-publication-policy.json").read_text())
    return data[filename]


def automatic_policy(objects, mode, app_id, installation_id):
    """Build a nonpublishing automatic-policy bundle copy for transition/projection tests."""
    f, c, u, b = deepcopy(objects)
    f["releasePolicy"] = mode
    for row in f["entries"]:
        row["releasePolicy"] = mode
    c["releasePolicy"] = mode
    u["mode"] = "UNATTENDED"
    u["controls"] = {name: True for name in u["controls"]}
    b.update(mode="ENFORCE", publisherAppId=app_id, publisherInstallationId=installation_id)
    return [f, c, u, b]
