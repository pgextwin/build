#!/usr/bin/env python3
"""Issue #311 R03 inert request contract deny fixtures (NO PUBLISH)."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("issue311_contract", ROOT / "scripts" / "issue311-request-contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
NOW = datetime(2026, 10, 29, 0, 10, tzinfo=timezone.utc)
ID = "r-20261029-aaaaaaaa"
PATH = ".github/execution-requests/" + ID + ".json"


def valid():
    return {
        "schemaVersion": 1, "kind": "pgextwin-execution-request",
        "requestId": ID, "mode": "AUDIT_ONLY",
        "requestedBy": "ShutenOishi",
        "createdAt": "2026-10-29T00:00:00Z",
        "expiresAt": "2026-10-29T01:00:00Z",
        "purpose": "Read-only audit proof for one bounded frozen target.",
        "allowFutureUpdates": False,
        "source": {"centralMainSha": "a" * 40, "fleetRegistryBlobSha": "b" * 40},
        "limits": {"maxParallel": 2, "maxAttemptsPerStage": 2,
                   "maxOperations": 20, "maxWallClockMinutes": 90},
        "approval": {"scopeText": "Audit this one immutable target, without signing or publishing.",
                     "publicReleaseAuthorized": False, "publicationGrants": []},
        "targets": [{"repo": "pgextwin/orafce", "mainSha": "c" * 40}],
        "resumeFrom": None,
    }


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class ContractTests(unittest.TestCase):
    def test_valid_audit_and_prepare_never_authorize_release(self):
        for mode in ("AUDIT_ONLY", "PREPARE"):
            value = valid()
            value["mode"] = mode
            output = contract.validate_declaration(encode(value), PATH, now=NOW)
            self.assertEqual(output["mode"], mode)
            self.assertTrue(output["declarationOnly"])
            self.assertFalse(output["actorAuthenticated"])
            self.assertFalse(output["publicationAuthorized"])
            self.assertEqual(output["targets"], ("pgextwin/orafce",))

    def test_declared_publish_eligibility_is_not_real_grant(self):
        value = valid()
        value["mode"] = "PUBLISH_ELIGIBLE"
        value["approval"]["publicReleaseAuthorized"] = True
        value["approval"]["publicationGrants"] = [{
            "repo": "pgextwin/orafce", "releaseTag": "v4.17.1-windows.1",
            "candidateHeadSha": "d" * 40, "candidateRunId": 123,
            "decisionRunId": 122, "packagingMainSha": "c" * 40,
        }]
        output = contract.validate_declaration(encode(value), PATH, now=NOW)
        self.assertFalse(output["actorAuthenticated"])
        self.assertFalse(output["publicationAuthorized"])

    def test_reject_invalid_scope_and_approval(self):
        cases = [
            lambda v: v.update(schemaVersion=True),
            lambda v: v.update(kind="free-form-command"),
            lambda v: v.update(command="gh release create"),
            lambda v: v.update(allowFutureUpdates=True),
            lambda v: v.update(mode="PUBLISH_ELIGIBLE"),
            lambda v: v["approval"].update(publicReleaseAuthorized=True),
            lambda v: v["approval"].update(publicationGrants=[{"repo": "pgextwin/orafce"}]),
            lambda v: v["targets"][0].update(repo="pgextwin/unregistered"),
            lambda v: v["targets"][0].update(mainSha="main"),
            lambda v: v["targets"].append(copy.deepcopy(v["targets"][0])),
            lambda v: v["limits"].update(maxAttemptsPerStage=0),
            lambda v: v["limits"].update(maxParallel=99),
            lambda v: v["limits"].update(maxWallClockMinutes=900),
            lambda v: v.update(expiresAt="2026-10-31T00:00:00Z"),
            lambda v: v.update(expiresAt="2026-10-29T00:05:00Z"),
            lambda v: v.update(createdAt="2026-11-29T00:00:00Z"),
            lambda v: v.update(createdAt="2026-10-29T00:00:00"),
            lambda v: v.update(requestId="r-other"),
            lambda v: v.update(resumeFrom=ID),
        ]
        for n, mutate in enumerate(cases):
            v = valid()
            mutate(v)
            with self.subTest(index=n), self.assertRaises(contract.DeclarationDenied):
                contract.validate_declaration(encode(v), PATH, now=NOW)

    def test_reject_spoofed_request_path_duplicate_keys_and_expiry(self):
        raw = encode(valid())
        with self.assertRaises(contract.DeclarationDenied):
            contract.validate_declaration(raw, ".github/execution-requests/wrong.json", now=NOW)
        with self.assertRaises(contract.DeclarationDenied):
            contract.validate_declaration(raw.replace(b'"mode":"AUDIT_ONLY"',
                                                      b'"mode":"AUDIT_ONLY","mode":"AUDIT_ONLY"'),
                                          PATH, now=NOW)
        with self.assertRaises(contract.DeclarationDenied):
            contract.validate_declaration(raw, PATH, now=datetime(2026,10,29,1,0,tzinfo=timezone.utc))
        with self.assertRaises(contract.DeclarationDenied):
            contract.validate_declaration(raw + b" " * 20000, PATH, now=NOW)
        with self.assertRaises(contract.DeclarationDenied):
            contract.validate_declaration(b"{invalid", PATH, now=NOW)


if __name__ == "__main__":
    unittest.main()
