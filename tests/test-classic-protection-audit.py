#!/usr/bin/env python3
"""Offline deny/allow fixtures for the Issue #75 read-only Classic audit."""
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
from unittest import TestCase, main, mock
from urllib.error import HTTPError

MODULE = Path(__file__).resolve().parents[1] / "scripts" / "classic-protection-audit.py"
spec = importlib.util.spec_from_file_location("classic_protection_audit", MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

SHA = "a" * 40


def fixture():
    ordered = sorted(audit.REQUIRED_CONTEXTS)
    checks = [{"context": x, "app_id": audit.ACTIONS_APP_ID} for x in ordered]
    branch = {
        "name": "main", "protected": True, "commit": {"sha": SHA},
        "protection": {
            "enabled": True,
            "required_status_checks": {
                "checks": deepcopy(checks),
                "contexts": deepcopy(ordered),
                "enforcement_level": "everyone",
            },
        },
    }
    classic = {
        "required_status_checks": {
            "strict": True,
            "checks": deepcopy(checks),
            "contexts": deepcopy(ordered),
            "enforcement_level": "everyone",
        },
        "required_pull_request_reviews": {
            "required_approving_review_count": 0,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "restrictions": None,
    }
    return branch, classic


class FakeRead:
    def __init__(self, branch, classic, *, second_branch=None, second_classic=None):
        self.snapshots = [
            deepcopy(branch), deepcopy(classic),
            deepcopy(second_branch if second_branch is not None else branch),
            deepcopy(second_classic if second_classic is not None else classic),
        ]
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if not self.snapshots:
            raise AssertionError("more GitHub GET requests than expected")
        return self.snapshots.pop(0)


class Response(io.BytesIO):
    def __init__(self, data, *, status=200, link=""):
        super().__init__(data)
        self.status = status
        self.headers = {"Link": link}


class ClassicAuditTests(TestCase):
    def test_accepted_read_only_and_two_full_snapshots(self):
        branch, classic = fixture()
        reader = FakeRead(branch, classic)
        result = audit.collect_verified_classic(reader, expected_main_sha=SHA)
        self.assertEqual(result["status"], "VERIFIED_CLASSIC_READ_ONLY")
        self.assertEqual(result["mainSha"], SHA)
        self.assertEqual(result["requiredChecksAppId"], 15368)
        self.assertEqual(len(result["requiredChecks"]), 8)
        self.assertFalse(result["publishableReceipt"])
        self.assertNotIn("token", str(result).lower())
        self.assertEqual(reader.paths, [
            audit.BRANCH_PATH, audit.PROTECTION_PATH,
            audit.BRANCH_PATH, audit.PROTECTION_PATH,
        ])

    def test_protection_required_fields_and_denials(self):
        edits = [
            lambda b, p: b.update(name="release"),
            lambda b, p: b.update(protected=False),
            lambda b, p: b["commit"].update(sha="b" * 40),
            lambda b, p: b["protection"]["required_status_checks"].update(enforcement_level="non_admins"),
            lambda b, p: b["protection"]["required_status_checks"].update(checks=[]),
            lambda b, p: b["protection"]["required_status_checks"]["checks"][0].update(app_id=-1),
            lambda b, p: p.pop("required_status_checks"),
            lambda b, p: p["required_status_checks"].update(strict=False),
            lambda b, p: p["required_status_checks"].pop("strict"),
            lambda b, p: p["required_status_checks"].update(contexts=[]),
            lambda b, p: p["required_status_checks"].update(contexts=["Windows required summary"] * 8),
            lambda b, p: p["required_status_checks"]["checks"][0].update(app_id=123),
            lambda b, p: p["required_status_checks"]["checks"][0].update(app_id="15368"),
            lambda b, p: p["required_status_checks"]["checks"][0].update(context="other"),
            lambda b, p: p["required_status_checks"]["checks"].append(deepcopy(p["required_status_checks"]["checks"][0])),
            lambda b, p: p["required_status_checks"].update(enforcement_level="non_admins"),
            lambda b, p: p.pop("required_pull_request_reviews"),
            lambda b, p: p["required_pull_request_reviews"].update(required_approving_review_count=1),
            lambda b, p: p["required_pull_request_reviews"].update(required_approving_review_count=False),
            lambda b, p: p["required_pull_request_reviews"].pop("required_approving_review_count"),
            lambda b, p: p["required_pull_request_reviews"].pop("bypass_pull_request_allowances"),
            lambda b, p: p["required_pull_request_reviews"]["bypass_pull_request_allowances"].pop("apps"),
            lambda b, p: p["required_pull_request_reviews"]["bypass_pull_request_allowances"]["users"].append({"login": "admin"}),
            lambda b, p: p["required_pull_request_reviews"]["bypass_pull_request_allowances"]["teams"].append({"slug": "ops"}),
            lambda b, p: p["required_pull_request_reviews"]["bypass_pull_request_allowances"]["apps"].append({"slug": "bot"}),
            lambda b, p: p["enforce_admins"].update(enabled=False),
            lambda b, p: p.pop("enforce_admins"),
            lambda b, p: p["allow_force_pushes"].update(enabled=True),
            lambda b, p: p.pop("allow_force_pushes"),
            lambda b, p: p["allow_deletions"].update(enabled=True),
            lambda b, p: p.pop("allow_deletions"),
            lambda b, p: p.pop("restrictions"),
            lambda b, p: p.update(restrictions={"users": [{"login": "other"}], "teams": [], "apps": []}),
        ]
        for index, edit in enumerate(edits):
            branch, classic = fixture()
            edit(branch, classic)
            with self.subTest(index=index), self.assertRaises(audit.ProtectionDenied):
                audit.collect_verified_classic(FakeRead(branch, classic), expected_main_sha=SHA)

    def test_protection_tamper_or_race_denied(self):
        branch, classic = fixture()
        branch2 = deepcopy(branch)
        branch2["commit"]["sha"] = "b" * 40
        with self.assertRaises(audit.ProtectionDenied):
            audit.collect_verified_classic(
                FakeRead(branch, classic, second_branch=branch2), expected_main_sha=SHA)
        classic2 = deepcopy(classic)
        classic2["required_pull_request_reviews"]["dismiss_stale_reviews"] = True
        with self.assertRaises(audit.ProtectionDenied):
            audit.collect_verified_classic(
                FakeRead(branch, classic, second_classic=classic2), expected_main_sha=SHA)
        with self.assertRaises(audit.ProtectionDenied):
            audit.collect_verified_classic(FakeRead(branch, classic), expected_main_sha="short")

    def test_get_only_scoped_reads_and_no_token_leaks(self):
        with self.assertRaises(audit.ProtectionDenied):
            audit.ClassicProtectionReader("")
        token = "secret-never-print-this"
        reader = audit.ClassicProtectionReader(token)
        for path in ("repos/pgextwin/build/branches/main/protection",
                     "repos/pgextwin/plpgsql_check/issues",
                     audit.PROTECTION_PATH + "?other=true"):
            with self.subTest(path=path), self.assertRaises(audit.ProtectionDenied):
                reader.get(path)
        response = Response(b'{"enforce_admins":{"enabled":true}}')
        with mock.patch.object(audit, "urlopen", return_value=response) as opener:
            got = reader.get(audit.PROTECTION_PATH)
            self.assertEqual(got["enforce_admins"], {"enabled": True})
            req = opener.call_args[0][0]
            self.assertEqual(req.get_method(), "GET")
            self.assertEqual(req.get_header("Authorization"), "Bearer " + token)
        for status in (401, 403, 404, 429, 500):
            with self.subTest(status=status):
                err = HTTPError("https://api.github.com/redacted", status, "denied", {}, None)
                with mock.patch.object(audit, "urlopen", side_effect=err):
                    with self.assertRaises(audit.ProtectionDenied) as raised:
                        reader.get(audit.PROTECTION_PATH)
                    self.assertNotIn(token, str(raised.exception))

    def test_missing_duplicate_incomplete_pagination_denied(self):
        token = audit.ClassicProtectionReader("not-real-token")
        payloads = [
            (b"not JSON", ""),
            (b"[]", ""),
            (b'{"strict":true,"strict":false}', ""),
            (b'{"ok":true}', '<https://api.github.com/next>; rel="next"'),
            (b'{"ok":true}', "<https://api.github.com/next>; rel=next"),
            (b"x" * (audit.MAX_JSON_BYTES + 1), ""),
        ]
        for data, link in payloads:
            with self.subTest(data=data[:30], link=link):
                with mock.patch.object(audit, "urlopen",
                                       return_value=Response(data, link=link)):
                    with self.assertRaises(audit.ProtectionDenied):
                        token.get(audit.PROTECTION_PATH)
        with mock.patch.object(audit, "urlopen", return_value=Response(b"{}", status=202)):
            with self.assertRaises(audit.ProtectionDenied):
                token.get(audit.PROTECTION_PATH)


if __name__ == "__main__":
    main()
