#!/usr/bin/env python3
"""Issue #75 Wave3 admin GET-only contract: synthetic fixtures, never live GO."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_wave3_classic", ROOT / "scripts/issue-75-wave3-classic-readonly.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

SHA = "a" * 40


def fixture(repository):
    checks = [{"context": "Windows required summary", "app_id": 15368}]
    branch = {
        "name": "main", "protected": True, "commit": {"sha": SHA},
        "protection": {"required_status_checks": {
            "enforcement_level": "everyone", "contexts": ["Windows required summary"],
            "checks": deepcopy(checks)}}}
    classic = {
        "required_status_checks": {
            "strict": True, "contexts": ["Windows required summary"],
            "checks": deepcopy(checks), "enforcement_level": "everyone"},
        "required_pull_request_reviews": {
            "required_approving_review_count": 0,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []}},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "restrictions": None,
    }
    repo = {"id": w.TARGETS[repository], "full_name": repository,
            "owner": {"login": "pgextwin"}}
    return [repo, branch, classic, []]


class Reader:
    def __init__(self, repository, before=None, after=None):
        self.paths = []
        self.names = w.paths(repository)
        self.snapshots = deepcopy((before or fixture(repository),
                                   after or before or fixture(repository)))
        self.num = 0

    def get(self, path):
        self.paths.append(path)
        if path != self.names[self.num % 4]:
            raise AssertionError("wrong endpoint/order")
        item = deepcopy(self.snapshots[self.num // 4][self.num % 4])
        self.num += 1
        return item


class Response(io.BytesIO):
    status = 200
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class Wave3Contracts(TestCase):
    def test_three_actual_immutable_target_ids_and_single_ci(self):
        self.assertEqual(w.TARGETS, {
            "pgextwin/pgtap": 1425678353,
            "pgextwin/pg_variables": 1425679720,
            "pgextwin/pg_store_plans": 1425680909})
        self.assertEqual(w.EXPECTED_CONTEXTS, {"Windows required summary"})
        self.assertEqual((w.AUDITOR_APP_ID, w.AUDITOR_INSTALLATION_ID),
                         (5295410, 170837728))
        # Historical pilot policy must not be weakened in this PR.
        self.assertEqual(len(w.rest.REQUIRED_CONTEXTS), 8)
        self.assertIn("Windows required summary", w.rest.REQUIRED_CONTEXTS)
        self.assertEqual(w.rest.REPOSITORY, "pgextwin/plpgsql_check")

    def test_all_targets_two_full_snapshots_contract_only(self):
        for name in w.TARGETS:
            with self.subTest(name=name):
                reader = Reader(name)
                result = w.collect(reader, repository=name, expected_main_sha=SHA)
                self.assertEqual(reader.paths, list(w.paths(name)) * 2)
                self.assertEqual(result["repositoryId"], w.TARGETS[name])
                self.assertEqual(result["requiredCheckAppId"], 15368)
                self.assertEqual(result["classification"],
                                 "WAVE3_CLASSIC_TWO_SNAPSHOT_CONTRACT_ONLY")
                for field in ("publishableReceipt", "publicationAuthorized",
                              "auditorIdentityIndependentlyAuthenticated",
                              "effectiveRulesAuthenticatedByIndependentApp",
                              "externalCredentialIsolationProven"):
                    self.assertIs(result[field], False)
                self.assertEqual((result["goB"], result["g4"], result["g5"]),
                                 ("NO_GO",) * 3)

    def test_foreign_repo_type_and_invalid_sha_denied_before_get(self):
        bad = ("pgextwin/build", "pgextwin/catalog", "pgextwin/website",
               "pgextwin/plpgsql_check", "pgextwin/PgTap", "pgextwin/pgtap/",
               "attacker/pgtap", "", None, 17, True)
        for name in bad:
            with self.subTest(name=name), self.assertRaises(w.Deny):
                w.paths(name)
        for sha in ("main", "f"*39, "F"*40, None, True, 12):
            with self.subTest(sha=sha), self.assertRaises(w.Deny):
                w.collect(Reader("pgextwin/pgtap"),
                          repository="pgextwin/pgtap", expected_main_sha=sha)

    def test_repo_identity_and_missing_rulesets_fail_closed(self):
        target = "pgextwin/pgtap"
        mutations = [
            lambda x: x[0].update(id=1425679720),
            lambda x: x[0].update(id=True),
            lambda x: x[0].update(full_name="pgextwin/catalog"),
            lambda x: x[0].update(owner={"login": "attacker"}),
            lambda x: x[0].pop("id"),
            lambda x: x[3].append({"name": "override"}),
            lambda x: x.__setitem__(3, None),
            lambda x: x.__setitem__(3, {}),
        ]
        for i, edit in enumerate(mutations):
            items = fixture(target)
            edit(items)
            with self.subTest(i=i), self.assertRaises((w.Deny, w.rest.ProtectionDenied)):
                w.collect(Reader(target, before=items), repository=target,
                          expected_main_sha=SHA)

    def test_strict_classic_required_ci_admin_and_bypass(self):
        target = "pgextwin/pg_variables"
        mutations = [
            lambda x: x[1]["commit"].update(sha="b"*40),
            lambda x: x[1].update(protected=False),
            lambda x: x[1]["protection"]["required_status_checks"]["checks"][0].update(app_id=0),
            lambda x: x[2]["required_status_checks"].update(strict=False),
            lambda x: x[2]["required_status_checks"]["checks"][0].update(app_id=5281285),
            lambda x: x[2]["required_status_checks"].update(contexts=[]),
            lambda x: x[2]["required_pull_request_reviews"].update(required_approving_review_count=1),
            lambda x: x[2]["required_pull_request_reviews"].pop("bypass_pull_request_allowances"),
            lambda x: x[2]["required_pull_request_reviews"]["bypass_pull_request_allowances"]["apps"].append({"slug":"bot"}),
            lambda x: x[2]["enforce_admins"].update(enabled=False),
            lambda x: x[2]["allow_force_pushes"].update(enabled=True),
            lambda x: x[2]["allow_deletions"].update(enabled=True),
            lambda x: x[2].pop("restrictions"),
        ]
        for i, edit in enumerate(mutations):
            items = fixture(target)
            edit(items)
            with self.subTest(i=i), self.assertRaises((w.Deny, w.rest.ProtectionDenied)):
                w.collect(Reader(target, before=items), repository=target,
                          expected_main_sha=SHA)

    def test_second_snapshot_races_all_four_endpoints(self):
        target = "pgextwin/pg_store_plans"
        for index in range(4):
            first = fixture(target)
            second = deepcopy(first)
            if index == 0:
                second[0]["description"] = "changed"
            elif index == 1:
                second[1]["commit"]["sha"] = "b"*40
            elif index == 2:
                second[2]["required_status_checks"]["checks"][0]["app_id"] = 5
            else:
                second[3].append({"id": 1})
            with self.subTest(index=index), self.assertRaises(
                    (w.Deny, w.rest.ProtectionDenied)):
                w.collect(Reader(target, before=first, after=second),
                          repository=target, expected_main_sha=SHA)

    def test_scoped_http_only_get_and_never_leaks_token(self):
        target = "pgextwin/pgtap"
        secret = "SYNTHETIC_SECRET_MUST_NOT_PRINT_1234567890"
        calls = []
        def fake_open(req, timeout):
            calls.append((req, timeout))
            return Response(b'{"id":1425678353}')
        reader = w.ScopedReader(secret, target, opener=fake_open)
        for path in ("repos/pgextwin/catalog", "repos/pgextwin/build",
                     "repos/pgextwin/pg_variables/branches/main",
                     "repos/pgextwin/pgtap/branches/main/protection?alter=1",
                     "https://attacker.invalid", None):
            with self.subTest(path=path), self.assertRaises(w.Deny):
                reader.get(path)
        self.assertEqual(calls, [])
        self.assertEqual(reader.get(w.paths(target)[0]), {"id": 1425678353})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].get_method(), "GET")
        self.assertEqual(calls[0][0].get_header("Authorization"), "Bearer "+secret)
        self.assertEqual(calls[0][1], 20)
        for corrupt in (b'{"id":1,"id":2}', b"{}", b"[]"*w.MAX_RESPONSE,
                        b"invalid", b"\xff"):
            with self.subTest(corrupt=corrupt[:20]):
                reader = w.ScopedReader(secret, target,
                        opener=lambda *args, **kw: Response(corrupt))
                if corrupt == b"{}":
                    self.assertEqual(reader.get(w.paths(target)[0]), {})
                else:
                    with self.assertRaises(w.Deny) as e:
                        reader.get(w.paths(target)[0])
                    self.assertNotIn(secret, str(e.exception))
        with self.assertRaises(w.Deny):
            w.NoRedirect().redirect_request(None, None, 302, "", {},
                                            "https://attacker.invalid")

    def test_no_secret_or_publish_workflow_entrypoint(self):
        src = (ROOT / "scripts/issue-75-wave3-classic-readonly.py").read_text()
        for forbidden in ("if __name__ ==", "gh release", "secrets.",
                          "create-github-app-token", "workflow_dispatch:",
                          "GITHUB_OUTPUT", "git push"):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    main()
