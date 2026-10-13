#!/usr/bin/env python3
"""Adversarial offline tests for Issue #75 same-token REST/GraphQL composite."""
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
from unittest import TestCase, main, mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


composite = load("composite_tested", ROOT / "scripts/classic-composite-protection.py")
fixtures = load("original_rest_fixtures", ROOT / "tests/test-classic-protection-audit.py")
SHA = fixtures.SHA


def graphql_example():
    return {
        "data": {"repository": {
            "nameWithOwner": "pgextwin/plpgsql_check",
            "ref": {
                "name": "main", "prefix": "refs/heads/",
                "target": {"oid": SHA},
                "branchProtectionRule": {
                    "id": "BPR-test-effective-main",
                    "bypassPullRequestAllowances": {
                        "totalCount": 0, "nodes": [],
                        "pageInfo": {"hasNextPage": False},
                    },
                },
            },
        }},
    }


class FakeComposite:
    def __init__(self, branch, protection, gql=None, *, second=None):
        self.first = (deepcopy(branch), deepcopy(protection),
                      deepcopy(graphql_example() if gql is None else gql))
        self.second = deepcopy(second if second is not None else self.first)
        self.steps = []
        self.index = 0

    def get(self, path):
        self.steps.append(("REST", path))
        target = self.first if self.index < 3 else self.second
        if path == composite.rest.BRANCH_PATH:
            assert self.index % 3 == 0
            out = target[0]
        elif path == composite.rest.PROTECTION_PATH:
            assert self.index % 3 == 1
            out = target[1]
        else:
            raise AssertionError("invalid REST path")
        self.index += 1
        return deepcopy(out)

    def get_graphql(self):
        self.steps.append(("GRAPHQL", "query"))
        assert self.index % 3 == 2
        target = self.first if self.index < 3 else self.second
        self.index += 1
        return deepcopy(target[2])


class Response(io.BytesIO):
    def __init__(self, content, status=200):
        super().__init__(content)
        self.status = status


class CompositeContractTests(TestCase):
    def base(self, omitted=True):
        branch, protection = fixtures.fixture()
        if omitted:
            del protection["required_pull_request_reviews"]["bypass_pull_request_allowances"]
        return branch, protection

    def verify(self, b, p, g=None, second=None):
        r = FakeComposite(b, p, g, second=second)
        receipt = composite.collect_verified_composite(r, expected_main_sha=SHA)
        self.assertEqual(r.index, 6)
        self.assertEqual(r.steps, [
            ("REST", composite.rest.BRANCH_PATH),
            ("REST", composite.rest.PROTECTION_PATH), ("GRAPHQL", "query"),
            ("REST", composite.rest.BRANCH_PATH),
            ("REST", composite.rest.PROTECTION_PATH), ("GRAPHQL", "query"),
        ])
        return receipt

    def test_real_rest_field_absent_requires_two_independent_zero_proofs(self):
        b, p = self.base()
        self.assertNotIn("bypass_pull_request_allowances", p["required_pull_request_reviews"])
        result = self.verify(b, p)
        self.assertEqual(result["status"], "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY")
        self.assertEqual(result["mainSha"], SHA)
        self.assertEqual(result["bypassEvidence"], "GRAPHQL_ZERO_FOR_REST_OMISSION")
        self.assertEqual(result["snapshotCount"], 2)
        self.assertTrue(result["independentEffectiveRefZero"])
        self.assertIs(result["publishableReceipt"], False)
        # Production verifier must never mutate raw REST evidence.
        self.assertNotIn("bypass_pull_request_allowances", p["required_pull_request_reviews"])

    def test_explicit_empty_rest_is_not_replaced(self):
        b, p = self.base(omitted=False)
        result = self.verify(b, p)
        self.assertEqual(result["bypassEvidence"], "REST_EXPLICIT_EMPTY")

    def test_reject_nonempty_or_malformed_rest_even_if_graphql_claims_zero(self):
        edits = [
            lambda x: x.update(bypass_pull_request_allowances=None),
            lambda x: x.update(bypass_pull_request_allowances=[]),
            lambda x: x.update(bypass_pull_request_allowances={"users": [], "teams": []}),
            lambda x: x.update(bypass_pull_request_allowances={"users": [], "teams": [], "apps": None}),
            lambda x: x.update(bypass_pull_request_allowances={"users": [], "teams": [], "apps": "invalid"}),
            lambda x: x.update(bypass_pull_request_allowances={"users": [{"login": "test"}], "teams": [], "apps": []}),
            lambda x: x.update(bypass_pull_request_allowances={"users": [], "teams": [{"slug": "test"}], "apps": []}),
            lambda x: x.update(bypass_pull_request_allowances={"users": [], "teams": [], "apps": [{"id": 1}]}),
        ]
        for i, edit in enumerate(edits):
            b, p = self.base()
            edit(p["required_pull_request_reviews"])
            with self.subTest(i=i), self.assertRaises(composite.rest.ProtectionDenied):
                self.verify(b, p)

    def test_rest_required_policies_never_weakened(self):
        edits = [
            lambda b, p: b.update(protected=False),
            lambda b, p: b["commit"].update(sha="b" * 40),
            lambda b, p: b["protection"]["required_status_checks"].update(checks=[]),
            lambda b, p: p["required_status_checks"].update(strict=False),
            lambda b, p: p["required_status_checks"].update(contexts=[]),
            lambda b, p: p["required_status_checks"]["checks"][0].update(app_id=-1),
            lambda b, p: p.pop("required_pull_request_reviews"),
            lambda b, p: p["required_pull_request_reviews"].update(required_approving_review_count=1),
            lambda b, p: p["enforce_admins"].update(enabled=False),
            lambda b, p: p["allow_force_pushes"].update(enabled=True),
            lambda b, p: p["allow_deletions"].update(enabled=True),
            lambda b, p: p.pop("restrictions"),
        ]
        for i, edit in enumerate(edits):
            b, p = self.base()
            edit(b, p)
            with self.subTest(i=i), self.assertRaises((composite.rest.ProtectionDenied, composite.CompositeDenied)):
                self.verify(b, p)

    def test_graphql_bypass_identity_and_completeness_fail_closed(self):
        edits = [
            lambda x: x.update(errors=[]),
            lambda x: x.update(errors=[{"message": "oops"}]),
            lambda x: x.pop("data"),
            lambda x: x["data"]["repository"].update(nameWithOwner="pgextwin/catalog"),
            lambda x: x["data"]["repository"]["ref"].update(name="other"),
            lambda x: x["data"]["repository"]["ref"].update(prefix="refs/tags/"),
            lambda x: x["data"]["repository"]["ref"]["target"].update(oid="b" * 40),
            lambda x: x["data"]["repository"]["ref"].update(branchProtectionRule=None),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"].update(id=""),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(totalCount=1),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(totalCount=None),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(totalCount=False),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(nodes=[{"id": "one"}]),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(pageInfo={"hasNextPage": True}),
            lambda x: x["data"]["repository"]["ref"]["branchProtectionRule"].pop("bypassPullRequestAllowances"),
        ]
        for i, edit in enumerate(edits):
            b, p = self.base()
            g = graphql_example()
            edit(g)
            with self.subTest(i=i), self.assertRaises(composite.graphql.GraphqlBypassDenied):
                self.verify(b, p, g)

    def test_race_between_full_rest_graphql_snapshots_denied(self):
        b, p = self.base()
        variants = []
        b2 = deepcopy(b)
        b2["commit"]["sha"] = "b" * 40
        variants.append((b2, p, graphql_example()))
        p2 = deepcopy(p)
        p2["required_pull_request_reviews"]["dismiss_stale_reviews"] = True
        variants.append((b, p2, graphql_example()))
        g2 = graphql_example()
        g2["data"]["repository"]["ref"]["branchProtectionRule"]["id"] = "BPR-replaced"
        variants.append((b, p, g2))
        p3 = deepcopy(p)
        p3["required_pull_request_reviews"]["bypass_pull_request_allowances"] = {"users": [], "teams": [], "apps": []}
        variants.append((b, p3, graphql_example()))
        g3 = graphql_example()
        g3["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"]["totalCount"] = 1
        variants.append((b, p, g3))
        for i, second in enumerate(variants):
            with self.subTest(i=i), self.assertRaises((composite.CompositeDenied, composite.graphql.GraphqlBypassDenied, composite.rest.ProtectionDenied)):
                self.verify(b, p, second=second)

    def test_token_same_for_rest_and_graphql_query_only(self):
        token = "secret-never-emit"
        reader = composite.CompositeReader(token)
        payload = b'{"data":{"repository":null}}'
        with mock.patch.object(composite, "urlopen", return_value=Response(payload)) as call:
            self.assertEqual(reader.get_graphql(), {"data": {"repository": None}})
            req = call.call_args[0][0]
            self.assertEqual(req.get_method(), "POST")
            self.assertEqual(req.full_url, "https://api.github.com/graphql")
            self.assertEqual(req.get_header("Authorization"), "Bearer " + token)
            body = __import__("json").loads(req.data)
            self.assertIn("query", body)
            self.assertNotIn("mutation", body["query"])
        self.assertEqual(reader._rest._token, token)
        for payload in (b"not json", b'{"a":1,"a":2}', b"[]", b"x" * (composite._MAX + 1)):
            with self.subTest(size=len(payload)):
                with mock.patch.object(composite, "urlopen", return_value=Response(payload)):
                    with self.assertRaises((composite.CompositeDenied, composite.rest.ProtectionDenied)):
                        reader.get_graphql()
        with mock.patch.object(composite, "urlopen", side_effect=HTTPError(
                "https://api.github.com/graphql", 403, "forbidden", {}, None)):
            with self.assertRaises(composite.CompositeDenied) as ex:
                reader.get_graphql()
            self.assertNotIn(token, str(ex.exception))

    def test_bad_sha_denied(self):
        b, p = self.base()
        with self.assertRaises(composite.CompositeDenied):
            composite.collect_verified_composite(FakeComposite(b, p), expected_main_sha="short")


if __name__ == "__main__":
    main()
