#!/usr/bin/env python3
"""Prior-success pilot reuse for all 3 Wave3 targets, with hostile denial."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load("wave3_composite_test", "scripts/issue-75-wave3-classic-composite.py")
old = load("wave3_rest_fixture", "tests/test-issue-75-wave3-classic-readonly.py")
SHA = old.SHA


def graphql(repository):
    return {"data": {"repository": {
        "nameWithOwner": repository,
        "ref": {
            "name": "main", "prefix": "refs/heads/", "target": {"oid": SHA},
            "branchProtectionRule": {
                "id": "BPR-synthetic-fixture",
                "restrictsPushes": False,
                "pushAllowances": {
                    "totalCount": 0, "nodes": [],
                    "pageInfo": {"hasNextPage": False}},
                "bypassPullRequestAllowances": {
                    "totalCount": 0, "nodes": [],
                    "pageInfo": {"hasNextPage": False}},
            }}}}}


def data(repository, *, omitted=True):
    repo, branch, classic, rulesets = old.fixture(repository)
    if omitted:
        del classic["required_pull_request_reviews"]["bypass_pull_request_allowances"]
        del classic["restrictions"]
    return [repo, branch, classic, rulesets, graphql(repository)]


class Reader:
    def __init__(self, repository, before=None, after=None):
        self.repository = repository
        self.before = deepcopy(before if before is not None else data(repository))
        self.after = deepcopy(after if after is not None else self.before)
        self.paths = w.wave3.paths(repository)
        self.events = []
        self.n = 0

    def take(self, typ, path=None):
        round_index, step = divmod(self.n, 5)
        if typ == "GET":
            assert step < 4 and path == self.paths[step]
        else:
            assert typ == "GRAPHQL" and step == 4
        item = deepcopy((self.before if round_index == 0 else self.after)[step])
        self.events.append((typ, path))
        self.n += 1
        return item

    def get(self, path):
        return self.take("GET", path)

    def get_graphql(self):
        return self.take("GRAPHQL")


class Response(io.BytesIO):
    def __init__(self, body, *, status=200, link=""):
        super().__init__(body)
        self.status = status
        self.headers = {"Link": link}


class Wave3CompositeTests(TestCase):
    def check(self, repository, *, before=None, after=None):
        r = Reader(repository, before=before, after=after)
        out = w.collect(r, repository=repository, expected_main_sha=SHA)
        self.assertEqual(r.n, 10)
        self.assertEqual(r.events, ([( "GET", p) for p in r.paths] +
                                     [("GRAPHQL", None)]) * 2)
        self.assertEqual(out["repositoryId"], w.wave3.TARGETS[repository])
        self.assertEqual(out["classification"],
                         "WAVE3_CLASSIC_REST_GRAPHQL_CONTRACT_ONLY")
        self.assertEqual(out["requiredCheckAppId"], 15368)
        for key in ("independentAppPrincipalAuthenticated",
                    "adminReadPermissionAuthenticated",
                    "signerWriterIsolationProven",
                    "publicationAuthorized", "publishableReceipt"):
            self.assertIs(out[key], False)
        self.assertEqual((out["goB"],out["g4"],out["g5"]), ("NO_GO",)*3)
        return out

    def test_three_real_repo_id_pins_and_pilot_reuse_rest_omissions(self):
        for repo in w.wave3.TARGETS:
            with self.subTest(repo=repo):
                result = self.check(repo)
                self.assertEqual(result["bypassEvidence"],
                                 "GRAPHQL_ZERO_FOR_REST_OMISSION")
                self.assertEqual(result["pushEvidence"],
                                 "GRAPHQL_UNRESTRICTED_FOR_REST_OMISSION")
                explicit = self.check(repo, before=data(repo, omitted=False))
                self.assertEqual(explicit["bypassEvidence"],"REST_EXPLICIT_EMPTY")
                self.assertEqual(explicit["pushEvidence"],"REST_EXPLICIT_UNRESTRICTED")
        self.assertEqual(w.core.rest.REPOSITORY, "pgextwin/plpgsql_check")
        self.assertEqual(len(w.core.rest.REQUIRED_CONTEXTS), 8)
        self.assertIn("plpgsql_check", w.core._QUERY)

    def test_graphql_ambiguous_identity_sha_effective_bypass_and_push_denied(self):
        repo = "pgextwin/pgtap"
        mutations = [
            lambda x: x[4].update(errors=[]),
            lambda x: x[4].pop("data"),
            lambda x: x[4]["data"]["repository"].update(nameWithOwner="pgextwin/pg_variables"),
            lambda x: x[4]["data"]["repository"]["ref"]["target"].update(oid="b"*40),
            lambda x: x[4]["data"]["repository"]["ref"].update(branchProtectionRule=None),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"].update(id=""),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(totalCount=1),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(totalCount=False),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"].update(nodes=[{"id":"actor"}]),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["bypassPullRequestAllowances"]["pageInfo"].update(hasNextPage=True),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"].update(restrictsPushes=True),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["pushAllowances"].update(totalCount=1),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["pushAllowances"].update(nodes=[{"id":"actor"}]),
            lambda x: x[4]["data"]["repository"]["ref"]["branchProtectionRule"]["pushAllowances"].pop("pageInfo"),
        ]
        for i, edit in enumerate(mutations):
            items=data(repo)
            edit(items)
            with self.subTest(i=i), self.assertRaises(
                (w.wave3.Deny,w.core.CompositeDenied,w.core.graphql.GraphqlBypassDenied,
                 w.core.rest.ProtectionDenied)):
                w.collect(Reader(repo,before=items),
                          repository=repo,expected_main_sha=SHA)

    def test_invalid_explicit_rest_bypass_and_rules_never_fall_back(self):
        repo="pgextwin/pg_variables"
        edits=[
            lambda x:x[2]["required_pull_request_reviews"].update(bypass_pull_request_allowances=None),
            lambda x:x[2]["required_pull_request_reviews"].update(bypass_pull_request_allowances={"users":[],"teams":[]}),
            lambda x:x[2]["required_pull_request_reviews"].update(bypass_pull_request_allowances={"users":[{"id":5}],"teams":[],"apps":[]}),
            lambda x:x[2].update(restrictions={"users":[{"login":"admin"}],"teams":[],"apps":[]}),
            lambda x:x[2]["enforce_admins"].update(enabled=False),
            lambda x:x[2]["required_status_checks"].update(strict=False),
            lambda x:x[2]["required_status_checks"]["checks"][0].update(app_id=5281285),
            lambda x:x[3].append({"name":"override"}),
            lambda x:x[0].update(id=1425680909),
        ]
        for i,edit in enumerate(edits):
            items=data(repo)
            edit(items)
            with self.subTest(i=i),self.assertRaises((
                w.wave3.Deny,w.core.CompositeDenied,w.core.graphql.GraphqlBypassDenied,
                w.core.rest.ProtectionDenied)):
                w.collect(Reader(repo,before=items),repository=repo,expected_main_sha=SHA)

    def test_second_snapshot_race_credential_mismatch_and_unknown_sha(self):
        repo="pgextwin/pg_store_plans"
        for idx in range(5):
            second=data(repo)
            if idx==0:second[0]["full_name"]="pgextwin/catalog"
            if idx==1:second[1]["commit"]["sha"]="b"*40
            if idx==2:second[2]["required_pull_request_reviews"]["dismiss_stale_reviews"]=True
            if idx==3:second[3].append({"name":"override"})
            if idx==4:second[4]["data"]["repository"]["ref"]["branchProtectionRule"]["id"]="changed"
            with self.subTest(idx=idx),self.assertRaises((
                w.wave3.Deny,w.core.CompositeDenied,w.core.graphql.GraphqlBypassDenied,
                w.core.rest.ProtectionDenied)):
                w.collect(Reader(repo,after=second),repository=repo,expected_main_sha=SHA)
        for sha in ("main","f"*39,"F"*40,None):
            with self.assertRaises(w.wave3.Deny):
                w.collect(Reader(repo),repository=repo,expected_main_sha=sha)
        with self.assertRaises(w.wave3.Deny):
            w.collect(Reader(repo),repository="pgextwin/build",expected_main_sha=SHA)

    def test_exact_query_safe_static_graphql_same_token_no_leak(self):
        token="SYNTHETIC_SCOPED_TOKEN_DO_NOT_LOG_1234567890"
        for repo in w.wave3.TARGETS:
            calls=[]
            def opener(request,timeout=20):
                calls.append((request,timeout))
                return Response(json.dumps(graphql(repo)).encode())
            r=w.CompositeReader(token,repo,opener=opener)
            self.assertEqual(r._token,token)
            self.assertEqual(r._repository,repo)
            self.assertEqual(r.get_graphql(),graphql(repo))
            self.assertEqual(len(calls),1)
            req,timeout=calls[0]
            self.assertEqual(req.get_method(),"POST")
            self.assertEqual(req.full_url,"https://api.github.com/graphql")
            self.assertEqual(req.get_header("Authorization"),"Bearer "+token)
            query=json.loads(req.data)["query"]
            self.assertIn('name: "'+repo.split("/")[1]+'"',query)
            self.assertNotIn("mutation",query.lower())
            self.assertIn("bypassPullRequestAllowances",query)
            self.assertIn("pushAllowances",query)
            self.assertEqual(timeout,20)
        bad_payloads=[
            (b'{"a":1,"a":2}',200,""),
            (b'{"data":null}',202,""),
            (b"invalid",200,""),
            (b"[]" ,200,""),
            (b"x"*(w.MAX_GRAPHQL+1),200,""),
            (b"{}",200,'<https://attacker.invalid>; rel="next"'),
        ]
        for body,status,link in bad_payloads:
            r=w.CompositeReader(token,"pgextwin/pgtap",
                opener=lambda *args,**kwargs:Response(body,status=status,link=link))
            with self.assertRaises(w.wave3.Deny) as e:
                r.get_graphql()
            self.assertNotIn(token,str(e.exception))
        for foreign in ("pgextwin/build","pgextwin/plpgsql_check",None,True):
            with self.assertRaises(w.wave3.Deny):
                w.CompositeReader(token,foreign,opener=lambda *_:None)

    def test_nonprivileged_ci_only_and_no_publishing(self):
        work=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("python tests/test-issue-75-wave3-classic-composite.py",work)
        src=(ROOT/"scripts/issue-75-wave3-classic-composite.py").read_text()
        for forbidden in ("secrets.", "gh release", "workflow_dispatch",
                          "git push", "create-github-app-token@"):
            self.assertNotIn(forbidden,src)


if __name__=="__main__":
    main()
