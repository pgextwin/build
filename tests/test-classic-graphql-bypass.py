#!/usr/bin/env python3
"""Credential-free adversarial fixtures for Issue #75 GraphQL proof."""
import copy
import importlib.util
from pathlib import Path

module_path = Path(__file__).resolve().parents[1] / "scripts/classic-graphql-bypass.py"
spec = importlib.util.spec_from_file_location("classic_graphql_bypass", module_path)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "6ee70f3fdfe26fec4cb28c82e17bc216e390214b"


def example():
    return {"data": {"repository": {
        "nameWithOwner": "pgextwin/plpgsql_check",
        "ref": {
            "name": "main",
            "prefix": "refs/heads/",
            "target": {"oid": SHA},
            "branchProtectionRule": {
                "id": "BPR_trusted_fixture_only",
                "bypassPullRequestAllowances": {
                    "totalCount": 0,
                    "nodes": [],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        },
    }}}


def deny(mutator, expected_sha=SHA):
    snapshot = example()
    mutator(snapshot)
    try:
        mod.validate_effective_ref_bypass_zero(snapshot, expected_main_sha=expected_sha)
    except mod.GraphqlBypassDenied:
        return
    raise AssertionError("hostile/ambiguous GraphQL effective protection accepted")


def main():
    proof = mod.validate_effective_ref_bypass_zero(example(), expected_main_sha=SHA)
    assert proof == {
        "schemaVersion": 1,
        "status": "VERIFIED_EFFECTIVE_REF_BYPASS_ZERO",
        "repository": "pgextwin/plpgsql_check",
        "branch": "main",
        "mainSha": SHA,
        "bypassPullRequestAllowances": 0,
        "publishableReceipt": False,
    }
    rule = lambda s: s["data"]["repository"]["ref"]["branchProtectionRule"]
    ref = lambda s: s["data"]["repository"]["ref"]
    mutations = [
        lambda s: s.update({"errors": [{"message": "denied"}]}),
        lambda s: s.update({"errors": []}),
        lambda s: s.pop("data"),
        lambda s: s["data"].update({"repository": None}),
        lambda s: s["data"]["repository"].update({"nameWithOwner": "pgextwin/catalog"}),
        lambda s: s["data"]["repository"].pop("ref"),
        lambda s: ref(s).update({"name": "release"}),
        lambda s: ref(s).update({"prefix": "refs/tags/"}),
        lambda s: ref(s)["target"].update({"oid": "0" * 40}),
        lambda s: ref(s).update({"target": None}),
        lambda s: ref(s).pop("branchProtectionRule"),
        lambda s: rule(s).update({"id": ""}),
        lambda s: rule(s).pop("bypassPullRequestAllowances"),
        lambda s: rule(s).update({"bypassPullRequestAllowances": None}),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"totalCount": 1}),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"totalCount": False}),
        lambda s: rule(s)["bypassPullRequestAllowances"].pop("totalCount"),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"nodes": [{"id": "actor"}]}),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"nodes": None}),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"pageInfo": {"hasNextPage": True}}),
        lambda s: rule(s)["bypassPullRequestAllowances"].update({"pageInfo": None}),
    ]
    for mutation in mutations:
        deny(mutation)
    deny(lambda s: None, expected_sha="0" * 40)
    deny(lambda s: None, expected_sha="not-a-sha")
    print("PASS: strict effective Ref + zero bypass GraphQL fixture and", len(mutations) + 2, "denial cases")


if __name__ == "__main__":
    main()
