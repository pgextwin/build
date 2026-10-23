#!/usr/bin/env python3
"""Hostile read-only tag-plan tests. Synthetic data is never Publisher authority."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]


def load(label, path):
    spec = importlib.util.spec_from_file_location(label, ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


plan = load("auto_tag_plan", "scripts/automatic-release-tag-plan.py")
pub = load("tag_plan_pub_bridge", "tests/test-automatic-publisher-bridge.py")
base = load("tag_plan_source_fixture", "tests/test-fleet-publish-release.py")
REPO = "pgextwin/pgaudit"
SHA = "a" * 40
RUN = 456789


def fixture():
    inputs = pub.fixture()
    inputs["repo"] = REPO
    inputs["audit"]["repository"] = REPO
    audit = inputs["audit"]
    bridged = pub.bridge.bridge(**inputs)
    manifest = base.fixture()[0]
    return audit, bridged, manifest


def released(n, *, stem="v18.1"):
    return {"id": n, "tag_name": f"{stem}-windows.{n}", "draft": False}


def tagged(n, *, stem="v18.1"):
    return {"ref": f"refs/tags/{stem}-windows.{n}"}


def run_plan(mutator=None, *, releases=None, refs=None):
    audit, bridge, manifest = fixture()
    # The in-memory fixture bridge shares dicts with the mock signed audit.
    # Actual workflow artifacts are separate JSON files: model that boundary.
    bridge = deepcopy(bridge)
    if mutator:
        mutator(audit, bridge, manifest)
    return plan.plan(
        audit, bridge, manifest,
        [] if releases is None else releases,
        [] if refs is None else refs,
        repo=REPO, sha=SHA, run_id=RUN, attempt=1)


class TagProposalTests(unittest.TestCase):
    def test_new_and_existing_tag_sequence_not_publication(self):
        got = run_plan()
        self.assertEqual(got["releaseTagProposal"], "v18.1-windows.1")
        self.assertEqual(got["status"], "PROPOSED_TAG_NONPUBLISHING")
        self.assertIs(got["publicationAuthorized"], False)
        self.assertIs(got["publisherWriteEnabled"], False)
        self.assertTrue(got["requiresIndependentLiveRecheckAndAtomicTagReservation"])
        got = run_plan(releases=[released(1), released(3)],
                       refs=[tagged(1), tagged(3), tagged(4)])
        self.assertEqual(got["releaseTagProposal"], "v18.1-windows.5")
        self.assertEqual(got["existingSameVersionReleases"], 2)

    def test_old_upstream_version_tags_are_not_reissued_or_merged(self):
        r = [released(4, stem="v17.1"), released(1)]
        got = run_plan(releases=r, refs=[tagged(1)])
        self.assertEqual(got["releaseTagProposal"], "v18.1-windows.2")

    def test_pgbigm_uses_dated_upstream_tag_stem(self):
        audit, bridge, ext = fixture()
        ext["name"] = "pg_bigm"
        ext["upstream"] = {
            "repository": "pgbigm/pg_bigm",
            "ref": "v1.2-20250903", "version": "1.2",
            "commit": "b" * 40,
        }
        audit["repository"] = bridge["repository"] = "pgextwin/pg_bigm"
        got = plan.plan(audit, bridge, ext,
                        [released(1, stem="v1.2-20250903")],
                        [tagged(2, stem="v1.2-20250903")],
                        repo="pgextwin/pg_bigm", sha=SHA,
                        run_id=RUN, attempt=1)
        self.assertEqual(got["releaseTagProposal"], "v1.2-20250903-windows.3")

    def test_spoofed_bridge_event_and_source_rejected(self):
        mutations = (
            lambda a, b, e: a.update(mainMergeSha="f"*40),
            lambda a, b, e: a.update(signedArtifactsVerified=False),
            lambda a, b, e: a.update(cryptographicVerification="OFFLINE_MOCK"),
            lambda a, b, e: a.update(publicationAuthorized=True),
            lambda a, b, e: b.update(status="PUBLISH_ALLOW"),
            lambda a, b, e: b.update(publicationAuthorized=True),
            lambda a, b, e: b.update(publisherWriteEnabled=True),
            lambda a, b, e: b.update(runAttempt=2),
            lambda a, b, e: b.update(goB="GO"),
            lambda a, b, e: b.update(policyBlockers=[]),
            lambda a, b, e: e.update(name="pg_cron"),
            lambda a, b, e: e["upstream"].update(repository="untrusted/upstream"),
            lambda a, b, e: e["upstream"]["perPostgresql"]["18"].update(commit="NOT_SHA"),
        )
        for i, mutation in enumerate(mutations):
            with self.subTest(i=i), self.assertRaises(plan.Denied):
                run_plan(mutation)

    def test_blocking_grype_finding_rejects_tag_proposal_even_when_signed(self):
        for severity in ("High", "Critical", "Unknown"):
            with self.subTest(severity=severity):
                audit, bridged, manifest = fixture()
                entry = audit["grypePolicyByMajor"]["18"]
                entry["findingCountBySeverity"][severity] = 1
                entry["blockingFindingCount"] = 1
                entry["status"] = "BLOCKING_FINDINGS"
                bridged = pub.bridge.bridge(**dict(pub.fixture(), audit=audit,
                                                   repo=REPO))
                self.assertIn("BLOCKING_GRYPE_FINDINGS", bridged["policyBlockers"])
                with self.assertRaises(plan.Denied):
                    plan.plan(audit, bridged, manifest, [], [],
                              repo=REPO, sha=SHA, run_id=RUN, attempt=1)

    def test_divergent_signed_asset_evidence_and_scan_verdict_denied(self):
        changes = (
            lambda a, b: b["zipSha256ByMajor"].update({"18": "f" * 64}),
            lambda a, b: b["spdxSha256ByMajor"].pop("15"),
            lambda a, b: b["grypeSha256ByMajor"].update({"14": "f" * 64}),
            lambda a, b: b["grypePolicyByMajor"].pop("17"),
            lambda a, b: b.update(maintainedMajors=[14, 15, 16, 17]),
            lambda a, b: b["policyBlockers"].append("BLOCKING_GRYPE_FINDINGS"),
        )
        for i, change in enumerate(changes):
            with self.subTest(i=i):
                with self.assertRaises(plan.Denied):
                    run_plan(lambda a, b, m: change(a, b))

    def test_missing_ambiguous_and_partial_github_inventory_denied(self):
        for rel, ref in (
            ([released(1), released(1)], []),
            ([], [tagged(1), tagged(1)]),
            ([{**released(1), "id": True}], []),
            ([{**released(1), "draft": "false"}], []),
            ([released(1)], [{"ref": "refs/heads/main"}]),
            ([], [{"ref": "refs/tags/other-tag"}]),
            ([{"id": 1, "draft": False, "tag_name": "v18.1-windows.0"}], []),
            ([], [{"ref": "refs/tags/v18.1-windows.malicious"}]),
            ([released(i) for i in range(1, 101)], []),
            ([], [tagged(i) for i in range(1, 101)]),
        ):
            with self.subTest(rel=len(rel), refs=len(ref)), self.assertRaises(plan.Denied):
                run_plan(releases=rel, refs=ref)

    def test_readonly_http_error_never_means_empty_except_known_ref_404(self):
        class DummyResponse:
            status = 200
            def __init__(self, payload, link=""):
                self.payload = payload
                self.headers = {"Link": link}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, *args): return self.payload
        with patch.dict("os.environ", {"GH_TOKEN": "TEST_ONLY"}):
            with patch.object(plan, "urlopen", return_value=DummyResponse(b'[]')):
                self.assertEqual(plan.get_listing(REPO, "releases?per_page=100"), [])
            with patch.object(plan, "urlopen",
                              return_value=DummyResponse(b'[]', '<a>; rel="next"')):
                with self.assertRaises(plan.Denied):
                    plan.get_listing(REPO, "releases?per_page=100")
            with patch.object(plan, "urlopen",
                              side_effect=HTTPError("https://api.github.com", 404, "not found", {}, None)):
                self.assertEqual(
                    plan.get_listing(REPO, "git/matching-refs/tags/v18.1-windows.", allow_missing=True), [])
                with self.assertRaises(plan.Denied):
                    plan.get_listing(REPO, "releases?per_page=100", allow_missing=False)
            with patch.object(plan, "urlopen",
                              side_effect=HTTPError("https://api.github.com", 403, "denied", {}, None)):
                with self.assertRaises(plan.Denied):
                    plan.get_listing(REPO, "git/matching-refs/tags/v18.1-windows.",
                                     allow_missing=True)


if __name__ == "__main__":
    unittest.main()
