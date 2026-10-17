#!/usr/bin/env python3
"""Issue #75 hostile tests: nonpublishing SHA subgraph and Reader/Writer isolation."""
import copy
import importlib.util
from pathlib import Path
import re
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

graph = load("scripts/issue-75-transitive-dependency-delta.py", "issue75_delta")
probe = load("scripts/issue-75-reader-isolation-probe.py", "issue75_reader_probe")
def evidence():
    return graph.read_json(graph.DELTA)
def base():
    return graph.read_json(graph.BASE)
def check(d):
    return graph.inspect(d, base(), base_bytes=graph.BASE.read_bytes())

class DependencyAndReaderTests(TestCase):
    def test_32_plus_13_never_proves_full_closure(self):
        v = check(evidence())
        self.assertEqual((v["originalGitBlobs"], v["addedGitBlobs"],
                          v["totalGitBlobs"], v["dependencyEdges"],
                          v["unverifiedExternalDependencies"]),
                         (32, 13, 45, 54, 16))
        self.assertEqual(v["decision"],
                         "INTERNAL_BLOB_SUBGRAPH_RECORDED_EXTERNAL_INCOMPLETE")
        for key in ("readerTokenScopesVerified", "writerTokenIsolationVerified",
                    "signedPublisherPrewriteVerified", "publicationAuthorized",
                    "mutationAuthorized"):
            self.assertIs(v[key], False)
        self.assertEqual(v["goB"], "NO_GO")

    def test_missing_or_forged_sha_or_wrong_root_deny(self):
        cases = [
            lambda s: s["additionalGitBlobs"].pop("signer:scripts/install-syft.ps1"),
            lambda s: s["additionalGitBlobs"].update(
                **{"signer:scripts/install-syft.ps1": "0"*40}),
            lambda s: s["additionalGitBlobs"].update(
                **{"legacy:scripts/install-syft.ps1":
                   s["additionalGitBlobs"].pop("signer:scripts/install-syft.ps1")}),
            lambda s: s["baseline"].update(gitBlob="f"*40),
            lambda s: s["baseline"].update(rootNames=["pilot", "legacy", "current"]),
            lambda s: s["externalDependencies"].pop("ext:grype-db"),
        ]
        for mutation in cases:
            with self.subTest(case=str(mutation)):
                d = evidence()
                mutation(d)
                with self.assertRaises(graph.Deny):
                    check(d)

    def test_missing_or_poisoned_edge_and_cycles_deny(self):
        d = evidence()
        d["edges"].pop()
        with self.assertRaises(graph.Deny):
            check(d)
        d = evidence()
        d["edges"][0]["to"] = "ext:unreviewed-dynamic-hook"
        with self.assertRaises(graph.Deny):
            check(d)
        d = evidence()
        d["edges"][0] = copy.deepcopy(d["edges"][1])
        with self.assertRaises(graph.Deny):
            check(d)
        d = evidence()
        # Create a cycle and preserve cardinality; must reject independently.
        d["edges"][-1] = {
            "from": "signer:scripts/scan-vulnerabilities.ps1",
            "to": "signer:.github/workflows/build-extension-attested.yml"}
        with self.assertRaises(graph.Deny):
            check(d)

    def test_unpinned_external_action_and_floating_digests_deny(self):
        cases = [
            ("ext:actions/checkout", "pin", "v7"),
            ("ext:syft-zip", "pin", "0"*40),
            ("ext:grype-zip", "verification", "verified_bytes"),
            ("ext:python-jsonschema", "verification", "sha256_verified"),
            ("ext:windows-runner", "verification", "immutable_image"),
            ("ext:chocolatey-postgresql", "verification", "sha256_verified"),
            ("ext:python-meson-ninja", "pin", "meson>=1.8"),
        ]
        for key, field, new_value in cases:
            with self.subTest(key=key, field=field):
                d = evidence()
                d["externalDependencies"][key][field] = new_value
                with self.assertRaises(graph.Deny):
                    check(d)

    def test_reader_writer_signer_perimeter_and_mock_success_deny(self):
        changes = [
            lambda s: s["credentialBoundaries"]["reader"]["permissions"].append(
                "contents:write"),
            lambda s: s["credentialBoundaries"]["reader"].update(
                usesWriterCredential=True),
            lambda s: s["credentialBoundaries"]["writer"].update(
                tokenMintedThisStep=True),
            lambda s: s["credentialBoundaries"]["signer"]["permissions"].append(
                "contents:write"),
            lambda s: s["credentialBoundaries"]["signer"].update(
                checkoutPersistCredentials=False),
            lambda s: s["credentialBoundaries"].update(
                readerCheckoutPersistCredentials=True),
            lambda s: s["credentialBoundaries"].update(
                artifactLeakageRuntimeVerified=True),
            lambda s: s["acceptance"].update(liveSignedPublisherPrewrite=True),
            lambda s: s["acceptance"].update(goB="GO"),
            lambda s: s["knownUnresolved"].remove("noVerifiedReaderTokenScopes"),
        ]
        for mutation in changes:
            d = evidence()
            mutation(d)
            with self.assertRaises(graph.Deny):
                check(d)

    def test_reader_only_two_mock_gets_still_no_go(self):
        calls = []
        run = {"id": probe.CANDIDATE_RUN, "head_sha": probe.SHA,
               "head_branch": "auto-candidate/29d1c1984a1b44a55107",
               "path": ".github/workflows/windows.yml",
               "status": "completed", "conclusion": "success"}
        def get(path, **kw):
            calls.append((path, kw))
            return copy.deepcopy(run)
        args = {"repository": "pgextwin/build", "event": "pull_request",
                "head_ref": probe.PR_BRANCH, "job": "issue75_reader_probe",
                "run_id": "999", "attempt": "1"}
        v = probe.inspect(get, **args)
        self.assertEqual(len(calls), 2)
        self.assertEqual(v["decision"], "PR_READER_GET2_NEGATIVE_ONLY")
        self.assertFalse(v["tokenScopesVerified"])
        self.assertFalse(v["publicationAuthorized"])
        self.assertEqual(v["goB"], "NO_GO")
        for key, value in (
            ("job", "publish"), ("event", "workflow_dispatch"),
            ("repository", "pgextwin/plpgsql_check"),
            ("head_ref", "main")):
            a = dict(args)
            a[key] = value
            with self.assertRaises(probe.Deny):
                probe.inspect(get, **a)
        self.assertEqual(len(calls), 2)
        def race(path, **kw):
            calls.append(path)
            x = copy.deepcopy(run)
            if len(calls) % 2:
                x["conclusion"] = "failure"
            return x
        with self.assertRaises(probe.Deny):
            probe.inspect(race, **args)

    def test_reader_workflow_has_no_writer_or_artifact_escape(self):
        content = (ROOT / ".github/workflows/validate.yml").read_text()
        match = re.search(r"(?ms)^  issue75_reader_probe:\n(.*?)(?=^  [a-z_]+:\n|\Z)",
                          content)
        self.assertIsNotNone(match)
        job = match.group(1)
        self.assertIn("github.event_name == 'pull_request'", job)
        self.assertIn("github.head_ref == 'issue-75-transitive-closure-reader-isolation'", job)
        self.assertIn("actions: read", job)
        self.assertIn("contents: read", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("scripts/issue-75-reader-isolation-probe.py", job)
        for forbidden in ("contents: write", "id-token: write", "attestations: write",
                          "secrets.", "create-github-app-token", "upload-artifact",
                          "download-artifact", "workflow_dispatch", "gh release",
                          "gh workflow run", "echo $GH_TOKEN", "git push", "curl -X",
                          "GITHUB_TOKEN:"):
            self.assertNotIn(forbidden, job)

if __name__ == "__main__":
    main()
