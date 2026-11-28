#!/usr/bin/env python3
"""Offline live-binding fixtures. RFC test signing only; no production key."""

import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("local_auth_live", ROOT / "scripts/local-auth-live.py")
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
spec = importlib.util.spec_from_file_location(
    "foundation_fixtures", ROOT / "tests/test-verify-local-authorized-candidate.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
spec = importlib.util.spec_from_file_location(
    "local_auth_candidate", ROOT / "scripts/local-auth-candidate.py")
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)
issuance_transport = authority.load_script("local-auth-issuance")


def claim_file(claim):
    raw = live.verifier.canonical_json(claim)
    return {"type": "file", "path": "claim.json", "encoding": "base64", "size": len(raw),
            "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
            "content": base64.b64encode(raw).decode() + "\n"}


class LiveBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.TicketTests.setUpClass()

    def setUp(self):
        self.ticket = copy.deepcopy(fixtures.TicketTests.template_ticket)
        self.policy = copy.deepcopy(fixtures.TicketTests.template_policy)
        # Only the fixture key is used. Production key bytes are never available.
        self.policy["issuerKeyId"] = self.ticket["issuerKeyId"] = live.ISSUER_KEY_ID
        fixtures.sign_ticket(self.ticket)
        self.inputs = fixtures.TicketTests.inputs
        self.now = fixtures.TicketTests.now
        self.fleet = {self.ticket["repository"]}
        self.issuance = {
            "repository": live.ISSUER_REPOSITORY, "mainSha": "a" * 40,
            "workflowPath": live.ISSUER_WORKFLOW, "workflowId": 421122469,
            "runId": 44054867827, "claimCommitSha": "b" * 40,
            "requestId": self.ticket["requestId"],
            "ticketSha256": hashlib.sha256(live.verifier.canonical_json(self.ticket)).hexdigest(),
        }
        self.claim = {
            "requestId": self.ticket["requestId"], "ticketSha256": self.issuance["ticketSha256"],
            "issuerRepository": live.ISSUER_REPOSITORY, "issuerRunId": str(self.issuance["runId"]),
            "issuerRunAttempt": "1", "operation": "candidate", "recordedAt": "2026-11-17T12:00:00Z",
        }
        repository = {"id": 12345, "full_name": live.ISSUER_REPOSITORY, "default_branch": "main"}
        self.facts = {
            "repository": repository,
            "main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": "a" * 40}},
            "run": {"id": self.issuance["runId"], "repository": copy.deepcopy(repository),
                    "head_repository": copy.deepcopy(repository), "path": live.ISSUER_WORKFLOW,
                    "workflow_id": self.issuance["workflowId"], "run_attempt": 1,
                    "head_sha": "a" * 40, "head_branch": "main", "event": "workflow_dispatch",
                    "status": "completed", "conclusion": "success"},
            "workflow": {"id": self.issuance["workflowId"], "path": live.ISSUER_WORKFLOW},
            "claimRef": {"ref": "refs/claims/" + self.ticket["requestId"],
                         "object": {"type": "commit", "sha": "b" * 40}},
            "claimFile": claim_file(self.claim),
        }

    def verify(self, **kwargs):
        arguments = dict(ticket_obj=self.ticket, inputs_bytes=self.inputs, policy=self.policy,
                         fleet_repositories=self.fleet, now=self.now,
                         issuance_policy=self.issuance, facts=self.facts)
        arguments.update(kwargs)
        return live.verify_live_binding(**arguments)

    def rejected(self, code, **kwargs):
        with self.assertRaises(live.verifier.TicketRejected) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_positive_offline_evidence_has_no_authority_or_side_effects(self):
        before = copy.deepcopy((self.ticket, self.policy, self.issuance, self.facts))
        with patch("socket.socket", side_effect=AssertionError("network")), \
                patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                patch("builtins.open", side_effect=AssertionError("file write")):
            result = self.verify()
        self.assertEqual(result["status"], "VERIFIED_LIVE_BINDING_ONLY")
        self.assertIs(result["authorized"], False)
        self.assertIs(result["publication"], False)
        self.assertEqual(result["issuerRunId"], self.issuance["runId"])
        self.assertEqual(result["claimCommitSha"], self.issuance["claimCommitSha"])
        self.assertEqual(before, (self.ticket, self.policy, self.issuance, self.facts))

    def test_candidate_gate_matches_fresh_plan_and_live_issuance(self):
        self.policy["mode"] = "ENFORCE"
        with patch.object(authority.live, "fetch_live_facts", return_value=self.facts) as fetch:
            prepared = (self.policy, self.fleet, {"targetMainSha": self.ticket["targetMainSha"]},
                        self.inputs)
            authorize = lambda current: authority.authorize(
                self.ticket, self.inputs, self.issuance, current, now=self.now)
            self.assertEqual(authorize(prepared)["status"], "AUTHORIZED_CANDIDATE")
            self.assertFalse(authorize(prepared)["publication"])
            self.assertEqual(fetch.call_count, 2)
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "CANDIDATE_BINDING_MISMATCH"):
                authorize((*prepared[:3], b"{}"))
            self.facts["run"]["conclusion"] = "failure"
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "ISSUER_RUN_NOT_SUCCESSFUL"):
                authorize(prepared)
            self.policy["mode"] = "DENY"
            fetch.reset_mock()
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "DENY_MODE"):
                authorize(prepared)
            fetch.assert_not_called()

    def test_dispatch_uses_exact_run_and_checks_private_zip_bytes(self):
        ticket_raw = live.verifier.canonical_json(self.ticket)
        claim = {"status": "CLAIM_CREATED", "requestId": self.ticket["requestId"],
                 "ticketSha256": self.issuance["ticketSha256"],
                 "commit": self.issuance["claimCommitSha"]}
        stream = io.BytesIO()
        with ZipFile(stream, "w") as artifact_zip:
            artifact_zip.writestr("ticket.json", ticket_raw)
            artifact_zip.writestr("inputs.json", self.inputs)
            artifact_zip.writestr("claim-result.json", json.dumps(claim))
        artifact = stream.getvalue()
        prefix = issuance_transport.PREFIX
        workflow = prefix + "/actions/workflows/" + str(issuance_transport.WORKFLOW_ID)
        run = prefix + "/actions/runs/" + str(self.issuance["runId"])
        metadata = {"id": 1234, "size_in_bytes": len(artifact), "expired": False,
                    "workflow_run": {"id": self.issuance["runId"]},
                    "digest": "sha256:" + hashlib.sha256(artifact).hexdigest(),
                    "name": issuance_transport.ARTIFACT}
        responses = {
            workflow: {"path": live.ISSUER_WORKFLOW, "state": "active"},
            prefix + "/git/ref/heads/main": self.facts["main"],
            workflow + "/dispatches": {"workflow_run_id": self.issuance["runId"]},
            run: {"status": "completed", "conclusion": "success"},
            run + "/artifacts?per_page=100": {"total_count": 1, "artifacts": [metadata]},
            prefix + "/actions/artifacts/1234/zip": artifact,
        }

        def request(endpoint, *, payload=None):
            if payload is not None:
                self.assertEqual(endpoint, workflow + "/dispatches")
                self.assertEqual(payload["inputs"]["consumer_run_id"], "17")
            value = responses[endpoint]
            return value if type(value) is bytes else json.dumps(value).encode()

        with patch.dict("os.environ", {"LOCAL_AUTH_ISSUER_TOKEN": "offline"}), patch.object(
                issuance_transport, "request", side_effect=request):
            args = (self.ticket["repository"], self.ticket["targetMainSha"], 17, live.verifier)
            self.assertEqual(issuance_transport.receive(*args), (self.ticket, self.inputs, self.issuance))
            metadata["digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
                issuance_transport.receive(*args)

    def test_pgtap_license_is_compared_at_the_signed_source_commit(self):
        repository = "pgextwin/pgtap"
        upstream = "theory/pgtap"
        target_sha, upstream_sha = "1" * 40, "2" * 40
        entry = {"major": 17, "upstreamCommit": upstream_sha, "upstreamRef": "v1.3.4",
                 "upstreamVersion": "1.3.4", "licenseFiles": [
                     {"repositoryPath": "LICENSE", "upstreamPath": "README.md"}]}
        heading = b"Copyright and License\n---------------------\n\n"
        license_bytes = b"fixture license\n"
        files = {(upstream, "README.md", upstream_sha): b"About\n\n" + heading + license_bytes,
                 (repository, "LICENSE", target_sha): license_bytes}

        def read_file(fetch, repo, path, sha):
            raw = files[(repo, path, sha)]
            return {"path": path, "encoding": "base64", "size": len(raw),
                    "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                    "content": base64.b64encode(raw).decode()}

        with patch.object(authority, "build_matrix", return_value=("false", [entry])), patch.object(
                authority, "file_at", side_effect=read_file):
            args = ({"upstream": {"repository": upstream}}, repository, target_sha, None, self.now)
            sources = authority.versioned_sources(*args)
            self.assertEqual(sources[0]["licenses"][0]["sha256"], hashlib.sha256(license_bytes).hexdigest())
            files[(upstream, "README.md", upstream_sha)] += b"unexpected suffix\n"
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "VERSIONED_LICENSE_MISMATCH"):
                authority.versioned_sources(*args)

    def test_packaging_and_build_licenses_are_checked_at_target_sha(self):
        repository = "pgextwin/pldebugger"
        upstream = "EnterpriseDB/pldebugger"
        target_sha, upstream_sha = "1" * 40, "2" * 40
        readme_bytes = b"pldebugger README\n"
        pkg_license = b"Artistic License 2.0\n"
        build_notice = b"PostgreSQL License\n"
        pkg_sha = hashlib.sha256(pkg_license).hexdigest()
        build_sha = hashlib.sha256(build_notice).hexdigest()
        entry = {
            "major": 17,
            "upstreamCommit": upstream_sha,
            "upstreamRef": "v1.10",
            "upstreamVersion": "1.10",
            "licenseFiles": [
                {"repositoryPath": "README-pldebugger.md", "upstreamPath": "README-pldebugger.md"},
                {"origin": "packaging", "repositoryPath": "LICENSE", "sha256": pkg_sha},
                {
                    "origin": "build",
                    "repositoryPath": "licenses/COPYRIGHT.postgresql",
                    "generatedSource": "upstream",
                    "generatedPath": "POSTGRESQL-COPYRIGHT",
                    "sha256": build_sha,
                },
            ],
        }
        files = {
            (upstream, "README-pldebugger.md", upstream_sha): readme_bytes,
            (repository, "README-pldebugger.md", target_sha): readme_bytes,
            (repository, "LICENSE", target_sha): pkg_license,
            (repository, "licenses/COPYRIGHT.postgresql", target_sha): build_notice,
        }

        def read_file(fetch, repo, path, sha):
            raw = files[(repo, path, sha)]
            return {
                "path": path,
                "encoding": "base64",
                "size": len(raw),
                "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
                "content": base64.b64encode(raw).decode(),
            }

        with patch.object(authority, "build_matrix", return_value=("true", [entry])), patch.object(
                authority, "file_at", side_effect=read_file):
            args = ({"upstream": {"repository": upstream}}, repository, target_sha, None, self.now)
            sources = authority.versioned_sources(*args)
            self.assertEqual(len(sources[0]["licenses"]), 3)
            self.assertEqual(sources[0]["licenses"][1]["sha256"], pkg_sha)
            self.assertEqual(sources[0]["licenses"][2]["sha256"], build_sha)

            entry["licenseFiles"][1]["sha256"] = "0" * 64
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "VERSIONED_LICENSE_MISMATCH"):
                authority.versioned_sources(*args)
            entry["licenseFiles"][1]["sha256"] = pkg_sha

            files[(repository, "licenses/COPYRIGHT.postgresql", target_sha)] = b"Tampered\n"
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "VERSIONED_LICENSE_MISMATCH"):
                authority.versioned_sources(*args)

            entry["licenseFiles"] = [entry["licenseFiles"][1]]
            with self.assertRaisesRegex(authority.verifier.TicketRejected, "MISSING_VERSIONED_LICENSE"):
                authority.versioned_sources(*args)

    def test_policy_can_revoke_authority_without_issuer_changes(self):
        policy = json.loads((ROOT / "metadata/local-candidate-authority.json").read_text())
        deny = dict(policy, mode="DENY", delegationStartsAt=None, delegationEndsAt=None)
        self.assertIs(policy["publication"], False)
        with self.assertRaises(live.verifier.TicketRejected) as caught:
            live.verifier.authorize(self.ticket, self.inputs, deny, self.fleet, self.now)
        self.assertEqual(caught.exception.code, "DENY_MODE")
        self.rejected("DELEGATION_UNSET", policy=deny)

    def test_even_successful_binding_cannot_authorize_under_deny(self):
        self.policy["mode"] = "DENY"  # Test key/window only; not the real DENY policy.
        self.assertIs(self.verify()["authorized"], False)
        with self.assertRaises(live.verifier.TicketRejected) as caught:
            live.verifier.authorize(self.ticket, self.inputs, self.policy, self.fleet, self.now)
        self.assertEqual(caught.exception.code, "DENY_MODE")

    def test_wrong_expected_issuer_repository(self):
        self.issuance["repository"] = "pgextwin/build"
        self.rejected("ISSUER_REPOSITORY_MISMATCH")

    def test_wrong_live_issuer_repository(self):
        self.facts["repository"]["full_name"] = "attacker/local-auth-issuer"
        self.rejected("ISSUER_REPOSITORY_MISMATCH")

    def test_current_main_sha_mismatch(self):
        self.facts["main"]["object"]["sha"] = "c" * 40
        self.rejected("ISSUER_MAIN_MISMATCH")

    def test_wrong_key_id_rejected_by_la1(self):
        self.ticket["issuerKeyId"] = "local-auth-test-1"
        self.rejected("ISSUER_MISMATCH")

    def test_matching_nonproduction_key_id_is_rejected(self):
        self.policy["issuerKeyId"] = self.ticket["issuerKeyId"] = "local-auth-test-1"
        fixtures.sign_ticket(self.ticket)
        self.rejected("PINNED_KEY_MISMATCH")

    def test_wrong_epoch_rejected_by_la1(self):
        self.ticket["policyEpoch"] += 1
        self.rejected("EPOCH_MISMATCH")

    def test_signature_checked_before_any_fetch(self):
        self.ticket["signature"] = "0" * 128
        self.rejected("BAD_SIGNATURE", facts=None, api=lambda _: self.fail("must not fetch"))

    def test_inputs_checked_by_la1(self):
        self.rejected("INPUTS_HASH_MISMATCH", inputs_bytes=b"{}")

    def test_expired_ticket_checked_by_la1(self):
        self.rejected("EXPIRED", now=live.verifier._timestamp(self.ticket["expiresAt"]))

    def test_unknown_ticket_field_checked_by_la1(self):
        self.ticket["issuerMainSha"] = self.issuance["mainSha"]
        self.rejected("UNKNOWN_FIELD")

    def test_issuance_context_is_for_exact_ticket(self):
        for field, value in (("requestId", "c" * 32), ("ticketSha256", "c" * 64)):
            with self.subTest(field=field):
                issuance = dict(self.issuance, **{field: value})
                self.rejected("ISSUANCE_TICKET_MISMATCH", issuance_policy=issuance)

    def test_missing_or_malformed_context_never_inferred_from_live(self):
        for value in (None, {}, dict(self.issuance, runId=True),
                      dict(self.issuance, mainSha="main"), dict(self.issuance, unknown=1)):
            with self.subTest(value=value):
                self.rejected("INVALID_ISSUANCE_POLICY", issuance_policy=value)

    def test_wrong_run_repository_or_id(self):
        for field in ("repository", "head_repository"):
            for key, value in (("full_name", "attacker/issuer"), ("id", 54321)):
                with self.subTest(field=field, key=key):
                    facts = copy.deepcopy(self.facts)
                    facts["run"][field][key] = value
                    self.rejected("ISSUER_RUN_REPOSITORY_MISMATCH", facts=facts)

    def test_wrong_run_id(self):
        self.facts["run"]["id"] += 1
        self.rejected("ISSUER_RUN_MISMATCH")

    def test_run_attempt_must_be_integer_one(self):
        for attempt in (2, 0, "1", True, None):
            with self.subTest(attempt=attempt):
                self.facts["run"]["run_attempt"] = attempt
                self.rejected("ISSUER_RUN_ATTEMPT_MISMATCH")

    def test_run_main_context_mismatch(self):
        for key, value in (("head_branch", "feature"), ("head_sha", "c" * 40)):
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                facts["run"][key] = value
                self.rejected("ISSUER_RUN_MAIN_MISMATCH", facts=facts)

    def test_wrong_workflow_path_or_id(self):
        for section, key, value in (
                ("run", "path", ".github/workflows/other.yml"), ("run", "workflow_id", 1),
                ("workflow", "path", ".github/workflows/other.yml"), ("workflow", "id", 1)):
            with self.subTest(section=section, key=key):
                facts = copy.deepcopy(self.facts)
                facts[section][key] = value
                self.rejected("ISSUER_WORKFLOW_MISMATCH", facts=facts)
        self.issuance["workflowPath"] = ".github/workflows/other.yml"
        self.rejected("ISSUER_WORKFLOW_MISMATCH")

    def test_run_must_be_successful_main_dispatch(self):
        for key, value in (("event", "pull_request"), ("status", "in_progress"), ("conclusion", "failure")):
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                facts["run"][key] = value
                self.rejected("ISSUER_RUN_NOT_SUCCESSFUL", facts=facts)

    def test_missing_or_malformed_live_facts(self):
        for section in self.facts:
            with self.subTest(section=section):
                facts = copy.deepcopy(self.facts)
                del facts[section]
                self.rejected("INVALID_LIVE_FACTS", facts=facts)
        self.rejected("INVALID_LIVE_FACTS", facts=[])

    def test_claim_ref_must_match_exact_name_commit_and_type(self):
        for key, value in (("ref", "refs/claims/" + self.ticket["requestId"] + "0"),
                           ("sha", "c" * 40), ("type", "tag")):
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                target = facts["claimRef"] if key == "ref" else facts["claimRef"]["object"]
                target[key] = value
                self.rejected("CLAIM_REF_MISMATCH", facts=facts)

    def test_claim_contents_must_bind_ticket_request_and_issuer_run(self):
        for key, value in (("ticketSha256", "c" * 64), ("requestId", "c" * 32),
                           ("issuerRunId", "1"), ("issuerRunAttempt", "2"),
                           ("issuerRepository", "attacker/issuer"), ("operation", "publish")):
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                facts["claimFile"] = claim_file(dict(self.claim, **{key: value}))
                self.rejected("CLAIM_BINDING_MISMATCH", facts=facts)

    def test_claim_must_be_recorded_during_ticket_lifetime(self):
        for value in ("2026-11-17T11:58:59Z", self.ticket["expiresAt"]):
            with self.subTest(recordedAt=value):
                self.facts["claimFile"] = claim_file(dict(self.claim, recordedAt=value))
                self.rejected("CLAIM_TIME_MISMATCH")

    def test_claim_file_bytes_and_metadata_are_checked(self):
        for key, value in (("content", "!bad base64"), ("sha", "c" * 40),
                           ("size", 0), ("path", "other.json"), ("encoding", "none")):
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                facts["claimFile"][key] = value
                self.rejected("INVALID_CLAIM_FILE", facts=facts)

    def test_claim_json_must_be_canonical_without_duplicate_keys(self):
        canonical = live.verifier.canonical_json(self.claim)
        duplicate = canonical[:-1] + b',"operation":"candidate"}'
        for raw in (b" " + canonical, duplicate, b"null", b"{}"):
            with self.subTest(raw=raw):
                facts = copy.deepcopy(self.facts)
                facts["claimFile"].update(
                    content=base64.b64encode(raw).decode(), size=len(raw),
                    sha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
                code = "CLAIM_BINDING_MISMATCH" if raw in (b"null", b"{}") else "INVALID_CLAIM_FILE"
                self.rejected(code, facts=facts)

    def test_fetch_layer_uses_exact_fixed_repo_and_immutable_claim_locator(self):
        prefix = "repos/" + live.ISSUER_REPOSITORY
        endpoints = [prefix, prefix + "/git/ref/heads/main",
                     prefix + "/actions/runs/44054867827", prefix + "/actions/workflows/421122469",
                     prefix + "/git/ref/claims/" + self.ticket["requestId"],
                     prefix + "/contents/claim.json?ref=" + self.issuance["claimCommitSha"]]
        responses = dict(zip(endpoints, self.facts.values()))
        calls = []

        def api(endpoint):
            calls.append(endpoint)
            return copy.deepcopy(responses[endpoint])

        self.assertEqual(self.verify(facts=None, api=api)["status"], "VERIFIED_LIVE_BINDING_ONLY")
        self.assertEqual(calls, endpoints)

    def test_missing_claim_ref_fetch_fails_closed(self):
        def api(endpoint):
            if "/git/ref/claims/" in endpoint:
                raise live.verifier.TicketRejected("LIVE_FETCH_FAILED")
            return {}

        self.rejected("LIVE_FETCH_FAILED", facts=None, api=api)


class GithubGetTests(unittest.TestCase):
    def test_only_authenticated_get_and_no_debug_environment(self):
        response = SimpleNamespace(returncode=0, stdout=b'{"id":1}', stderr=b"")
        with patch.dict("os.environ", {"GH_DEBUG": "api"}), \
                patch.object(live.subprocess, "run", return_value=response) as run:
            self.assertEqual(live.github_get("repos/" + live.ISSUER_REPOSITORY), {"id": 1})
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["gh", "api", "--hostname", "github.com", "--method", "GET",
                                   "repos/" + live.ISSUER_REPOSITORY])
        self.assertNotIn("GH_DEBUG", kwargs["env"])
        self.assertEqual(kwargs["timeout"], 45)

    def test_api_failures_and_malformed_responses_never_succeed(self):
        for response in (SimpleNamespace(returncode=1, stdout=b"", stderr=b"private error"),
                         SimpleNamespace(returncode=0, stdout=b"[]"),
                         SimpleNamespace(returncode=0, stdout=b"not JSON"),
                         SimpleNamespace(returncode=0, stdout=b'{"id":1,"id":2}'),
                         SimpleNamespace(returncode=0, stdout=b"\xff"),
                         SimpleNamespace(returncode=0, stdout=b"x" * (live.MAX_FACT_BYTES + 1))):
            with self.subTest(response=str(response)[:80]), \
                    patch.object(live.subprocess, "run", return_value=response), \
                    self.assertRaises(live.verifier.TicketRejected):
                live.github_get("repos/" + live.ISSUER_REPOSITORY)
        for error in (OSError(), subprocess.TimeoutExpired("gh", 45)):
            with self.subTest(error=type(error)), \
                    patch.object(live.subprocess, "run", side_effect=error), \
                    self.assertRaises(live.verifier.TicketRejected) as caught:
                live.github_get("repos/" + live.ISSUER_REPOSITORY)
            self.assertEqual(caught.exception.code, "LIVE_FETCH_FAILED")

    def test_arbitrary_urls_repos_and_matching_ref_lists_are_denied_before_subprocess(self):
        for endpoint in ("https://example.com", "repos/attacker/issuer",
                         "repos/pgextwin/local-auth-issuer/git/matching-refs/claims/abc",
                         "repos/pgextwin/local-auth-issuer/contents/claim.json?ref=main", None):
            with self.subTest(endpoint=endpoint), \
                    patch.object(live.subprocess, "run", side_effect=AssertionError("must not fetch")), \
                    self.assertRaises(live.verifier.TicketRejected) as caught:
                live.github_get(endpoint)
            self.assertEqual(caught.exception.code, "LIVE_ENDPOINT_DENIED")


class CentralCandidateBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.TicketTests.setUpClass()

    def setUp(self):
        LiveBindingTests.setUp(self)
        self.policy["mode"] = "ENFORCE"
        self.sha = "a" * 40
        self.extension = "pg_ivm"
        self.legacy_repo = f"pgextwin/{self.extension}"
        self.manifest = f"extensions/{self.extension}/extension.json"
        self.changes = [{"filename": self.manifest, "status": "modified"}]
        self.config = {
            "name": self.extension, "postgresql": {"majors": [17, 18]},
            "upstream": {"repository": "sraoss/pg_ivm", "ref": "v1.17", "version": "1.17", "commit": "e" * 40},
            "watch": {"source": "github", "strategy": "github-releases", "prereleases": False,
                      "stableTagPattern": r"^v(?P<version>\d+\.\d+)$"},
        }
        self.registry = json.loads((ROOT / authority.MANIFEST).read_text(encoding="utf-8"))
        row = next(row for row in self.registry["entries"] if row["repository"] == self.legacy_repo)
        self.registry["entries"].append(dict(row, repository=authority.BUILD))
        self.upstream_sha = "c" * 40
        self.license_bytes = b"fixture version-specific license\n"
        self.license_mapping = {"repositoryPath": "LICENSE.txt", "upstreamPath": "LICENSE"}
        self.sources = [{"major": 17, "ref": "v1.18", "version": "1.18", "commit": self.upstream_sha,
                         "licenses": [dict(self.license_mapping, sha256=hashlib.sha256(self.license_bytes).hexdigest())]}]
        self.run_id = 100
        self.consumer_run_status = "in_progress"
        self.calls = []
        self.enterContext(patch.object(authority.candidate, "execute", return_value=self.sha))
        self.matrix = self.enterContext(patch.object(authority, "build_matrix", return_value=(
            "true", [{"major": 17, "upstreamRef": "v1.18", "upstreamVersion": "1.18",
                      "upstreamCommit": self.upstream_sha, "licenseFiles": [self.license_mapping]}])))
        self.fetch_live = self.enterContext(patch.object(authority.live, "fetch_live_facts", return_value=self.facts))

    @staticmethod
    def content(path, data):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        return {"path": path, "encoding": "base64", "content": base64.b64encode(raw).decode(),
                "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()}

    def fetch(self, url):
        self.calls.append(url)
        repo = self.repository
        api = authority.API
        if url in (f"{api}{authority.BUILD}/branches/main", f"{api}{repo}/branches/main"):
            return {"name": "main", "protected": True, "commit": {"sha": self.sha}}
        if url == api + repo:
            return {"full_name": repo, "default_branch": "main", "id": 12345}
        if url == f"{api}{authority.BUILD}/actions/runs/{self.run_id}":
            identity = {"full_name": authority.BUILD}
            return {"id": self.run_id, "head_sha": self.sha, "head_branch": "main", "event": "schedule",
                    "path": authority.WATCH_WORKFLOW, "run_attempt": 1, "status": self.consumer_run_status,
                    "repository": identity, "head_repository": identity}
        upstream = api + self.config["upstream"]["repository"]
        if url == upstream + "/releases?per_page=100":
            return [{"tag_name": "v1.18", "draft": False, "prerelease": False}]
        if url == upstream + "/git/ref/tags/v1.18":
            return {"object": {"type": "commit", "sha": self.upstream_sha}}
        if url == f"{upstream}/contents/LICENSE?ref={self.upstream_sha}":
            return self.content("LICENSE", self.license_bytes)
        contents = {
            (authority.BUILD, authority.AUTHORITY): self.policy,
            (authority.BUILD, authority.MANIFEST): self.registry,
            (repo, self.manifest if repo == authority.BUILD else authority.EXTENSION): self.config,
            (repo, "LICENSE.txt"): self.license_bytes,
        }
        if repo != authority.BUILD:
            contents[(repo, authority.LEGACY_WATCH)] = {
                **self.config["watch"], "schemaVersion": 1, "repository": self.config["upstream"]["repository"]}
        for (name, path), value in contents.items():
            if url == f"{api}{name}/contents/{path}?ref={self.sha}":
                return self.content(path, value)
        self.fail(f"unexpected fetch {url}")

    def prepare(self, **kwargs):
        self.repository = authority.BUILD
        return authority.prepare(self.repository, self.sha, self.run_id, fetch=self.fetch, now=self.now,
                                 extension=self.extension, **kwargs)

    def sign(self, bindings, inputs):
        self.ticket.update(bindings, inputsSha256=hashlib.sha256(inputs).hexdigest())
        fixtures.sign_ticket(self.ticket)
        digest = hashlib.sha256(authority.verifier.canonical_json(self.ticket)).hexdigest()
        self.issuance["ticketSha256"] = self.claim["ticketSha256"] = digest
        self.facts["claimFile"] = claim_file(self.claim)

    def authorize(self, prepared, *, inputs=None, **kwargs):
        return authority.authorize(self.ticket, prepared[3] if inputs is None else inputs,
                                   self.issuance, prepared, now=self.now, **kwargs)

    def rejected(self, code, action):
        with self.assertRaises(authority.verifier.TicketRejected) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_tc15_central_prepare_authorize_binds_manifest_run_and_claim(self):
        prepared = self.prepare()
        _, _, bindings, raw = prepared
        inputs = json.loads(raw)
        self.assertEqual(bindings["manifestBlob"], self.content(self.manifest, self.config)["sha"])
        self.assertEqual(inputs["sources"], self.sources)
        self.assertEqual(inputs["centralScope"], {
            "extension": self.extension, "manifestPath": self.manifest, "branch": inputs["plan"]["branch"],
            "allowedPaths": [self.manifest], "operation": "candidate", "publication": False,
        })
        self.assertFalse(any("/contents/config/" in url for url in self.calls))
        self.sign(bindings, raw)
        result = self.authorize(prepared, changes=self.changes)
        self.assertEqual(result["status"], "AUTHORIZED_CANDIDATE")
        self.assertIs(result["authorized"], True)
        self.assertIs(result["publication"], False)
        binding = result["centralBinding"]
        self.assertIs(binding["ticket"], self.ticket)
        self.assertEqual(binding["inputs_obj"], inputs)
        self.assertEqual(binding["consumer_run_id"], self.run_id)
        self.assertIs(binding["live_evidence"]["authorized"], False)
        central = result["centralEvidence"]
        self.assertEqual(central, {
            "schemaVersion": 1, "status": "AUTHORIZED_CENTRAL_CANDIDATE", "authorized": True,
            "publication": False, "operation": "candidate", "repository": authority.BUILD,
            "policy": {key: self.policy[key] for key in ("mode", "policyEpoch", "issuerKeyId")},
            "consumerRun": {"repository": authority.BUILD, "runId": self.run_id},
            "issuerRun": {"repository": self.issuance["repository"], "runId": self.issuance["runId"], "attempt": 1},
            "claim": {key: self.issuance[key] for key in ("requestId", "claimCommitSha", "ticketSha256")},
            "target": {"extension": self.extension, "branch": inputs["plan"]["branch"],
                       "scopeMode": "candidate_manifest", "paths": [self.manifest], "pathClasses": ["P1"]},
        })

    def test_tc15_deny_short_circuits_live_fact_fetch(self):
        prepared = self.prepare()
        denied = (dict(prepared[0], mode="DENY"), *prepared[1:])
        self.rejected("DENY_MODE", lambda: self.authorize(denied, inputs=b"{}"))
        self.fetch_live.assert_not_called()

    def test_tc15_central_prepare_rejects_invalid_scope_before_license_reads(self):
        self.rejected("CROSS_EXTENSION_DENIED", lambda: self.prepare(changes=[
            {"filename": "extensions/pg_bigm/extension.json", "status": "modified"}]))
        self.matrix.assert_not_called()
        for extension in (None, "COM1", "../pg_ivm"):
            self.rejected("INVALID_CENTRAL_EXTENSION", lambda: authority.prepare(
                authority.BUILD, self.sha, self.run_id, fetch=self.fetch, now=self.now, extension=extension))

    def test_tc15_prepare_p7_precedes_invalid_consumer_run(self):
        self.consumer_run_status = "completed"
        consumer_run_url = f"{authority.API}{authority.BUILD}/actions/runs/{self.run_id}"
        self.rejected("PATH_CLASS_P7_DENIED", lambda: self.prepare(changes=[
            {"filename": "README.md", "status": "modified"}]))
        self.assertEqual(self.calls.count(consumer_run_url), 0)
        self.matrix.assert_not_called()

    def test_tc15_authorize_epoch_then_p7_precede_tampered_claim_ref(self):
        prepared = self.prepare()
        self.sign(prepared[2], prepared[3])
        changes = [{"filename": "README.md", "status": "modified"}]
        revoked = (dict(self.policy, policyEpoch=2, revokedPolicyEpochs=[1]), *prepared[1:])
        with patch.dict(self.facts["claimRef"]["object"], {"sha": "f" * 40}):
            self.rejected("PATH_CLASS_P7_DENIED", lambda: self.authorize(prepared, changes=changes))
            self.rejected("EPOCH_REVOKED", lambda: self.authorize(revoked, changes=changes))
        self.fetch_live.assert_not_called()

    def test_tc15_authorize_missing_prepared_plan_rejects_before_live_fetch(self):
        prepared = self.prepare()
        inputs = json.loads(prepared[3])
        del inputs["plan"]
        raw = authority.verifier.canonical_json(inputs)
        self.sign(prepared[2], raw)
        self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH", lambda: self.authorize((*prepared[:3], raw)))
        self.fetch_live.assert_not_called()

    def test_tc15_bad_epoch_claim_ref_or_issuer_run_is_rejected(self):
        prepared = self.prepare()
        self.sign(prepared[2], prepared[3])
        self.rejected("EPOCH_MISMATCH", lambda: self.authorize((dict(self.policy, policyEpoch=2), *prepared[1:])))
        self.rejected("EPOCH_REVOKED", lambda: self.authorize(
            (dict(self.policy, policyEpoch=2, revokedPolicyEpochs=[1]), *prepared[1:])))
        self.fetch_live.assert_not_called()
        with patch.dict(self.facts["claimRef"]["object"], {"sha": "f" * 40}):
            self.rejected("CLAIM_REF_MISMATCH", lambda: self.authorize(prepared))
        with patch.dict(self.facts["run"], {"id": self.issuance["runId"] + 1}):
            self.rejected("ISSUER_RUN_MISMATCH", lambda: self.authorize(prepared))

    def test_tc15_signed_scope_inputs_and_actual_changes_must_agree(self):
        prepared = self.prepare()
        bindings, raw = prepared[2:]
        self.sign(bindings, raw)
        for code, changes in (
            ("CROSS_EXTENSION_DENIED", [{"filename": "extensions/pg_bigm/extension.json", "status": "modified"}]),
            ("PATH_CLASS_P7_DENIED", [{"filename": "README.md", "status": "modified"}]),
            ("CANDIDATE_CHANGE_DENIED", [{"filename": self.manifest, "status": "renamed",
                                         "previous_filename": f"extensions/{self.extension}/old.json"}]),
        ):
            with self.subTest(code=code):
                self.rejected(code, lambda: self.authorize(prepared, changes=changes))

        for field, value in (("extension", "pg_bigm"), ("branch", "auto-candidate/" + "a" * 20),
                             ("allowedPaths", [self.manifest, "README.md"]), ("publication", 0)):
            with self.subTest(field=field):
                inputs = json.loads(raw)
                inputs["centralScope"][field] = value
                modified = authority.verifier.canonical_json(inputs)
                self.rejected("INPUTS_HASH_MISMATCH", lambda: self.authorize(prepared, inputs=modified))
                self.sign(bindings, modified)
                self.rejected("CANDIDATE_BINDING_MISMATCH", lambda: self.authorize(prepared, inputs=modified))
                self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH",
                              lambda: self.authorize((*prepared[:3], modified)))
                self.sign(bindings, raw)

        inputs = dict(json.loads(raw), consumerRunId=self.run_id + 1)
        modified = authority.verifier.canonical_json(inputs)
        self.sign(bindings, modified)
        self.rejected("CANDIDATE_BINDING_MISMATCH", lambda: self.authorize(prepared, inputs=modified))

    def test_tc15_legacy_extensionless_prepare_preserves_canonical_contract(self):
        self.repository = self.legacy_repo
        prepared = authority.prepare(self.repository, self.sha, self.run_id, fetch=self.fetch, now=self.now)
        _, _, bindings, raw = prepared
        plan = authority.candidate.plan(self.config, None, {"schemaVersion": 1, "enabled": True,
                                        "releasePolicy": "manual-only", "workflow": "windows.yml"}, fetch=self.fetch)
        expected_inputs = {"operation": "candidate", "consumerRunId": self.run_id, "repository": self.repository,
                           "plan": {key: value for key, value in plan.items() if key != "detectedAt"},
                           "sources": self.sources}
        canonical = authority.verifier.canonical_json
        self.assertEqual(raw, canonical(expected_inputs))
        self.assertEqual(bindings, {
            "operation": "candidate", "repository": self.repository, "repositoryId": 12345,
            "targetMainSha": self.sha, "policySha": self.sha, "centralMainSha": self.sha, "verifierSha": self.sha,
            "manifestBlob": self.content(authority.MANIFEST, self.registry)["sha"],
            "upstreamSourcesSha256": hashlib.sha256(canonical(self.sources)).hexdigest(),
            "issuerKeyId": self.policy["issuerKeyId"], "policyEpoch": self.policy["policyEpoch"],
        })
        self.sign(bindings, raw)
        result = self.authorize(prepared)
        self.assertNotIn("centralEvidence", result)
        self.assertNotIn("centralBinding", result)
        self.assertEqual(result["status"], "AUTHORIZED_CANDIDATE")


if __name__ == "__main__":
    unittest.main()
