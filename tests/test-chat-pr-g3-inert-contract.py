#!/usr/bin/env python3
"""Issue #75 G3 end-to-end *offline-only* fail-closed contracts.

No live GitHub API, publisher invocation, token, authorization PR or Release.
"""
from __future__ import annotations
from copy import deepcopy
import importlib.util
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


g3 = load("issue75_g3_test", "scripts/chat-pr-g3-inert-contract.py")
phase = load("issue75_g3_phase_case", "tests/test-chat-pr-phase-d-prepublish.py")
pair = load("issue75_g3_pair_case", "tests/test-chat-pr-phase-c-join.py")
approval_case = load("issue75_g3_approval_case", "tests/test-chat-pr-authorization.py")
atomic_case = load("issue75_g3_atomic_case", "tests/test-chat-pr-phase-d-atomic-replay.py")
receipt_case = load("issue75_g3_receipt_case", "tests/test-release-authorization.py")


def fixture():
    candidate_input, auth_input = pair.paired_fixtures()
    github, raw = approval_case.committed_fixture(auth_input)
    candidate = pair.gate_case.gate.verify(**candidate_input)
    source = dict(candidate["sources"][-1],
                  repository=candidate_input["ext"]["upstream"]["repository"])
    run = {
        "id": 505, "run_attempt": 1, "event": "push",
        "head_branch": "main", "head_sha": approval_case.AFTER,
        "status": "completed", "conclusion": "success",
    }
    package = {
        "buildMode": "release-attested",
        "package": {"name": "plpgsql_check"},
        "postgresql": {"major": candidate["majors"][-1]},
        "upstream": deepcopy(source),
        "source": {
            "packagingRepository": "pgextwin/plpgsql_check",
            "packagingCommit": approval_case.AFTER},
        "workflowRun": {
            "id": run["id"], "attempt": run["run_attempt"],
            "event": "push", "ref": "refs/heads/main"},
    }
    return {
        "central": dict(candidate_input["policy"], releasePolicy="manual-dispatch"),
        "local": dict(candidate_input["local"], releasePolicy="manual-dispatch"),
        "fleet": deepcopy(candidate_input["fleet"]),
        "raw_authorization": raw,
        "github_approval": github,
        "candidate_receipt": candidate,
        "jit_reader": phase.FakeReader(phase.snapshot()),
        "package_info": package,
        "package_run": run,
        "package_source": source,
    }


def check(case):
    return g3.verify_inert_g3(**case)


class G3InertTests(TestCase):
    def test_coherent_future_typed_tuple_is_still_denied(self):
        case = fixture()
        result = check(case)
        self.assertEqual(case["jit_reader"].calls, 2)
        self.assertEqual(result["status"], "DRY_RUN_G3_DEFAULT_DENY_ONLY")
        self.assertEqual(result["futureReceiptType"], "VERIFIED_CHAT_PR_AUTHORIZATION")
        self.assertEqual(result["futureEventShape"], "push")
        self.assertEqual(result["syntheticPackageMajor"], 18)
        self.assertEqual(result["jitSnapshotCount"], 2)
        self.assertEqual(result["publication"], "DENY")
        for field in ("signedArtifactsVerified", "publishableReceipt",
                      "publishingEnabled", "mutationsEnabled"):
            self.assertIs(result[field], False)
        with self.assertRaises(g3.receipt_lib.Denied):
            g3.receipt_lib.validate_receipt(
                result, repository="pgextwin/plpgsql_check",
                commit=approval_case.AFTER, actor="HumanOperator", event="push")

    def test_manual_only_modes_cannot_be_switched_for_g3(self):
        bad = [
            ("central", lambda x: x.update(releasePolicy="chat-pr-authorization")),
            ("central", lambda x: x.update(allowedRepositories=[])),
            ("local", lambda x: x.update(releasePolicy="chat-pr-authorization")),
            ("local", lambda x: x.update(enabled=False)),
            ("fleet", lambda x: x.update(releasePolicy="automatic")),
            ("fleet", lambda x: x["entries"][0].update(releasePolicy="automatic")),
        ]
        for k, change in bad:
            with self.subTest(case=k, change=change):
                case = fixture()
                change(case[k])
                with self.assertRaises(g3.Denied):
                    check(case)

    def test_actor_pr_commit_candidate_and_required_ci_denials(self):
        bad = [
            lambda x: x["github_approval"]["event"]["sender"].update(login="github-actions[bot]"),
            lambda x: x["github_approval"]["event"].update(before="0" * 40),
            lambda x: x["github_approval"]["event"].update(ref="refs/heads/other"),
            lambda x: x["github_approval"]["event"].update(after="0" * 40),
            lambda x: x["github_approval"]["commit"]["parents"].append({"sha": "0" * 40}),
            lambda x: x["github_approval"]["commit"]["files"].append(
                {"filename": "config/release-promotion.json", "status": "modified"}),
            lambda x: x["github_approval"]["pr"].update(merged=False),
            lambda x: x["github_approval"]["pr"]["merged_by"].update(login="intruder"),
            lambda x: x["github_approval"]["pr_files"].append(
                {"filename": ".github/workflows/promote.yml", "status": "added"}),
            lambda x: x["github_approval"]["ci"].update(headSha="0" * 40),
            lambda x: x["github_approval"]["ci"].update(allRequiredChecksPassed=False),
            lambda x: x["github_approval"]["effective_rules"].update(requiredChecksEnforced=False),
            lambda x: x["candidate_receipt"].update(candidatePr=999),
            lambda x: x["candidate_receipt"].update(candidateHeadSha="0" * 40),
            lambda x: x["candidate_receipt"].update(candidateRunId=10),
            lambda x: x["candidate_receipt"].update(decisionRunId=10),
            lambda x: x["candidate_receipt"].update(status="VERIFIED_MANUAL_DISPATCH"),
        ]
        for i, mutate in enumerate(bad):
            case = fixture()
            mutate(case)
            with self.subTest(index=i), self.assertRaises(g3.Denied):
                check(case)

    def test_wrong_package_info_build_run_and_source_denied(self):
        bad = [
            ("package_info", lambda x: x.update(buildMode="normal")),
            ("package_info", lambda x: x["package"].update(name="wal2json")),
            ("package_info", lambda x: x["postgresql"].update(major=20)),
            ("package_info", lambda x: x["source"].update(packagingCommit="0" * 40)),
            ("package_info", lambda x: x["source"].update(packagingRepository="evil/fork")),
            ("package_info", lambda x: x["upstream"].update(commit="0" * 40)),
            ("package_info", lambda x: x["upstream"].update(version="other")),
            ("package_info", lambda x: x["workflowRun"].update(event="workflow_dispatch")),
            ("package_info", lambda x: x["workflowRun"].update(ref="refs/heads/other")),
            ("package_info", lambda x: x["workflowRun"].update(id=999)),
            ("package_info", lambda x: x["workflowRun"].update(attempt=2)),
            ("package_run", lambda x: x.update(event="pull_request")),
            ("package_run", lambda x: x.update(conclusion="skipped")),
            ("package_run", lambda x: x.update(head_sha="0" * 40)),
            ("package_run", lambda x: x.update(run_attempt=2)),
            ("package_source", lambda x: x.update(commit="0" * 40)),
            ("package_source", lambda x: x.update(ref="untrusted")),
            ("candidate_receipt", lambda x: x.update(majors=[15, 16])),
            ("candidate_receipt", lambda x: x.update(sources=[])),
        ]
        for k, mut in bad:
            case = fixture()
            mut(case[k])
            with self.subTest(index=k, mutation=str(mut)), self.assertRaises(g3.Denied):
                check(case)

    def test_second_snapshot_toctou_and_auth_or_signature_invention(self):
        first = phase.snapshot()
        for mutation in (
            lambda second: second.update(mainSha="0" * 40),
            lambda second: second.update(tagRef="EXISTS"),
            lambda second: second.update(release="UNKNOWN"),
            lambda second: second["classicComposite"].update(strict=False),
            lambda second: second["candidateReceipt"].update(candidateRunId=12),
            lambda second: second.update(artifactSignatures="SIGNATURE_ASSERTED"),
        ):
            case = fixture()
            second = deepcopy(first)
            mutation(second)
            case["jit_reader"] = phase.FakeReader(first, second)
            with self.subTest(mutation=str(mutation)), self.assertRaises(g3.Denied):
                check(case)
        class FailedReader:
            calls = 0
            def capture(self):
                self.calls += 1
                raise TimeoutError("simulated API timeout")
        case = fixture()
        case["jit_reader"] = FailedReader()
        # Phase D deliberately propagates failures from a future live reader;
        # an unverified failure must never become a success record.
        with self.assertRaises((g3.Denied, TimeoutError)):
            check(case)

    def test_earlier_atomic_replay_and_draft_simulations_remain_inert(self):
        # Existing Phase D simulates exactly one winner, 422 loser, replay
        # rejection and partial Draft/Release ID quarantine with NO live IO.
        suite = atomic_case.AtomicReplayTests()
        for name in (
            "test_preflight_get_absence_is_not_atomic_post_422_wins",
            "test_partial_draft_failure_quarantines_existing_tag_and_draft",
            "test_release_id_or_draft_state_mismatch_never_patches",
        ):
            with self.subTest(name=name):
                getattr(suite, name)()

    def test_no_network_or_publisher_entrypoint_in_g3_module(self):
        text = (ROOT / "scripts/chat-pr-g3-inert-contract.py").read_text()
        for forbidden in ("urlopen(", "Request(", "subprocess", "gh release",
                          "git/refs", "workflow_dispatch:", "def main(",
                          "publishingEnabled=True", "publishableReceipt=true",
                          "def publish("):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    main()
