#!/usr/bin/env python3
"""Exercise App candidate origin joining with GitHub-shaped read-only fixtures."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location(Path(path).stem, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


origin = load("scripts/fleet_candidate_origin.py")
native_fixture = load("tests/test-native-pr-candidate-audit.py")
merge_fixture = load("tests/test-automatic-postmerge-audit-bridge.py")
intent_fixture = load("tests/test-automatic-signed-build-intent-live.py")
requal_fixture = load("tests/test-merged-candidate-requalification.py")
binder_fixture = load("tests/test-bind-native-candidate-audit-live.py")
sys.path.insert(0, str(ROOT / "scripts"))
fleet_status = load("scripts/fleet-status.py")
REPO = "pgextwin/pg_ivm"
CENTRAL_REPO = "pgextwin/build"
BUILD = "repos/pgextwin/build/"
RUN = BUILD + "actions/runs/100"
JOBS = RUN + "/attempts/1/jobs?per_page=100"
ARTIFACTS = RUN + "/artifacts?per_page=100"
START = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
BUILD_SHA = "9" * 40
APP = "apps/" + origin.APP["slug"]
EXTENSION = {"name": "pg_ivm", "upstream": {"repository": "sraoss/pg_ivm",
                                          "ref": "v1.17", "version": "1.17", "commit": "8" * 40}}


def timestamp(minute):
    return (START + timedelta(minutes=minute)).isoformat()


def collection(key, *rows):
    return {"total_count": len(rows), key: list(rows)}


class Evidence:
    def __init__(self, pr, repo=REPO, extension=EXTENSION, base=None):
        self.repo = repo
        self.pr = pr
        slug = repo.split("/")[1]
        head = pr["head"]["sha"]
        base = base or pr["base"]["sha"]
        repo_id = 1406488805
        for entry in (pr["head"], pr["base"]):
            entry["repo"] = {"full_name": repo, "id": repo_id}
        pr.update(user={"type": "Bot", "id": origin.APP["botUserId"], "login": origin.BOT},
                  created_at=timestamp(7))
        raw = json.dumps(extension).encode()
        self.blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        source = {"path": origin.MANIFEST, "encoding": "base64", "sha": self.blob,
                  "content": base64.b64encode(raw).decode("ascii")}
        upstream = extension["upstream"]
        self.record = {"schemaVersion": 1, "repository": repo, "repositoryId": repo_id,
                       "appId": origin.APP["appId"], "botUserId": origin.APP["botUserId"],
                       "runId": 100, "runAttempt": 1, "runSha": BUILD_SHA, "decisionArtifactId": 44,
                       "baseSha": base, "headSha": head, "manifestBlob": self.blob,
                       "decision": {"schemaVersion": 1, "extension": extension["name"], "status": "candidate",
                                    "repository": upstream["repository"], "releasePolicy": "manual-only",
                                    "candidateId": origin.candidate_branch.parse_branch(pr["head"]["ref"]).candidate_id,
                                    "branch": pr["head"]["ref"],
                                    "updates": [{"major": None, "ref": upstream["ref"],
                                                 "version": upstream["version"], "commit": upstream["commit"],
                                                 "initialOnly": False, "pinOnly": False}]}}
        self.legacy_marker = f"<!-- pgextwin-candidate:v1:{self.record['decision']['candidateId']} -->"
        build_id = origin.APP["buildRepositoryId"]
        repository = {"full_name": origin.BUILD, "id": build_id}
        job = {"run_id": 100, "run_attempt": 1, "head_sha": BUILD_SHA,
               "status": "completed", "conclusion": "success"}
        workflow_run = {"id": 100, "repository_id": build_id, "head_repository_id": build_id,
                        "head_branch": "main", "head_sha": BUILD_SHA}
        artifact = {"workflow_run": workflow_run, "expired": False, "digest": "sha256:" + "a"*64,
                    "size_in_bytes": 500}
        target = "repos/" + repo + "/"
        merge = pr.get("merge_commit_sha")
        files = [{"filename": origin.MANIFEST, "status": "modified", "sha": self.blob}]
        self.reads = {
            APP: {"id": origin.APP["appId"], "slug": origin.APP["slug"], "owner": {"login": "pgextwin"}},
            RUN: {"id": 100, "path": origin.WATCH, "run_attempt": 1, "status": "completed",
                  "conclusion": "success", "event": "schedule", "head_branch": "main",
                  "head_sha": BUILD_SHA, "repository": repository, "head_repository": repository,
                  "created_at": timestamp(0)},
            BUILD + "branches/main": {"name": "main", "protected": True, "commit": {"sha": BUILD_SHA}},
            JOBS: collection("jobs", dict(job, name="readonly-fleet", completed_at=timestamp(2)),
                             dict(job, name="candidate-preparation (any matrix) / propose / Bind fleet candidate " + slug,
                                  started_at=timestamp(5), completed_at=timestamp(11),
                                  steps=[{"name": origin.UPLOAD_STEP, "status": "completed",
                                          "conclusion": "success", "started_at": timestamp(8),
                                          "completed_at": timestamp(10)}])),
            ARTIFACTS: collection("artifacts",
                                  dict(artifact, id=44, name="candidate-decision-" + slug, created_at=timestamp(4)),
                                  dict(artifact, id=45, created_at=timestamp(9))),
            target + "branches/main": {"name": "main", "protected": True,
                                       "commit": {"sha": merge if pr.get("merged") else base}},
            target + "commits/" + head: {"sha": head, "parents": [{"sha": base}], "files": files},
            target + "contents/" + origin.MANIFEST + "?ref=" + head: source,
        }
        if pr.get("merged"):
            self.reads[target + "commits/" + merge] = {"sha": merge, "parents": [{"sha": base}], "files": files}
        self.propose()

    def change_marker(self):
        self.pr["body"] = self.legacy_marker + "\n" + origin.marker(self.record)

    def propose(self):
        self.change_marker()
        self.reads[ARTIFACTS]["artifacts"][1]["name"] = origin.artifact_name(self.repo, self.record, self.pr["number"])

    def verify(self, repo=None, pr=None):
        return origin.verify(repo or self.repo, pr or self.pr, api=self.reads.__getitem__)


def regenerated_evidence(repo=REPO, predecessor_style="legacy", successor_style="legacy"):
    predecessor_id, successor_id, predecessor_number = "2" * 20, "3" * 20, 77
    evidence = Evidence(native_fixture.fixture()["pr"], repo)
    format_branch = origin.candidate_branch.format_branch
    predecessor_branch = format_branch(EXTENSION["name"], predecessor_id, predecessor_style)
    successor_branch = format_branch(EXTENSION["name"], successor_id, successor_style)
    predecessor_record = deepcopy(evidence.record)
    predecessor_record["decision"]["candidateId"] = predecessor_id
    predecessor_record["decision"]["branch"] = predecessor_branch
    evidence.record["decision"]["candidateId"] = successor_id
    evidence.record["decision"]["branch"] = successor_branch
    evidence.record["regeneration"] = {"predecessorCandidateId": predecessor_id,
                                        "predecessorPrNumber": predecessor_number}
    evidence.pr["head"]["ref"] = successor_branch
    evidence.legacy_marker = f"<!-- pgextwin-candidate:v1:{successor_id} -->"
    predecessor = {
        "number": predecessor_number, "state": "closed", "merged": False,
        "user": {"type": "Bot", "id": origin.APP["botUserId"], "login": origin.BOT},
        "head": {"ref": predecessor_branch, "sha": "7" * 40},
        "base": {"ref": "main"},
        "body": (f"<!-- pgextwin-candidate:v1:{predecessor_id} -->\n" +
                 origin.marker(predecessor_record)),
    }
    evidence.reads["repos/" + repo + "/pulls/" + str(predecessor_number)] = predecessor
    evidence.propose()
    return evidence


def replace_predecessor_record(evidence, record):
    predecessor = evidence.reads["repos/" + evidence.repo + "/pulls/77"]
    marker_text = f"<!-- pgextwin-candidate:v1:{'2' * 20} -->"
    predecessor["body"] = marker_text + "\n" + origin.marker(record)


def alter_predecessor_decision(evidence):
    predecessor = evidence.reads["repos/" + REPO + "/pulls/77"]
    record = origin.parse_marker(predecessor["body"])
    record["decision"]["updates"][0]["version"] = "9.99"
    replace_predecessor_record(evidence, record)


def make_chain_cycle(evidence):
    predecessor = evidence.reads["repos/" + REPO + "/pulls/77"]
    record = origin.parse_marker(predecessor["body"])
    record["regeneration"] = {"predecessorCandidateId": "3" * 20,
                              "predecessorPrNumber": 78}
    replace_predecessor_record(evidence, record)


def make_chain_too_deep(evidence):
    ids = [str(n) * 20 for n in (2, 4, 5, 6, 7, 8, 9, 0, 1)]
    for index, candidate_id in enumerate(ids):
        number = 77 + index
        record = deepcopy(evidence.record)
        record["decision"]["candidateId"] = candidate_id
        record["decision"]["branch"] = "auto-candidate/" + candidate_id
        record.pop("regeneration", None)
        if index + 1 < len(ids):
            record["regeneration"] = {"predecessorCandidateId": ids[index + 1],
                                      "predecessorPrNumber": number + 1}
        pr = {"number": number, "state": "closed", "merged": False,
              "user": {"type": "Bot", "id": origin.APP["botUserId"], "login": origin.BOT},
              "head": {"ref": "auto-candidate/" + candidate_id, "sha": "7" * 40},
              "base": {"ref": "main"},
              "body": f"<!-- pgextwin-candidate:v1:{candidate_id} -->\n" + origin.marker(record)}
        evidence.reads["repos/" + REPO + "/pulls/" + str(number)] = pr


class FleetCandidateOrigin(TestCase):
    def setUp(self):
        self.native = native_fixture.fixture()
        self.evidence = Evidence(self.native["pr"])

    def test_exact_app_candidate_passes_native_audit_and_keeps_publication_denied(self):
        self.native["pr_files"][0]["sha"] = self.evidence.blob
        result = native_fixture.native.validate(**self.native, verify_origin=self.evidence.verify)
        self.assertEqual(result["candidateOrigin"],
                         {"repository": origin.BUILD, "runId": 100, "runAttempt": 1,
                          "decisionArtifactId": 44, "originArtifactId": 45})
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["signedArtifactsVerified"])
        with self.assertRaises(native_fixture.native.Denied):
            native_fixture.native.validate(**self.native)

    def test_fleet_status_requires_origin_and_reports_unverified_ci(self):
        page = collection("workflow_runs", self.native["run"])
        _, status = fleet_status.native_candidate_ci(page, self.evidence.pr, REPO,
                                                      verify_origin=self.evidence.verify)
        self.assertEqual(status, "NATIVE_CI_SUCCESS_UNVERIFIED")
        self.evidence.pr["body"] = self.evidence.legacy_marker
        with self.assertRaises(fleet_status.WatchError):
            fleet_status.native_candidate_ci(page, self.evidence.pr, REPO,
                                             verify_origin=self.evidence.verify)

    def test_wrong_app_or_bot_and_name_alone_deny(self):
        for change in (lambda e: e.reads[APP].update(id=13),
                       lambda e: e.pr["user"].update(id=13),
                       lambda e: e.pr.update(performed_via_github_app={"id": 13}),
                       lambda e: e.pr.update(body=e.legacy_marker)):
            with self.subTest(change=change):
                evidence = deepcopy(self.evidence)
                change(evidence)
                with self.assertRaises(ValueError):
                    evidence.verify()

    def test_regenerated_candidate_accepts_exact_closed_app_predecessor_chain(self):
        evidence = regenerated_evidence()
        self.assertEqual(evidence.verify()["record"]["regeneration"],
                         {"predecessorCandidateId": "2" * 20, "predecessorPrNumber": 77})

    def test_tc15_origin_binds_exact_repository_branch_style_and_extension(self):
        for repo, style, name, accepted in (
            (REPO, "legacy", "pg_ivm", True),
            (REPO, "central", "pg_ivm", False),
            (CENTRAL_REPO, "central", "pg_ivm", True),
            (CENTRAL_REPO, "legacy", "pg_ivm", False),
            (CENTRAL_REPO, "central", "pgaudit", False),
        ):
            with self.subTest(repo=repo, style=style, name=name):
                pr = native_fixture.fixture()["pr"]
                pr["head"]["ref"] = origin.candidate_branch.format_branch(name, "d" * 20, style)
                evidence = Evidence(pr, repo)
                if accepted:
                    self.assertEqual(origin.validate_pr(repo, pr, evidence.record), evidence.record["decision"])
                else:
                    with self.assertRaises(origin.Denied):
                        origin.validate_pr(repo, pr, evidence.record)

    def test_tc15_regeneration_accepts_both_central_predecessor_formats(self):
        for predecessor_style in ("central", "legacy"):
            with self.subTest(style=predecessor_style):
                evidence = regenerated_evidence(CENTRAL_REPO, predecessor_style, "central")
                self.assertEqual(origin.validate_pr(CENTRAL_REPO, evidence.pr, evidence.record),
                                 evidence.record["decision"])
                origin.verify_regeneration_chain(evidence.reads.__getitem__, CENTRAL_REPO, evidence.record)
                predecessor = evidence.reads[f"repos/{CENTRAL_REPO}/pulls/77"]
                record = origin.parse_marker(predecessor["body"])
                wrong_branch = origin.candidate_branch.format_branch("pgaudit", "2" * 20, "central")
                predecessor["head"]["ref"] = wrong_branch
                record["decision"]["branch"] = wrong_branch
                replace_predecessor_record(evidence, record)
                with self.assertRaisesRegex(origin.Denied, "predecessor branch differs"):
                    origin.verify_regeneration_chain(evidence.reads.__getitem__, CENTRAL_REPO, evidence.record)

    def test_regeneration_chain_mismatches_fail_closed(self):
        changes = (
            lambda e: e.reads["repos/" + REPO + "/pulls/77"].update(merged=True),
            lambda e: e.reads["repos/" + REPO + "/pulls/77"]["user"].update(id=13),
            lambda e: alter_predecessor_decision(e),
            lambda e: e.reads["repos/" + REPO + "/pulls/77"].update(body="<!-- pgextwin-candidate:v1:" + "2" * 20 + " -->"),
            lambda e: make_chain_cycle(e),
            lambda e: make_chain_too_deep(e),
            lambda e: e.record.update(regeneration={"predecessorCandidateId": "bad", "predecessorPrNumber": 77}),
        )
        for change in changes:
            with self.subTest(change=change):
                evidence = regenerated_evidence()
                change(evidence)
                evidence.propose()
                with self.assertRaises(ValueError):
                    evidence.verify()

    def test_substituted_head_pr_number_manifest_and_base_deny(self):
        target = "repos/" + REPO + "/"
        head_commit = target + "commits/" + self.evidence.record["headSha"]
        for change in (lambda e: e.pr["head"].update(sha="1"*40),
                       lambda e: e.pr.update(number=e.pr["number"] + 1),
                       lambda e: e.pr["base"]["repo"].update(id=21),
                       lambda e: e.reads[head_commit]["parents"].append({"sha": "1"*40}),
                       lambda e: e.reads[target + "branches/main"]["commit"].update(sha="1"*40),
                       lambda e: e.record["decision"]["updates"][0].update(ref="v2.0")):
            with self.subTest(change=change):
                evidence = deepcopy(self.evidence)
                change(evidence)
                evidence.change_marker()
                with self.assertRaises(ValueError):
                    evidence.verify()
        # Even when centrally recorded, mismatched pins must fail at the manifest check.
        self.evidence.record["decision"]["updates"][0]["commit"] = "1"*40
        self.evidence.propose()
        with self.assertRaisesRegex(ValueError, "upstream pins"):
            self.evidence.verify()

    def test_other_old_or_replayed_run_deny(self):
        for change in (lambda e: e.reads[RUN].update(run_attempt=2),
                       lambda e: e.reads[RUN].update(event="push"),
                       lambda e: e.reads[RUN].update(created_at=timestamp(-181)),
                       lambda e: e.reads[ARTIFACTS]["artifacts"][0].update(id=87),
                       lambda e: e.reads[ARTIFACTS]["artifacts"][1]["workflow_run"].update(id=101),
                       lambda e: e.reads[JOBS]["jobs"][1].update(run_id=101),
                       lambda e: e.pr.update(created_at=timestamp(4)),
                       lambda e: e.pr.update(created_at=timestamp(12))):
            with self.subTest(change=change):
                evidence = deepcopy(self.evidence)
                change(evidence)
                with self.assertRaises(ValueError):
                    evidence.verify()
        self.evidence.record["runId"] = 101
        self.evidence.propose()
        with self.assertRaises(KeyError):
            self.evidence.verify()

    def test_unregistered_target_and_missing_or_ambiguous_evidence_deny(self):
        for change in (lambda e: e.reads[ARTIFACTS]["artifacts"][1].update(expired=True),
                       lambda e: e.reads[ARTIFACTS].update(total_count=100),
                       lambda e: e.reads[ARTIFACTS].update(collection("artifacts", e.reads[ARTIFACTS]["artifacts"][0])),
                       lambda e: e.reads[JOBS]["jobs"][1].update(steps=[]),
                       lambda e: e.reads[JOBS]["jobs"][0].update(conclusion="failure"),
                       lambda e: e.pr.update(body=e.pr["body"] + e.pr["body"])):
            with self.subTest(change=change):
                evidence = deepcopy(self.evidence)
                change(evidence)
                with self.assertRaises(ValueError):
                    evidence.verify()
        with self.assertRaisesRegex(ValueError, "outside"):
            self.evidence.verify("pgextwin/unknown")

    def test_historical_protected_build_commit_and_merged_candidate(self):
        merged = merge_fixture.fixture()
        evidence = Evidence(merged["pr"], extension=merged["manifest"], base=merged["event"]["before"])
        merged["pr_files"][0]["sha"] = merged["commit"]["files"][0]["sha"] = evidence.blob
        newer = "2" * 40
        evidence.reads[BUILD + "branches/main"]["commit"]["sha"] = newer
        compare = BUILD + "compare/" + BUILD_SHA + "..." + newer
        evidence.reads[compare] = {"status": "ahead", "merge_base_commit": {"sha": BUILD_SHA}}
        result = merge_fixture.gate.verify(**merged, verify_origin=evidence.verify)
        self.assertEqual(result["candidateOrigin"]["decisionArtifactId"], 44)
        self.assertFalse(result["publishableReceipt"])
        evidence.reads[compare]["status"] = "diverged"
        with self.assertRaisesRegex(merge_fixture.gate.Denied, "outside protected"):
            merge_fixture.gate.verify(**merged, verify_origin=evidence.verify)

    def test_live_native_binder_rechecks_the_app_origin(self):
        inputs = binder_fixture.fixture()
        pr = inputs["pr"]
        pr["head"]["ref"] = "auto-candidate/" + "9" * 20
        pr["base"]["sha"] = inputs["main"]["commit"]["sha"]
        evidence = Evidence(pr)
        inputs["manifest"] = evidence.reads[
            "repos/" + REPO + "/contents/" + origin.MANIFEST + "?ref=" + pr["head"]["sha"]]
        inputs["files"][0]["sha"] = evidence.blob
        main_sha, _, _ = binder_fixture.mod.validate_live(**inputs, verify_origin=evidence.verify)
        self.assertEqual(main_sha, evidence.record["baseSha"])
        del evidence.reads[ARTIFACTS]
        with self.assertRaises(binder_fixture.mod.Denied):
            binder_fixture.mod.validate_live(**inputs, verify_origin=evidence.verify)

    def test_registered_original_audit_remains_nonpublishing(self):
        inputs = requal_fixture.fixture()
        extension = origin.contents.decode_json_file(inputs["candidate_contents"], origin.MANIFEST)
        evidence = Evidence(inputs["pr"], repo=inputs["entry"]["repository"],
                            extension=extension, base="3" * 40)
        result = requal_fixture.m.validate_merged(**inputs, verify_origin=evidence.verify)
        self.assertEqual(result["status"], requal_fixture.m.SOURCE_KIND)
        self.assertFalse(result["publicationAuthorized"])
        self.assertIsNone(result["newOIDCSigningRun"])

    def test_original_decision_from_app_enters_existing_intent_only_after_verification(self):
        base, event, data, api, _ = intent_fixture.setup()
        repo = event["repository"]["full_name"]
        event["before"] = "3" * 40
        evidence = Evidence(data["pulls/8"], repo=repo, extension=base["manifest"], base=event["before"])
        data.pop("actions/runs?per_page=100")

        def bind():
            return intent_fixture.live.bind(
                repository=repo, event=event, witness=base["witness"], fleet=base["fleet"],
                central_policy=base["central_policy"], lifecycle=base["lifecycle"],
                candidate_policy=base["candidate_policy"], api=api, today=date(2026, 10, 22),
                verify_origin=evidence.verify)

        result = bind()
        self.assertEqual(result["originalDecisionRunId"], 100)
        self.assertEqual(result["originalDecisionArtifactId"], 44)
        self.assertEqual(result["originalDecisionRepository"], origin.BUILD)
        self.assertFalse(result["signedArtifactsVerified"])
        self.assertFalse(result["publicationAuthorized"])
        event["before"] = "4" * 40
        with self.assertRaisesRegex(intent_fixture.live.Denied, "protected parent"):
            bind()

    def test_legacy_path_does_not_need_app_evidence(self):
        args = native_fixture.fixture()
        def no_app_api(*_):
            self.fail("legacy candidate consulted App evidence")
        result = native_fixture.native.validate(**args, verify_origin=no_app_api)
        self.assertNotIn("candidateOrigin", result)


if __name__ == "__main__":
    main()
