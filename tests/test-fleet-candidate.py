#!/usr/bin/env python3
"""Exercise the same-run candidate handoff without GitHub writes."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("fleet_candidate", ROOT / "scripts/fleet-candidate.py")
direct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(direct)

REPO = "pgextwin/pg_ivm"
BUILD_SHA = "a" * 40
TARGET_SHA = "b" * 40
UPDATE_SHA = "c" * 40
UPSTREAM = "sraoss/pg_ivm"
WRITER = (direct.origin.BOT, direct.origin.APP["botUserId"])
REGISTRY = json.loads((ROOT / "metadata/automation-fleet.json").read_text(encoding="utf-8"))
AUTHORITY_POLICY = dict(direct.local_auth_central.load_policy(ROOT), delegationEndsAt="2099-01-01T00:00:00Z")
MANIFEST = {"name": "pg_ivm", "postgresql": {"majors": [17, 18]},
            "upstream": {"repository": UPSTREAM, "ref": "v1.17", "version": "1.17", "commit": "e" * 40},
            "watch": {"source": "github", "strategy": "github-releases", "prereleases": False,
                      "stableTagPattern": r"^v(?P<version>\d+\.\d+)$"}}
UPDATE = {"current": {"ref": "v1.17", "version": "1.17"},
          "candidate": {"ref": "v1.18", "version": "1.18"}}


def branch(sha):
    return {"protected": True, "commit": {"sha": sha}}


def fixture(updated=True):
    now = datetime.now(timezone.utc)
    run = {"id": 100, "status": "in_progress", "conclusion": None, "head_sha": BUILD_SHA,
           "event": "schedule", "path": direct.receipt.WATCH_PATH, "head_branch": "main",
           "repository": {"full_name": direct.receipt.BUILD}, "run_attempt": 1,
           "created_at": (now - timedelta(minutes=4)).isoformat()}
    scan = {"name": "readonly-fleet", "conclusion": "success", "status": "completed",
            "run_id": 100, "run_attempt": 1, "head_sha": BUILD_SHA,
            "completed_at": (now - timedelta(minutes=1)).isoformat()}
    rows = [{"repository": row["repository"], "mainSha": TARGET_SHA,
             "status": "up-to-date", "updates": []} for row in REGISTRY["entries"]]
    if updated:
        row = next(row for row in rows if row["repository"] == REPO)
        row.update(status="update-available", updates=[deepcopy(UPDATE)])
    report = {"schemaVersion": 1, "scope": "STABLE_UPSTREAM_GET_ONLY",
              "publication": "DENY", "candidatePrCreated": False, "fleetSize": len(rows),
              "indeterminate": 0, "updatesDetected": int(updated), "extensions": rows,
              "generatedAt": (now - timedelta(minutes=2)).isoformat()}
    return report, (run, branch(BUILD_SHA), scan, REGISTRY)


def fetch(url):
    if url.endswith("/releases?per_page=100"):
        return [{"tag_name": "v1.18", "draft": False, "prerelease": False}]
    if url.endswith("/git/ref/tags/v1.18"):
        return {"object": {"type": "commit", "sha": UPDATE_SHA}}
    if url.endswith("/contents/metadata/automation-fleet.json?ref=main"):
        return {"encoding": "base64",
                "content": base64.b64encode(json.dumps(REGISTRY).encode()).decode()}
    raise AssertionError(url)


class FleetCandidate(TestCase):
    def setUp(self):
        def branches(url, token):
            if url.endswith("/pgextwin/build/branches/main"):
                return branch(BUILD_SHA)
            self.assertIn(url, {direct.receipt.HOST + row["repository"] + "/branches/main"
                                for row in REGISTRY["entries"]})
            return branch(TARGET_SHA)

        self.enterContext(patch.dict(os.environ, {"PGEXTWIN_SCAN_READ_TOKEN": "reader"}))
        self.enterContext(patch.object(direct.receipt, "api", branches))
        self.enterContext(patch.object(direct, "execution_mode", return_value="DENY"))

    def test_enforce_selects_the_full_fleet_with_one_policy(self):
        _, context = fixture()
        with patch.object(direct, "execution_mode", return_value="ENFORCE"):
            self.assertEqual(direct.repositories(context),
                             sorted(row["repository"] for row in REGISTRY["entries"]))

    def test_no_update_runs_selection_only(self):
        report, context = fixture(updated=False)
        with patch.object(direct.candidate, "plan") as compute:
            matrix, summary = direct.select(report, context)
            self.assertEqual(matrix, [])
            self.assertIn("no update", summary[0])
            with self.assertRaises(direct.receipt.Denied):
                direct.checked_plan(report, context, REPO, fetch=fetch)
            compute.assert_not_called()

    def test_require_own_successful_scan_even_if_other_jobs_fail(self):
        report, context = fixture()
        context[0]["unrelated_audit"] = "failure"
        self.assertEqual(direct.select(report, context)[0][0]["repository"], REPO)
        for field, value in (("run_id", 101), ("head_sha", "0" * 40),
                             ("conclusion", "failure"), ("run_attempt", 2),
                             ("completed_at", "2020-01-01T00:00:00Z")):
            with self.subTest(field=field), patch.dict(context[2], {field: value}):
                with self.assertRaises(direct.receipt.Denied):
                    direct.select(report, context)
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event), patch.dict(context[0], {"event": event}):
                with self.assertRaises(direct.receipt.Denied):
                    direct.select(report, context)
        with patch.object(direct.receipt, "api", return_value=branch("0" * 40)):
            with self.assertRaises(direct.receipt.Denied):
                direct.select(report, context)

    def test_update_plan_to_proposal_uses_real_engine_with_stubbed_git_and_gh(self):
        self.exercise_plan_to_proposal(None)

    def test_tc14_central_plan_and_created_origin_agree_with_local_auth(self):
        with patch.object(direct, "execution_mode", return_value="ENFORCE"), \
                patch.object(direct.local_auth_central, "load_policy", return_value=AUTHORITY_POLICY):
            self.exercise_plan_to_proposal(direct.receipt.BUILD)

    def test_tc16_unsigned_successor_stops_before_writes_and_authorization_evidence(self):
        with patch.object(direct, "execution_mode", return_value="ENFORCE"), \
                patch.object(direct.local_auth_central, "load_policy", return_value=AUTHORITY_POLICY):
            self.exercise_plan_to_proposal(direct.receipt.BUILD, closed_predecessor=True)

    def exercise_plan_to_proposal(self, target_repository, *, closed_predecessor=False):
        report, context = fixture()
        repo_name = target_repository or REPO
        base_sha = BUILD_SHA if target_repository else TARGET_SHA
        manifest_path = "extensions/pg_ivm/extension.json" if target_repository else direct.MANIFEST
        proposal_paths = {"target_repository": target_repository, "manifest_path": manifest_path}
        commands = []
        repo_id = 1406488805
        branch_head = "f" * 40
        blob = "a" * 40
        body = ""

        def closed_pr_marker():
            return f"<!-- pgextwin-candidate:v1:{plan['candidateId']} -->"

        def fetch_with_pr(url):
            if url == direct.receipt.HOST + repo_name:
                return {"full_name": repo_name, "id": repo_id}
            if url.endswith("/pulls/123"):
                repo = {"full_name": repo_name, "id": repo_id}
                return {"number": 123, "state": "closed" if closed_predecessor else "open", "merged": False,
                        "user": {"login": WRITER[0], "id": WRITER[1], "type": "Bot"},
                        "body": closed_pr_marker() if closed_predecessor else body,
                        "head": {"ref": plan["branch"], "sha": branch_head, "repo": repo},
                        "base": {"ref": "main", "sha": base_sha, "repo": repo}}
            return fetch(url)

        def execute(*args):
            nonlocal body
            commands.append(args)
            if args == ("git", "rev-parse", "HEAD:" + manifest_path):
                return blob
            if args[:2] == ("git", "rev-parse"):
                return branch_head if ("git", "commit") in [call[:2] for call in commands] else base_sha
            if args[:3] == ("git", "remote", "get-url"):
                return "https://github.com/" + repo_name
            if args == ("git", "diff", "--name-status", "-z", "-M", "-C", "HEAD~1", "HEAD"):
                self.assertIsNotNone(target_repository)
                return f"M\0{manifest_path}\0"
            if closed_predecessor and args[:3] == ("gh", "pr", "list") and plan["branch"] in args:
                return json.dumps([{"number": 123, "state": "CLOSED", "body": closed_pr_marker(),
                                    "url": f"https://github.com/{repo_name}/pull/123", "headRefOid": branch_head,
                                    "headRefName": plan["branch"], "baseRefName": "main", "isCrossRepository": False}])
            if args == ("gh", "api", f"repos/{repo_name}/pulls/123"):
                return json.dumps(fetch_with_pr(direct.receipt.HOST + repo_name + "/pulls/123"))
            if args[:3] in (("gh", "pr", "list"), ("gh", "run", "list")):
                return "[]"
            if args[:3] == ("gh", "pr", "create"):
                body = Path(args[args.index("--body-file") + 1]).read_text("utf-8")
                return "https://github.com/" + repo_name + "/pull/123"
            return ""

        matrix, _ = direct.select(report, context)
        self.assertEqual(matrix, [{"repository": REPO, "sha": TARGET_SHA, "extension": "pg_ivm"}])
        previous = Path.cwd()
        with TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}), \
                patch.object(direct.candidate, "execute", execute):
            try:
                os.chdir(tmp)
                manifest = Path(manifest_path)
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
                plan = direct.checked_plan(report, context, REPO, fetch=fetch, **proposal_paths)
                legacy = direct.candidate.plan(
                    MANIFEST, None, direct.candidate.publication_policy.load_candidate_policy(ROOT), fetch=fetch)
                prefix = "auto-candidate/pg_ivm/" if target_repository else "auto-candidate/"
                self.assertEqual(plan["branch"], prefix + legacy["candidateId"])
                self.assertEqual(plan["candidateId"], legacy["candidateId"])
                prepared = self.assert_issuer_plan_matches(plan, repo_name, base_sha)
                self.assertEqual(plan["updates"][0]["commit"], UPDATE_SHA)
                self.assertEqual(plan["releasePolicy"], "manual-only")
                altered = deepcopy(plan)
                altered["updates"][0]["commit"] = "0" * 40
                with self.assertRaises(direct.receipt.Denied):
                    direct.propose(report, context, REPO, altered, WRITER, fetch=fetch,
                                   origin_path=Path(tmp) / "origin.json", decision_id=45, **proposal_paths)
                self.assertFalse(any(call[:2] == ("git", "push") for call in commands))
                origin = Path(tmp) / "origin.json"
                output = Path(tmp) / "output"
                with ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_RUN_ID": "100"}))
                    if target_repository:
                        evidence_path = Path(tmp) / "authorization.json"
                        proposal_paths["auth_evidence_path"] = evidence_path
                        inputs, issuance = prepared[3], {"receipt": "fixture"}
                        inputs_obj = json.loads(inputs)
                        ticket = dict(prepared[2], requestId="d" * 32,
                                      inputsSha256=hashlib.sha256(inputs).hexdigest())
                        central_binding = {
                            "ticket": ticket, "inputs_obj": inputs_obj, "consumer_run_id": 100,
                            "live_evidence": {"authorized": False, "publication": False,
                                              "requestId": ticket["requestId"],
                                              "issuerRepository": direct.local_auth.live.ISSUER_REPOSITORY,
                                              "issuerRunId": 120, "issuerRunAttempt": 1,
                                              "claimCommitSha": "e" * 40, "ticketSha256": "f" * 64},
                        }
                        central_evidence = {
                            "schemaVersion": 1, "status": "AUTHORIZED_CENTRAL_CANDIDATE",
                            "publication": False, "authorized": True,
                            "target": {"extension": "pg_ivm", "paths": [manifest_path], "branch": plan["branch"]},
                        }
                        prepare = stack.enter_context(patch.object(direct.local_auth, "prepare", return_value=prepared))
                        receive = stack.enter_context(patch.object(direct.issuance, "receive",
                                                                   return_value=(ticket, inputs, issuance)))
                        authorize = stack.enter_context(patch.object(
                            direct.local_auth, "authorize",
                            return_value={"centralEvidence": central_evidence, "centralBinding": central_binding}))
                    if closed_predecessor:
                        original_manifest = manifest.read_bytes()
                        with self.assertRaisesRegex(direct.candidate.WatchError,
                                                    "^RUN_CLAIM_CHANGE_BINDING_MISMATCH$"):
                            direct.propose(report, context, REPO, plan, WRITER, fetch=fetch_with_pr,
                                           origin_path=origin, decision_id=45, **proposal_paths)
                        authorize.assert_called_once()
                        successor = direct.candidate.regenerated_candidate_id(plan["candidateId"], 123)
                        successor_branch = f"auto-candidate/pg_ivm/{successor}"
                        self.assertTrue(any(call[:3] == ("gh", "pr", "list") and successor_branch in call
                                            for call in commands))
                        blocked_git = {"ls-remote", "checkout", "add", "commit", "push"}
                        self.assertFalse(any((call[0] == "git" and call[1] in blocked_git)
                                             or call[:3] in {("gh", "pr", "create"), ("gh", "workflow", "run")}
                                             for call in commands), commands)
                        self.assertEqual(manifest.read_bytes(), original_manifest)
                        self.assertFalse(evidence_path.exists())
                        self.assertFalse(origin.exists())
                        return
                    direct.propose(report, context, REPO, plan, WRITER, fetch=fetch_with_pr,
                                   origin_path=origin, decision_id=45, **proposal_paths)
                    if target_repository:
                        registered = frozenset(row["repository"].split("/")[1] for row in REGISTRY["entries"])
                        changes = [{"filename": manifest_path, "status": "modified"}]
                        self.assertEqual(prepare.call_count, 2)
                        for call in prepare.call_args_list:
                            self.assertEqual(call.args, (repo_name, base_sha, 100))
                            self.assertEqual(call.kwargs, {"fetch": fetch_with_pr, "extension": "pg_ivm",
                                                           "registered_extensions": registered, "changes": changes})
                        receive.assert_called_once_with(repo_name, base_sha, 100, direct.local_auth.verifier)
                        self.assertEqual(authorize.call_args.args, (ticket, inputs, issuance, prepared))
                        self.assertEqual(authorize.call_args.kwargs["changes"], changes)
                        self.assertEqual(json.loads(evidence_path.read_bytes()), central_evidence)
                expected = direct.origin.parse_marker(body)
                self.assertEqual(body.count(f"<!-- pgextwin-candidate:v1:{plan['candidateId']} -->"), 1)
                self.assertEqual(json.loads(origin.read_bytes()), {"origin": expected, "pullRequest": 123})
                self.assertEqual(expected["decision"], plan)
                self.assertEqual((expected["repository"], expected["baseSha"]), (repo_name, base_sha))
                pr = fetch_with_pr(direct.receipt.HOST + repo_name + "/pulls/123")
                if target_repository:
                    for branch_name in (legacy["branch"], "auto-candidate/pgaudit/" + plan["candidateId"]):
                        invalid = deepcopy(expected)
                        invalid["decision"]["branch"] = branch_name
                        with self.assertRaises(direct.origin.Denied):
                            direct.origin.validate_pr(repo_name, {**pr, "head": {**pr["head"], "ref": branch_name}}, invalid)
                self.assertEqual(expected["headSha"], branch_head)
                self.assertEqual(expected["manifestBlob"], blob)
                self.assertEqual(expected["decisionArtifactId"], 45)
                self.assertEqual(output.read_text(), "origin_artifact=" +
                                 direct.origin.artifact_name(repo_name, expected, 123) + "\n")
                self.assertEqual(json.loads(manifest.read_text())["upstream"]["commit"], UPDATE_SHA)
            finally:
                os.chdir(previous)
        self.assertIn(("git", "push", "--set-upstream", "origin", plan["branch"]), commands)
        self.assertTrue(any(call[:3] == ("gh", "pr", "create") and "--draft" in call for call in commands))
        self.assertIn(("gh", "workflow", "run", "windows.yml", "--repo", repo_name, "--ref", plan["branch"]), commands)
        if target_repository:
            self.assertIn(("git", "diff", "--name-status", "-z", "-M", "-C", "HEAD~1", "HEAD"), commands)

    def assert_issuer_plan_matches(self, record, repository, base_sha):
        auth = direct.local_auth
        registry = deepcopy(REGISTRY)
        if repository == auth.BUILD:
            # Simulate a future admitted central target only in this fixture.
            # The real targetSet still rejects the central repository.
            row = next(row for row in registry["entries"] if row["repository"] == REPO)
            registry["entries"].append(dict(row, repository=repository))

        def issuer_file(fetch_api, repo, path, sha):
            extension_path = "extensions/pg_ivm/extension.json" if repository == auth.BUILD else auth.EXTENSION
            payloads = {auth.MANIFEST: registry, extension_path: MANIFEST}
            if path == auth.LEGACY_WATCH:
                # A real legacy watch alongside the embedded one must agree with it.
                payloads[path] = dict(MANIFEST["watch"], schemaVersion=1, repository=UPSTREAM)
            raw = json.dumps(payloads[path]).encode()
            return {"path": path, "encoding": "base64", "content": base64.b64encode(raw).decode(),
                    "sha": hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()}

        def issuer_fetch(url):
            if url == auth.API + repository:
                return {"full_name": repository, "default_branch": "main", "id": 1406488805}
            if url.endswith("/branches/main"):
                sha = BUILD_SHA if url == auth.API + auth.BUILD + "/branches/main" else base_sha
                return dict(branch(sha), name="main")
            if url == f"{auth.API}{auth.BUILD}/actions/runs/100":
                identity = {"full_name": auth.BUILD}
                return {"id": 100, "head_sha": BUILD_SHA, "head_branch": "main", "event": "schedule",
                        "path": auth.WATCH_WORKFLOW, "run_attempt": 1, "status": "in_progress",
                        "repository": identity, "head_repository": identity}
            return fetch(url)

        scope = {"extension": record["extension"]} if repository == auth.BUILD else {}
        with patch.object(auth, "load_authority", return_value=(BUILD_SHA, AUTHORITY_POLICY)), \
             patch.object(auth, "enforce_policy"), patch.object(auth, "file_at", issuer_file), \
             patch.object(auth, "versioned_sources", return_value=[]), \
             patch.object(auth.candidate, "execute", return_value=BUILD_SHA):
            if repository == auth.BUILD:
                with patch.object(auth.fleet, "validate", return_value=direct.fleet.validate(REGISTRY)):
                    with self.assertRaisesRegex(auth.verifier.TicketRejected, "REPO_NOT_IN_FLEET"):
                        auth.prepare(repository, base_sha, 100, fetch=issuer_fetch, **scope)
            prepared = auth.prepare(repository, base_sha, 100, fetch=issuer_fetch, **scope)
        canonical = auth.verifier.canonical_json
        self.assertEqual(canonical(json.loads(prepared[3])["plan"]),
                         canonical({k: v for k, v in record.items() if k != "detectedAt"}))
        return prepared

    def assert_central_preflight_denied(self, code, *, mode="ENFORCE", policy=AUTHORITY_POLICY, invalid_fleet=False,
                                        manifest_path="extensions/pg_ivm/extension.json", branch_extension="pg_ivm"):
        report, context = fixture()
        if invalid_fleet:
            context = (*context[:3], {})
        record = direct.candidate.plan(
            MANIFEST, None, direct.candidate.publication_policy.load_candidate_policy(ROOT),
            fetch=fetch, branch_style="central")
        record["branch"] = f"auto-candidate/{branch_extension}/{record['candidateId']}"
        with TemporaryDirectory() as tmp, \
                patch.object(direct, "execution_mode", return_value=mode), \
                patch.object(direct.local_auth_central, "load_policy", return_value=policy), \
                patch.object(direct.issuance, "receive") as receive, \
                patch.object(direct.local_auth, "prepare") as prepare, \
                patch.object(direct.candidate, "propose_candidate") as write, \
                patch.object(direct.candidate, "execute") as execute:
            origin, evidence = Path(tmp) / "origin.json", Path(tmp) / "auth.json"
            with self.assertRaises(direct.local_auth_central.TicketRejected) as caught:
                direct.propose(report, context, REPO, record, WRITER, fetch=fetch,
                               origin_path=origin, decision_id=45, target_repository=direct.receipt.BUILD,
                               manifest_path=manifest_path, auth_evidence_path=evidence)
            self.assertEqual(caught.exception.code, code)
            for operation in (prepare, receive, write, execute):
                operation.assert_not_called()
            self.assertFalse(origin.exists())
            self.assertFalse(evidence.exists())

    def test_pr_b4_central_enforcement_cross_extension(self):
        self.assert_central_preflight_denied("CROSS_EXTENSION_DENIED",
                                             manifest_path="extensions/pg_bigm/extension.json")

    def test_pr_b4_central_enforcement_unclassified_path(self):
        self.assert_central_preflight_denied("PATH_CLASS_P7_DENIED", manifest_path="README.md")

    def test_pr_b4_central_enforcement_branch_mismatch(self):
        self.assert_central_preflight_denied("BRANCH_EXTENSION_MISMATCH", branch_extension="pg_bigm")

    def test_pr_b4_central_enforcement_deny_precedes_other_errors(self):
        self.assert_central_preflight_denied("DENY_MODE", mode="DENY", manifest_path="README.md",
                                             branch_extension="pg_bigm")

    def test_pr_b4_central_enforcement_unsupported_mode(self):
        self.assert_central_preflight_denied("MODE_NOT_IMPLEMENTED", mode="OBSERVE")

    def test_tc16_revoked_epoch_precedes_invalid_fleet(self):
        revoked = dict(AUTHORITY_POLICY, revokedPolicyEpochs=[AUTHORITY_POLICY["policyEpoch"]])
        self.assert_central_preflight_denied("EPOCH_REVOKED", policy=revoked, invalid_fleet=True)

    def test_workflow_passes_environment_app_key_through_both_calls(self):
        workflow_dir = ROOT / ".github/workflows"
        watch, candidate, writer = (
            yaml.load((workflow_dir / filename).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
            for filename in ("fleet-upstream-watch.yml", "fleet-candidate.yml",
                             "local-authorized-candidate.yml")
        )
        key = "fleet_candidate_app_private_key"
        key_expression = "${{ secrets.fleet_candidate_app_private_key }}"
        for caller, job_id, callee, filename in (
            (watch, "candidate-preparation", candidate, "fleet-candidate.yml"),
            (candidate, "propose", writer, "local-authorized-candidate.yml"),
        ):
            job = caller["jobs"][job_id]
            with self.subTest(call=job_id):
                self.assertEqual(job["uses"], f"./.github/workflows/{filename}")
                self.assertNotIn("environment", job)
                self.assertEqual(job.get("secrets"), {key: key_expression})
            with self.subTest(declaration=filename):
                declared = callee["on"]["workflow_call"].get("secrets", {})
                self.assertEqual(declared.get(key, {}).get("required"), "true")

        self.assertNotIn("environment", candidate["jobs"]["plan"])
        execute = writer["jobs"]["execute"]
        self.assertEqual(execute["environment"], "fleet-candidate-writer")
        token_keys = {
            step["id"]: step["with"].get("private-key") for step in execute["steps"]
            if step.get("uses", "").startswith("actions/create-github-app-token@")
        }
        self.assertEqual(token_keys, {"writer": key_expression, "issuer": key_expression})

    def test_workflow_restricts_selection_and_proposal(self):
        workflow = (ROOT / ".github/workflows/fleet-upstream-watch.yml").read_text()
        candidate = (ROOT / ".github/workflows/fleet-candidate.yml").read_text()
        writer = (ROOT / ".github/workflows/local-authorized-candidate.yml").read_text()
        for text in (workflow, candidate):
            self.assertEqual(text.count("github.event_name == 'schedule'"), 2)
        self.assertIn("needs: readonly-fleet", workflow)
        self.assertIn("needs.candidate-selection.outputs.has_updates == 'true'", workflow)
        self.assertIn("needs.plan.outputs.decision != ''", candidate)
        self.assertIn("vars.PGEXTWIN_FLEET_CANDIDATE_WRITES == 'enabled'", candidate)
        self.assertIn("uses: ./.github/workflows/local-authorized-candidate.yml", candidate)
        self.assertIn("github.event_name == 'schedule'", writer)
        self.assertIn("secrets.fleet_candidate_app_private_key", writer)
        issuer_id = "\n        id: issuer\n"
        self.assertIn(issuer_id, writer)
        issuer, proposal, *_ = writer.split(issuer_id, 1)[1].split("\n      - ")
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", issuer)
        self.assertIn("client-id: ${{ vars.PGEXTWIN_FLEET_CANDIDATE_APP_CLIENT_ID }}", issuer)
        self.assertIn("private-key: ${{ secrets.fleet_candidate_app_private_key }}", issuer)
        self.assertIn("          owner: pgextwin\n", issuer)
        self.assertIn("          repositories: local-auth-issuer\n", issuer)
        self.assertEqual({line.strip() for line in issuer.splitlines() if line.strip().startswith("permission-")},
                         {"permission-actions: write", "permission-contents: read"})
        self.assertIn("python3 ../scripts/fleet-candidate.py propose\n", proposal)
        self.assertIn("LOCAL_AUTH_ISSUER_TOKEN: ${{ steps.issuer.outputs.token }}", proposal)
        self.assertNotIn("secrets." + "LOCAL_AUTH_ISSUER_TOKEN", writer)
        self.assertNotIn("PUBLISHER_APP", writer)


if __name__ == "__main__":
    main()
