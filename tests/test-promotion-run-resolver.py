#!/usr/bin/env python3
"""Offline promotion evidence and Issue #311 owner confirmation fixtures."""
from base64 import b64encode
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location(Path(path).stem, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


entry = load("scripts/publisher-promote-request.py")
resolver = entry.resolver
gate_fixture = load("tests/test-fleet-promotion-gate.py").fixture


class Evidence(resolver.GitHub):
    def __init__(self, extension="plpgsql_check"):
        case = self.case = gate_fixture(extension)
        self.project = project = f"repos/{case['repo']}"
        actions = f"{project}/actions"
        pull = f"{project}/pulls/{case['pr']['number']}"
        self.pull = pull
        self.runs = f"{actions}/runs?head_sha={case['pr']['head']['sha']}&per_page=100"
        self.decisions = f"{actions}/artifacts?name=candidate-decision&per_page=100"
        self.responses = {
            pull: case["pr"],
            f"{pull}/files?per_page=2": case["pr_files"],
            self.runs: [case["run"]],
            self.decisions: [],
        }
        self.documents = {resolver.MANIFEST: case["ext"]}
        self.archives = {}
        self.add_audit(case["run"], 700, case["audit"])
        self.add_decision(case["watch_run"], 701, case["decision"])

    def add_audit(self, run, artifact_id, audit):
        self.responses[f"{self.project}/actions/runs/{run['id']}/artifacts?name=candidate-audit&per_page=100"] = [
            {"name": "candidate-audit", "id": artifact_id, "expired": False}
        ]
        self.archives[artifact_id] = audit

    def add_decision(self, run, artifact_id, decision):
        self.responses[f"{self.project}/actions/runs/{run['id']}"] = run
        self.responses[self.decisions].append({
            "name": "candidate-decision", "id": artifact_id, "expired": False,
            "workflow_run": {"id": run["id"], "head_branch": run["head_branch"]},
        })
        self.archives[artifact_id] = decision

    def get(self, path, *options):
        if path.endswith("/zip"):
            report = self.archives[int(path.split("/")[-2])]
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("evidence.json", json.dumps(report))
            return buffer.getvalue()
        if "/contents/" in path:
            document, merge_sha = path.split("/contents/")[1].split("?ref=")
            assert merge_sha == self.case["pr"]["merge_commit_sha"]
            content = b64encode(json.dumps(self.documents[document]).encode()).decode()
            return json.dumps({"encoding": "base64", "content": content}).encode()
        value = self.responses[path]
        if "--paginate" in options:
            key = "artifacts" if "/artifacts?" in path else "workflow_runs"
            pages = [{key: [row], "total_count": len(value)} for row in value]
            return "\n".join(map(json.dumps, pages or [{key: [], "total_count": 0}])).encode()
        return json.dumps(value).encode()

    def resolve(self):
        return resolver.resolve(self.case["repo"], self.case["pr"]["number"],
                                github=self, lifecycle=self.case["lifecycle"])


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.github = Evidence()

    def test_unique_match(self):
        other = dict(self.github.case["run"], id=899, event="pull_request")
        self.github.responses[self.github.runs].insert(0, other)
        self.github.add_decision(dict(self.github.case["watch_run"], id=902), 702, {"status": "no-update"})
        ids = self.github.resolve()
        self.assertEqual(ids["candidateRunId"], 900)
        self.assertEqual(ids["decisionRunId"], 901)
        self.assertEqual(ids["candidateHeadSha"], self.github.case["pr"]["head"]["sha"])

    def test_no_candidate_run(self):
        self.github.responses[self.github.runs].clear()
        with self.assertRaisesRegex(resolver.Denied, "no matching candidate run"):
            self.github.resolve()

    def test_ambiguous_candidate_runs(self):
        duplicate = dict(self.github.case["run"], id=899)
        self.github.responses[self.github.runs].append(duplicate)
        self.github.add_audit(duplicate, 702, dict(self.github.case["audit"], runId=899))
        with self.assertRaisesRegex(resolver.Denied, "ambiguous candidate runs: 899, 900"):
            self.github.resolve()

    def test_audit_identity_mismatch(self):
        self.github.case["audit"]["runId"] = 902
        with self.assertRaisesRegex(resolver.Denied, "no matching candidate run: candidate-audit identity"):
            self.github.resolve()

    def test_decision_mismatch(self):
        self.github.case["decision"]["repository"] = "unrelated/upstream"
        with self.assertRaisesRegex(resolver.Denied, "no matching decision run: candidate decision branch/upstream"):
            self.github.resolve()

    def test_ambiguous_decision_runs(self):
        self.github.add_decision(dict(self.github.case["watch_run"], id=902), 702,
                                 self.github.case["decision"])
        with self.assertRaisesRegex(resolver.Denied, "ambiguous decision runs: 901, 902"):
            self.github.resolve()

    def test_missing_live_artifact(self):
        key = f"{self.github.project}/actions/runs/900/artifacts?name=candidate-audit&per_page=100"
        self.github.responses[key][0]["expired"] = True
        with self.assertRaisesRegex(resolver.Denied, "candidate-audit absent or expired"):
            self.github.resolve()

    def test_incomplete_listing_cannot_return_a_unique_run(self):
        with patch.object(resolver.GitHub, "get", return_value=b'{"total_count":2,"workflow_runs":[{"id":900}]}'):
            with self.assertRaisesRegex(resolver.Denied, "incomplete or changing"):
                resolver.GitHub().collection("runs", "workflow_runs", resolver.RUN_FIELDS)

    def test_first_release(self):
        github = Evidence("pgtap")
        case = github.case
        case["pr_files"][:] = [{"filename": resolver.FIRST_RELEASE, "status": "added"}]
        github.documents[resolver.FIRST_RELEASE] = {
            "schemaVersion": 1, "kind": "FIRST_RELEASE_PINNED_SOURCE", "extension": "pgtap",
            "repository": case["repo"], "candidateId": case["decision"]["candidateId"],
            "releasePolicy": "manual-only", "source": case["ext"]["upstream"],
        }
        case["decision"]["firstRelease"] = True
        update = case["decision"]["updates"][0]
        update.update(initialOnly=True, oldRef=update["ref"], oldVersion=update["version"])
        self.assertEqual(github.resolve()["decisionRunId"], 901)


class OwnerCommandTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.event = Path(tmp.name) / "event.json"
        self.github = Evidence()
        owner = {"login": "ShutenOishi", "id": 27071164, "type": "User"}
        self.comment = {
            "id": 12345, "user": owner,
            "body": "/pgextwin promote pgextwin/plpgsql_check 12 v2.10.14-windows.2",
            "issue_url": "https://api.github.com/repos/pgextwin/build/issues/311",
            "created_at": "2026-11-23T00:00:00Z", "updated_at": "2026-11-23T00:00:00Z",
        }
        self.payload = {"action": "created", "issue": {"number": 311}, "comment": self.comment, "sender": owner}
        self.env = {
            "GITHUB_REPOSITORY": "pgextwin/build", "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "issue_comment",
            "GITHUB_ACTOR": owner["login"], "GITHUB_TRIGGERING_ACTOR": owner["login"],
            "GITHUB_ACTOR_ID": str(owner["id"]), "GITHUB_EVENT_PATH": str(self.event),
        }
        self.github.responses["repos/pgextwin/build/issues/comments/12345"] = dict(self.comment)

    def confirm(self):
        self.event.write_text(json.dumps(self.payload), encoding="utf-8")
        return entry.confirm(self.env, self.github, lifecycle=self.github.case["lifecycle"])

    def test_owner_comment_is_bound_to_request_and_ids(self):
        record = self.confirm()
        self.assertEqual(record["ownerComment"]["body"], self.comment["body"])
        self.assertTrue(record["ownerComment"]["url"].endswith("#issuecomment-12345"))
        self.assertEqual((record["candidateRunId"], record["decisionRunId"]), (900, 901))
        self.assertEqual(record["publication"], "DENY")

    def test_other_trigger_actor_denied(self):
        self.env["GITHUB_TRIGGERING_ACTOR"] = "someone-else"
        with self.assertRaisesRegex(ValueError, "untrusted owner identity"):
            self.confirm()

    def test_extra_argument_denied(self):
        self.comment["body"] += " 900"
        with self.assertRaisesRegex(ValueError, "expected /pgextwin promote"):
            self.confirm()

    def test_edited_live_comment_denied(self):
        self.github.responses["repos/pgextwin/build/issues/comments/12345"]["body"] += " extra"
        with self.assertRaisesRegex(ValueError, "current owner promotion comment changed"):
            self.confirm()

    def test_workflow_keeps_execution_behind_opt_in_without_write_credentials(self):
        workflow = ROOT / ".github/workflows/publisher-candidate-intake.yml"
        jobs = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]
        intake = jobs["resolve_owner_promotion"]
        guard = intake["if"]
        for term in (
            "github.repository == 'pgextwin/build'", "github.event.issue.number == 311",
            "github.actor == 'ShutenOishi'", "github.triggering_actor == 'ShutenOishi'",
            "github.event_name == 'issue_comment'", "startsWith(github.event.comment.body, '/pgextwin promote ')",
        ):
            self.assertIn(term, guard)
        self.assertEqual(set(intake["permissions"].values()), {"read"})
        execution = jobs["execute_owner_promotion"]
        self.assertEqual(execution["needs"], "resolve_owner_promotion")
        self.assertEqual(execution["if"], "${{ vars.PGEXTWIN_MANUAL_PROMOTION_ENABLED == 'true' }}")
        self.assertEqual(execution["permissions"], {})
        self.assertEqual(len(execution["steps"]), 1)
        self.assertIn("exit 1", execution["steps"][0]["run"])


if __name__ == "__main__":
    unittest.main()
