#!/usr/bin/env python3
"""Strictly nonpublishing native Run/artifact live-binding negative tests."""
import base64
import hashlib
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "live_binding", ROOT / "scripts" / "bind-native-candidate-audit-live.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

REPO = "pgextwin/pg_ivm"
SHA = "a" * 40
MAIN = "b" * 40
CI, AUDIT, ART, PR = 39769754052, 39771145795, 12422372611, 28
FLEET = json.loads((ROOT / "metadata/automation-fleet.json").read_text("utf-8"))


def fixture():
    raw = json.dumps({"name": "pg_ivm"}).encode()
    source = base64.encodebytes(raw).decode()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return dict(
        repo=REPO, pr_number=PR, ci_id=CI, audit_id=AUDIT, artifact_id=ART,
        pr={"number": PR, "state": "open", "merged": False,
            "user": {"login": "github-actions[bot]"},
            "base": {"ref": "main", "repo": {"full_name": REPO}},
            "head": {"sha": SHA, "repo": {"full_name": REPO}}},
        files=[{"filename": "config/extension.json",
                "status": "modified", "sha": blob}],
        ci_run={"id": CI, "event": "pull_request", "head_sha": SHA,
                "status": "completed", "conclusion": "success"},
        audit_run={"id": AUDIT, "event": "workflow_run",
                   "head_sha": MAIN, "status": "completed", "conclusion": "success"},
        artifact_list={"total_count": 1, "artifacts": [
            {"id": ART, "name": "candidate-audit-native-pr"}]},
        main={"name": "main", "protected": True, "commit": {"sha": MAIN}},
        manifest={"encoding": "base64", "path": "config/extension.json",
                  "sha": blob, "content": source})


class NativeLiveBindingTests(unittest.TestCase):
    def test_exact_real_github_identity_is_observation_only(self):
        self.assertTrue(mod.identity(REPO, PR, CI, AUDIT, ART, FLEET,
                                     current_repo=REPO, ref="refs/heads/main",
                                     event="workflow_run"))
        sha, source, art = mod.validate_live(**fixture())
        self.assertEqual(sha, MAIN)
        self.assertEqual(source["name"], "pg_ivm")
        self.assertEqual(art["id"], ART)

    def test_reject_untrusted_caller_origin_or_roster(self):
        variants = [
            dict(current_repo="pgextwin/orafce", ref="refs/heads/main", event="workflow_run"),
            dict(current_repo=REPO, ref="refs/heads/evil", event="workflow_run"),
            dict(current_repo=REPO, ref="refs/heads/main", event="pull_request"),
            dict(current_repo=REPO, ref="refs/heads/main", event="push"),
        ]
        for arg in variants:
            with self.subTest(arg=arg), self.assertRaises(mod.Denied):
                mod.identity(REPO, PR, CI, AUDIT, ART, FLEET, **arg)
        for i in (0, -1, True):
            with self.subTest(id=i), self.assertRaises(mod.Denied):
                mod.identity(REPO, PR, i, AUDIT, ART, FLEET,
                             current_repo=REPO, ref="refs/heads/main", event="workflow_run")
        fake = deepcopy(FLEET)
        fake["entries"].pop()
        with self.assertRaises(mod.Denied):
            mod.identity(REPO, PR, CI, AUDIT, ART, fake,
                         current_repo=REPO, ref="refs/heads/main", event="workflow_run")

    def test_cross_run_cross_repo_stale_main_duplicate_artifact_denied(self):
        mutants = [
            lambda x: x.update(repo="pgextwin/evil"),
            lambda x: x["pr"].update(number=PR+1),
            lambda x: x["pr"].update(merged=True),
            lambda x: x["pr"].update(state="closed"),
            lambda x: x["pr"]["user"].update(login="rogue"),
            lambda x: x["pr"]["head"].update(sha=MAIN),
            lambda x: x["pr"]["head"]["repo"].update(full_name="evil/pg_ivm"),
            lambda x: x["pr"]["base"].update(ref="candidate"),
            lambda x: x["files"].append(deepcopy(x["files"][0])),
            lambda x: x["files"][0].update(filename=".github/workflows/promote.yml"),
            lambda x: x["files"][0].update(status="added"),
            lambda x: x["ci_run"].update(id=CI+1),
            lambda x: x["ci_run"].update(head_sha=MAIN),
            lambda x: x["ci_run"].update(event="workflow_dispatch"),
            lambda x: x["ci_run"].update(conclusion="action_required"),
            lambda x: x["ci_run"].update(status="queued"),
            lambda x: x["audit_run"].update(id=AUDIT+1),
            lambda x: x["audit_run"].update(head_sha=SHA),
            lambda x: x["audit_run"].update(event="push"),
            lambda x: x["audit_run"].update(conclusion="failure"),
            lambda x: x["main"].update(protected=False),
            lambda x: x["main"]["commit"].update(sha=SHA),
            lambda x: x["manifest"].update(path="config/approval.json"),
            lambda x: x["manifest"].update(encoding="utf-8"),
            lambda x: x["manifest"].update(sha="d"*40),
            lambda x: x["manifest"].update(content=base64.b64encode(b'{"name":"orafce"}').decode()),
            lambda x: x["artifact_list"].update(total_count=100),
            lambda x: x["artifact_list"]["artifacts"].append(
                deepcopy(x["artifact_list"]["artifacts"][0])),
            lambda x: x["artifact_list"]["artifacts"][0].update(id=ART+1),
            lambda x: x["artifact_list"]["artifacts"][0].update(name="promotion-receipt"),
        ]
        for i, mut in enumerate(mutants):
            with self.subTest(i=i), self.assertRaises(mod.Denied):
                x = fixture()
                mut(x)
                mod.validate_live(**x)

    def test_downloaded_artifact_must_contain_exactly_two_safe_jsons(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root/"native-pr-ci-context.json").write_text('{"status":"NATIVE"}')
            (root/"candidate-audit-native-pr.json").write_text('{"status":"VERIFIED"}')
            a, b = mod.strictly_read_audit(root)
            self.assertEqual(b["status"], "VERIFIED")
            (root/"injected.json").write_text("{}")
            with self.assertRaises(mod.Denied):
                mod.strictly_read_audit(root)
            (root/"injected.json").unlink()
            (root/"candidate-audit-native-pr.json").write_text("{")
            with self.assertRaises(mod.Denied):
                mod.strictly_read_audit(root)


if __name__ == "__main__":
    unittest.main()
