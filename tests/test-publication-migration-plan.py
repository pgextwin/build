#!/usr/bin/env python3
"""Nonpublishing migration acceptance against real minimized GET snapshots."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/issue-75/publication-migration"
spec = importlib.util.spec_from_file_location("migration_planner", ROOT / "scripts/publication-migration-plan.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads((EVIDENCE / "extension-snapshot.json").read_text())
        self.heads = json.loads((EVIDENCE / "observed-heads.json").read_text())

    def update_file(self, record, path, content):
        record["files"][path] = {"content": content, "blobSha": m.blob(content)}

    def test_all_templates_apply_and_preserve_signer_detector_and_source_files(self):
        result = m.plan(self.snapshot, self.heads)
        self.assertEqual(result, json.loads((EVIDENCE / "review-templates.json").read_text()))
        for key in ("publicationAuthorized", "publishableReceipt", "applyEnabled", "liveEvidenceVerified"):
            self.assertIs(result[key], False)
        self.assertIsNone(result["targetPolicySha"])
        sources = {row["repository"]: row for row in [self.snapshot["central"], *self.snapshot["extensions"]]}
        for record in [result["central"], *result["extensions"]]:
            source = sources[record["repository"]]
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                for path, item in source["files"].items():
                    target = root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(item["content"])
                diff = "".join(c["diff"] for c in record["changes"])
                for args in (("--check", "-"), ("-",)):
                    run = subprocess.run(["git", "apply", *args], cwd=root,
                                         input=diff, capture_output=True, text=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                for change in record["changes"]:
                    text = (root / change["path"]).read_text()
                    self.assertEqual(m.blob(text), change.get("templateBlobSha", change.get("proposedBlobSha")))
                if record["repository"] == "pgextwin/build":
                    objects = [json.loads((root / p).read_text()) for p in m.CENTRAL]
                    decision = m.gate.deployment_policy(*objects)
                    self.assertIs(decision["staticPublisherReady"], True)
                    self.assertIs(decision["publicationAuthorized"], False)
                    downstream = m.downstream.validate(json.loads((root / m.DOWNSTREAM).read_text()), *objects[:2])
                    self.assertIs(downstream["catalogWriteAuthorized"], False)
                else:
                    workflow = (root / m.LOCAL[0]).read_text()
                    self.assertEqual(workflow.count(m.TARGET), len(m.SUPPORT))
                    self.assertIn("build-extension-attested.yml@" + m.SIGNER, workflow)
                    before = source["files"][m.LOCAL[0]]["content"]
                    detector = [s for s in before.splitlines() if "detector_sha:" in s]
                    self.assertEqual(detector, [s for s in workflow.splitlines() if "detector_sha:" in s])
                    for p in m.LOCAL[2:]:
                        self.assertEqual((root / p).read_text(), source["files"][p]["content"])
                    self.assertEqual(record["requiredChecks"], source["requiredChecks"])

    def test_stale_sha_protection_and_extra_checks_are_not_waived(self):
        for field, value in (("sha", "a" * 40), ("protected", False),
                             ("requiredChecks", [{"context": "unrelated", "app_id": 15368}])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                heads = deepcopy(self.heads)
                heads["heads"][1][field] = value
                m.plan(self.snapshot, heads)
        source = next(r for r in self.snapshot["extensions"] if len(r["requiredChecks"]) > 1)
        heads = deepcopy(self.heads)
        next(r for r in heads["heads"] if r["repository"] == source["repository"])["requiredChecks"] = [
            {"context": "Windows required summary", "app_id": 15368}]
        with self.assertRaises(m.Denied):
            m.plan(self.snapshot, heads)

    def test_missing_duplicate_unregistered_and_tampered_files_fail(self):
        cases = []
        v = deepcopy(self.snapshot); v["extensions"].pop(); cases.append(v)
        v = deepcopy(self.snapshot); v["extensions"][-1] = deepcopy(v["extensions"][0]); cases.append(v)
        v = deepcopy(self.snapshot); v["extensions"][0]["repository"] = "pgextwin/unknown"; cases.append(v)
        v = deepcopy(self.snapshot); v["extensions"][0]["files"].pop(m.LOCAL[2]); cases.append(v)
        v = deepcopy(self.snapshot); v["extensions"][0]["files"][m.LOCAL[0]]["content"] += "# tamper\n"; cases.append(v)
        v = deepcopy(self.snapshot); v["central"]["files"][m.CENTRAL[0]]["blobSha"] = "b" * 40; cases.append(v)
        for case in cases:
            with self.subTest(case=cases.index(case)), self.assertRaises(ValueError):
                m.plan(case, self.heads)

    def test_rehashed_unsafe_workflow_candidate_or_identity_is_rejected(self):
        before = self.snapshot["extensions"][0]["files"][m.LOCAL[0]]["content"]
        mutations = [
            (m.LOCAL[0], before.replace("@" + m.SIGNER, "@" + "a" * 40)),
            (m.LOCAL[0], before.replace("operator-update-auto.yml@", "unreviewed.yml@")),
            (m.LOCAL[0], before.replace(next(m.CALL.finditer(before))[2], "main")),
            (m.LOCAL[2], '{"schemaVersion":1,"enabled":true,"releasePolicy":"automatic-signed-schedule"}'),
            (m.LOCAL[3], '{"name":"different"}'),
            (m.LOCAL[1], '{"schemaVersion":true,"enabled":true,"releasePolicy":"manual-dispatch"}')]
        for path, content in mutations:
            with self.subTest(path=path), self.assertRaises(ValueError):
                snapshot = deepcopy(self.snapshot)
                self.update_file(snapshot["extensions"][0], path, content)
                m.plan(snapshot, self.heads)

    def test_registered_growth_has_no_seventeen_repository_limit(self):
        snapshot, heads = deepcopy(self.snapshot), deepcopy(self.heads)
        extra = deepcopy(snapshot["extensions"][0])
        extra["repository"] = "pgextwin/future_extension"
        manifest = json.loads(extra["files"][m.LOCAL[3]]["content"])
        manifest["name"] = "future_extension"
        self.update_file(extra, m.LOCAL[3], m.encode(manifest))
        snapshot["extensions"].append(extra)
        heads["heads"].append({k: v for k, v in extra.items() if k != "files"})
        central = snapshot["central"]
        fleet = json.loads(central["files"][m.CENTRAL[0]]["content"])
        member = deepcopy(fleet["entries"][0]); member["repository"] = extra["repository"]
        fleet["entries"].append(member)
        policy = json.loads(central["files"][m.CENTRAL[1]]["content"])
        policy["allowedRepositories"].append(extra["repository"])
        self.update_file(central, m.CENTRAL[0], m.encode(fleet))
        self.update_file(central, m.CENTRAL[1], m.encode(policy))
        result = m.plan(snapshot, heads)
        self.assertEqual(result["registeredExtensionCount"], len(snapshot["extensions"]))
        self.assertIn(extra["repository"], {r["repository"] for r in result["extensions"]})
        self.assertIs(result["applyEnabled"], False)

    def test_cli_rejects_duplicate_json_symlinks_and_activation_options(self):
        command = [sys.executable, str(ROOT / "scripts/publication-migration-plan.py")]
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}')
            for file in (path, Path(tmp) / "link.json"):
                if file != path:
                    file.symlink_to(EVIDENCE / "extension-snapshot.json")
                run = subprocess.run(command + ["--snapshot", str(file), "--heads", str(EVIDENCE / "observed-heads.json")], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(run.stdout)
            for option in ("--apply", "--policy-sha"):
                run = subprocess.run(command + ["--snapshot", str(EVIDENCE / "extension-snapshot.json"),
                    "--heads", str(EVIDENCE / "observed-heads.json"), option], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(run.stdout)

if __name__ == "__main__":
    unittest.main()
