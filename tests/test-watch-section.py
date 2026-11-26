#!/usr/bin/env python3
"""Check candidate planning parity and fleet decisions during watch migration."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).with_name("fixtures") / "watch-section"
sys.path.insert(0, str(ROOT / "scripts"))
import update_watch_lib
from update_watch_lib import WatchError, load_watch, resolve_watch


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


candidate = load_script("candidate-update")
fleet = load_script("fleet-control")
validator = load_script("validate-update-watch")
detector = load_script("check-upstream-update")
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def read(path):
    return json.loads(path.read_text("utf-8"))


def watch_fixtures(name):
    extension = read(FIXTURES / f"{name}-extension.json")
    legacy = read(FIXTURES / f"{name}-update-watch.json")
    section = {key: value for key, value in legacy.items() if key not in {"repository", "schemaVersion"}}
    return extension, legacy, {**extension, "watch": section}


def stub_fetch(repository, strategy, *tags):
    prefix = f"https://api.github.com/repos/{repository}"
    listing = (
        {prefix + "/tags?per_page=100": [{"name": tag} for tag in tags]}
        if strategy == "github-tags"
        else {prefix + "/releases?per_page=100": [
            {"tag_name": tag, "draft": False, "prerelease": False,
             "html_url": f"https://github.com/{repository}/releases/tag/{tag}"}
            for tag in tags
        ]}
    )
    refs = {prefix + "/git/ref/tags/" + tag: {"object": {"type": "commit", "sha": COMMIT}}
            for tag in tags}
    responses = {**listing, **refs}
    return responses.__getitem__


class WatchSectionTests(unittest.TestCase):
    def test_candidate_plans_match(self):
        policy = candidate.publication_policy.load_candidate_policy(ROOT)
        for name, tags, majors in (
            ("orafce", ("VERSION_4_17_3",), [None]),
            ("pg_hint_plan", ("REL15_1_5_5", "REL19_1_9_1"), [15, 19]),
            ("pg_repack", ("ver_1.5.4",), [None]),
        ):
            with self.subTest(extension=name):
                extension, legacy, embedded = watch_fixtures(name)
                fetch = stub_fetch(legacy["repository"], legacy["strategy"], *tags)
                self.assertEqual(resolve_watch(embedded), legacy)
                old = candidate.plan(extension, legacy, policy, fetch=fetch)
                new = candidate.plan(embedded, None, policy, fetch=fetch)
                self.assertEqual(new["status"], "candidate")
                self.assertEqual([item["major"] for item in new["updates"]], majors)
                self.assertEqual([item["commit"] for item in new["updates"]], [COMMIT] * len(majors))
                self.assertEqual([item["ref"] for item in new["updates"]], list(tags))
                del old["detectedAt"], new["detectedAt"]
                self.assertEqual(new, old)

    def test_embedded_repository_and_unknown_fields(self):
        _, legacy, embedded = watch_fixtures("orafce")
        section = embedded["watch"]
        section["repository"] = legacy["repository"]
        self.assertEqual(resolve_watch(embedded), legacy)
        section["repository"] = "other/upstream"
        with self.assertRaisesRegex(WatchError, "repository must match"):
            resolve_watch(embedded)
        self.assertIs(resolve_watch(embedded, legacy), legacy)
        del section["repository"]
        section["schemaVersion"] = 1
        with self.assertRaisesRegex(WatchError, "section fields"):
            resolve_watch(embedded)

    def test_file_loading_falls_back_only_for_missing_file(self):
        extension, legacy, embedded = watch_fixtures("orafce")
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "update-watch.json"
            self.assertEqual(load_watch(embedded, path), legacy)
            with self.assertRaises(WatchError):
                load_watch(extension, path)
            path.write_text("{}", "utf-8")
            self.assertEqual(load_watch(embedded, path), {})
            path.write_text("null", "utf-8")
            with self.assertRaises(WatchError):
                load_watch(embedded, path)

    def test_validator_and_detector_watch_resolution(self):
        _, legacy, embedded = watch_fixtures("orafce")
        fetch = stub_fetch(legacy["repository"], legacy["strategy"], "VERSION_4_17_3")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, watch, output = (root / name for name in
                                       ("extension.json", "legacy-watch.json", "result.json"))
            inputs = ["--extension-config", str(manifest), "--watch-config", str(watch)]
            validate = [*inputs, "--schema", str(ROOT / "schema/update-watch.schema.json")]
            detect = [*inputs, "--output", str(output),
                      "--watcher-repository", "pgextwin/build", "--watcher-sha", COMMIT]
            for legacy_payload, extension, valid in (
                (None, embedded, True),
                (json.dumps(legacy), {**embedded, "watch": {"unexpected": True}}, True),
                ("null", embedded, False),
            ):
                with self.subTest(legacy=legacy_payload):
                    manifest.write_text(json.dumps(extension), "utf-8")
                    if legacy_payload is not None:
                        watch.write_text(legacy_payload, "utf-8")
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        with patch.object(sys, "argv", ["validate-update-watch.py", *validate]):
                            self.assertEqual(validator.main(), 0 if valid else 1)
                        with patch.object(detector, "github_get_json", side_effect=lambda url, token: fetch(url)):
                            with patch.object(sys, "argv", ["check-upstream-update.py", *detect]):
                                self.assertEqual(detector.main(), 0 if valid else 2)
                    result = read(output)
                    self.assertEqual(result["status"], "update-available" if valid else "indeterminate")
                    self.assertEqual(result["watcher"], {"repository": "pgextwin/build", "sha": COMMIT})

    def test_fleet_validation_and_decisions(self):
        _, legacy, embedded = watch_fixtures("orafce")
        watch = resolve_watch(embedded)
        registry = read(ROOT / "metadata" / "automation-fleet.json")
        entries = fleet.validate(registry)
        repo = "pgextwin/orafce"
        entry = entries[repo]
        policy = fleet.publication_policy.load_candidate_policy(ROOT)
        self.assertEqual(fleet.decide(registry, repo, embedded, watch, "candidate", policy), (True, "BUILD"))
        different_strategy = {**legacy, "strategy": "github-tags"}
        with self.assertRaisesRegex(WatchError, "strategy or upstream identity"):
            fleet.decide(registry, repo, embedded, different_strategy, "watch")

        del entry["strategy"], entry["scheduleUtc"]
        entry.pop("ownerSource", None)
        self.assertEqual(fleet.validate(registry)[repo], entry)
        self.assertEqual(fleet.decide(registry, repo, embedded, different_strategy, "watch"), (True, "BUILD"))
        with self.assertRaisesRegex(WatchError, "strategy or upstream identity"):
            fleet.decide(registry, repo, embedded, {**watch, "repository": "other/upstream"}, "watch")
        with self.assertRaises(WatchError):
            fleet.decide(registry, repo, embedded, watch, "candidate")

        for key, value in (("strategy", "unknown"), ("scheduleUtc", "0 1 * * *"),
                           ("ownerSource", 1), ("unknown", True)):
            with self.subTest(field=key):
                entry[key] = value
                with self.assertRaises(WatchError):
                    fleet.validate(registry)
                del entry[key]

    def test_missing_file_through_cli_and_proposer(self):
        _, legacy, embedded = watch_fixtures("orafce")
        registry = read(ROOT / "metadata" / "automation-fleet.json")
        fleet_response = {"encoding": "base64",
                          "content": base64.b64encode(json.dumps(registry).encode("utf-8")).decode("ascii")}
        fetch = stub_fetch(legacy["repository"], legacy["strategy"], "VERSION_4_17_3")
        repo = "pgextwin/orafce"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, output = root / "extension.json", root / "plan.json"
            manifest.write_text(json.dumps(embedded), "utf-8")
            inputs = ["--extension", str(manifest), "--watch", str(root / "update-watch.json")]
            with patch.dict(os.environ, {"GITHUB_OUTPUT": "", "GITHUB_REPOSITORY": repo,
                                         "GITHUB_REF": "refs/heads/main", "GH_TOKEN": "fixture-token"}):
                with patch.object(fleet, "get_live", return_value=registry), redirect_stdout(io.StringIO()) as stdout:
                    with patch.object(sys, "argv", ["fleet-control.py", *inputs,
                                                    "--repository", repo, "--action", "candidate"]):
                        self.assertEqual(fleet.main(), 0)
                    self.assertIs(json.loads(stdout.getvalue())["allowed"], True)
                with patch.object(candidate, "github_get_json", side_effect=lambda url, token: fetch(url)):
                    with patch.object(sys, "argv", ["candidate-update.py", "plan", *inputs, "--output", str(output)]):
                        with redirect_stdout(io.StringIO()):
                            self.assertEqual(candidate.main(), 0)
                    record = read(output)
                    self.assertEqual(record["status"], "candidate")
                    chain_query = ("gh", "pr", "list", "--repo", repo, "--head", record["branch"],
                                   "--state", "all", "--limit", "100", "--json",
                                   "number,body,state,url,headRefOid,headRefName,baseRefName,"
                                   "isDraft,isCrossRepository")
                    branch_lookup = ("git", "ls-remote", "--heads", "origin",
                                     "refs/heads/" + record["branch"])
                    # The proposer resolves the effective candidate branch by walking
                    # the candidate-PR chain before any branch lookup or write, so a
                    # failed chain query aborts the proposal at the first remote call.
                    with patch.object(update_watch_lib, "github_get_json", return_value=fleet_response), \
                         patch.object(candidate, "execute", side_effect=WatchError("stop at remote branch lookup")) as execute:
                        with self.assertRaisesRegex(WatchError, "stop at remote branch lookup"):
                            candidate.propose(record, manifest, repo, root / "update-watch.json")
                        execute.assert_called_once_with(*chain_query)
                    # With no candidate PR in the chain, the remote branch lookup
                    # follows with its original arguments, and its failure aborts too.
                    def fail_at_branch_lookup(*args):
                        if args[0] == "git":
                            raise WatchError("stop at remote branch lookup")
                        return "[]"
                    with patch.object(update_watch_lib, "github_get_json", return_value=fleet_response), \
                         patch.object(candidate, "execute", side_effect=fail_at_branch_lookup) as execute:
                        with self.assertRaisesRegex(WatchError, "stop at remote branch lookup"):
                            candidate.propose(record, manifest, repo, root / "update-watch.json")
                        self.assertEqual(execute.call_args_list, [call(*chain_query), call(*branch_lookup)])
            self.assertEqual(read(manifest), embedded)


if __name__ == "__main__":
    unittest.main()
