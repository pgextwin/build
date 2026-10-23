#!/usr/bin/env python3
"""Hostile fixtures for the independent live signed-Publisher boundary."""
from __future__ import annotations
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


live = load("automatic_publisher_live", "scripts/automatic-publisher-live-preflight.py")
hand = load("automatic_handoff_for_live", "tests/test-automatic-publisher-handoff.py")
REPO = hand.REPO
SHA = hand.SHA
RUN = hand.RUN


def fixture():
    return {
        "handoff": hand.handoff.handoff(**hand.fixture()),
        "branch": {"name": "main", "protected": True,
                   "commit": {"sha": SHA}},
        "run": {"id": RUN, "run_attempt": 1,
                "repository": {"full_name": REPO},
                "head_sha": SHA, "head_branch": "main",
                "event": "push", "path": ".github/workflows/update-watch.yml",
                "status": "in_progress", "conclusion": None},
        "fleet": json.loads((ROOT / "metadata/automation-fleet.json").read_text()),
        "central": json.loads((ROOT / "metadata/release-promotion.json").read_text()),
        "local": {"schemaVersion": 1, "enabled": True,
                  "releasePolicy": "manual-dispatch"},
        "unattended": json.loads(
            (ROOT / "metadata/unattended-publication.json").read_text()),
        "repository": REPO, "sha": SHA, "run_id": RUN,
        "attempt": 1, "event": "push", "ref": "refs/heads/main",
        "tag_absent": True, "release_absent": True,
    }


class IndependentLivePublisherTests(unittest.TestCase):
    def test_valid_observation_never_grants_write(self):
        got = live.assess(**fixture())
        self.assertEqual(got["status"],
                         "LIVE_SIGNED_HANDOFF_RECHECK_NONPUBLISHING")
        self.assertTrue(got["tagAndReleaseAbsentAtObservation"])
        self.assertTrue(got["mustRecheckAndReserveTagInIndependentPublisher"])
        self.assertEqual(len(got["policyBlockers"]), 5)
        for k in ("publicationAuthorized", "publishableReceipt",
                  "publisherWriteEnabled", "automaticReleaseEnabled"):
            self.assertIs(got[k], False)
        for k in ("goB", "g4", "g5"):
            self.assertEqual(got[k], "NO_GO")
        for forbidden in ("GH_TOKEN", "authorizationMode", "operator",
                          "confirmRelease", "releaseId", "token"):
            self.assertNotIn(forbidden, got)

    def test_full_seventeen_same_nonpublishing_result(self):
        for row in fixture()["fleet"]["entries"]:
            with self.subTest(repo=row["repository"]):
                obj = fixture()
                name = row["repository"]
                obj["repository"] = name
                obj["handoff"]["repository"] = name
                obj["run"]["repository"]["full_name"] = name
                self.assertIs(live.assess(**obj)["publisherWriteEnabled"], False)

    def test_forged_identity_and_policy_never_accepted(self):
        modifications = [
            lambda x: x.update(event="workflow_dispatch"),
            lambda x: x.update(ref="refs/heads/other"),
            lambda x: x.update(attempt=2),
            lambda x: x.update(attempt=True),
            lambda x: x.update(run_id=RUN + 1),
            lambda x: x.update(sha="b" * 40),
            lambda x: x.update(repository="pgextwin/evil"),
            lambda x: x.update(tag_absent=False),
            lambda x: x.update(release_absent=False),
            lambda x: x.update(tag_absent="true"),
            lambda x: x["branch"].update(protected=False),
            lambda x: x["branch"].update(name="other"),
            lambda x: x["branch"]["commit"].update(sha="b" * 40),
            lambda x: x["run"].update(run_attempt=2),
            lambda x: x["run"].update(event="schedule"),
            lambda x: x["run"].update(status="completed", conclusion="success"),
            lambda x: x["run"].update(path=".github/workflows/promote.yml"),
            lambda x: x["run"].update(head_sha="b" * 40),
            lambda x: x["run"]["repository"].update(full_name="pgextwin/other"),
            lambda x: x["handoff"].update(publisherWriteEnabled=True),
            lambda x: x["handoff"].update(publicationAuthorized=True),
            lambda x: x["handoff"].update(status="PUBLISH_READY"),
            lambda x: x["handoff"].update(runAttempt=2),
            lambda x: x["handoff"].update(independentSigstoreSecondOpinion=False),
            lambda x: x["handoff"].update(tagProposal="../escape"),
            lambda x: x["handoff"].update(g4="GO"),
            lambda x: x["handoff"]["policyBlockers"].append("EXTRA"),
            lambda x: x["fleet"].update(releasePolicy="automatic"),
            lambda x: x["fleet"]["entries"].pop(),
            lambda x: x["fleet"]["entries"].append(
                deepcopy(x["fleet"]["entries"][0])),
            lambda x: x["central"].update(releasePolicy="automatic"),
            lambda x: x["central"]["allowedRepositories"].pop(),
            lambda x: x["local"].update(releasePolicy="automatic"),
            lambda x: x["unattended"].update(mode="UNATTENDED"),
            lambda x: x["unattended"].update(defaultAction="ALLOW"),
            lambda x: x["unattended"]["controls"].update(
                automaticFormalRelease=True),
        ]
        for n, mutate in enumerate(modifications):
            with self.subTest(case=n), self.assertRaises(live.Denied):
                obj = fixture()
                mutate(obj)
                live.assess(**obj)

    def test_live_policy_uses_actual_github_blob_not_self_claimed_json(self):
        content = (ROOT / "metadata/release-promotion.json").read_bytes()
        path = "metadata/release-promotion.json"
        response = {
            "path": path, "encoding": "base64",
            "sha": live.blob_sha(content),
            "content": base64.b64encode(content).decode()
        }
        self.assertEqual(live.verified_live_file(response,path,content),
                         fixture()["central"])
        for corrupt in (
            {**response,"sha": "a" * 40},
            {**response,"content": base64.b64encode(b"{}").decode()},
            {**response,"path": "metadata/other.json"},
            {**response,"encoding": "utf-8"},
        ):
            with self.assertRaises(live.Denied):
                live.verified_live_file(corrupt,path,content)

    def test_read_only_get_url_is_strict_and_404_cannot_hide_access_denial(self):
        with patch.object(live.subprocess, "run",
                          side_effect=AssertionError("no network")):
            for suffix in ("actions/runs/3;curl evil", "releases",
                           "git/ref/heads/main", "git/ref/tags/../evil"):
                with self.assertRaises(live.Denied):
                    live.github(REPO,suffix)
        not_found = subprocess.CompletedProcess(
            [],1,stdout="",stderr="gh: Not Found (HTTP 404)")
        forbidden = subprocess.CompletedProcess(
            [],1,stdout="",stderr="gh: Resource not accessible (HTTP 403)")
        with patch.object(live.subprocess,"run",return_value=not_found):
            self.assertIsNone(live.github(REPO,
                "releases/tags/v1.0-windows.1",not_found=True))
        with patch.object(live.subprocess,"run",return_value=forbidden):
            with self.assertRaises(live.Denied):
                live.github(REPO,"releases/tags/v1.0-windows.1",
                            not_found=True)

    def test_publisher_live_stage_has_no_write_scope_or_api(self):
        workflow = (ROOT / ".github/workflows/verify-signed-candidate-readonly.yml").read_text()
        code = (ROOT / "scripts/automatic-publisher-live-preflight.py").read_text()
        self.assertIn("automatic-publisher-live-preflight.py",workflow)
        self.assertIn("automatic-publisher-live-policy-recheck-nonpublishing.json",workflow)
        region = workflow.split("  publisher_second_opinion:",1)[1]
        self.assertNotIn("contents: write",region)
        self.assertNotIn("id-token: write",region)
        for needle in ("--method\", \"GET", "publisherWriteEnabled\": False"):
            self.assertIn(needle,code)
        for forbidden in ("gh release create", "gh release upload",
                          "gh api --method POST", "gh workflow run",
                          "subprocess.run([\"git\", \"push"):
            self.assertNotIn(forbidden,code)


if __name__ == "__main__":
    unittest.main()
