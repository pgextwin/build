#!/usr/bin/env python3
"""Deployed signed-chain names from real REST metadata, never signature fixtures."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("signed_source_job_contract", ROOT / "scripts/signed-source-jobs.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ORIGINAL = json.loads((ROOT / "tests/fixtures/signed-source-jobs-plpgsql-40250416760.json").read_text())

def verify(d):
    return m.verify(d["run"], d["jobs"], repository=d["repository"],
        sha=d["sha"], run_id=d["run"]["id"], attempt=1, majors=d["majors"])

class SignedSourceJobs(unittest.TestCase):
    def test_actual_original_signed_chain_and_both_independent_jobs(self):
        d = deepcopy(ORIGINAL)
        result = verify(d)
        self.assertEqual(len(result), 9)
        self.assertIn(("Authenticate main merge and scheduled decision (NONPUBLISHING) / "
            "Authenticate protected candidate merge from real GitHub bytes", 121340866998), result)
        self.assertIn(("Independently verify signed candidate bytes and identity (NO PUBLISH) / "
            "Independently reverify signed candidate before future Publisher (NO PUBLISH)",
            121344303962), result)
        self.assertNotIn("publicationAuthorized", str(result))

    def test_each_required_job_must_succeed_once(self):
        good_names = {name for name, _ in verify(ORIGINAL)}
        for name in good_names:
            for variant in ("missing", "duplicate", "failure", "skipped", "in_progress"):
                d = deepcopy(ORIGINAL)
                item = next(j for j in d["jobs"]["jobs"] if j["name"] == name)
                if variant == "missing":
                    d["jobs"]["jobs"].remove(item)
                elif variant == "duplicate":
                    duplicate = deepcopy(item); duplicate["id"] += 999999
                    d["jobs"]["jobs"].append(duplicate)
                elif variant == "in_progress": item.update(status=variant, conclusion=None)
                else: item["conclusion"] = variant
                d["jobs"]["total_count"] = len(d["jobs"]["jobs"])
                with self.subTest(name=name, variant=variant), self.assertRaises(m.Denied):
                    verify(d)

    def test_original_run_head_attempt_and_check_urls_are_bound(self):
        for mutation in (
            lambda d: d["run"].update(event="workflow_dispatch"),
            lambda d: d["run"].update(conclusion="failure"),
            lambda d: d["run"].update(run_attempt=2),
            lambda d: d["jobs"]["jobs"][0].update(run_id=1),
            lambda d: d["jobs"]["jobs"][0].update(run_attempt=2),
            lambda d: d["jobs"]["jobs"][0].update(head_sha="a" * 40),
            lambda d: d["jobs"]["jobs"][0].update(check_run_url="https://example.test/check"),
            lambda d: d["jobs"]["jobs"][0].update(html_url="https://github.com/pgextwin/hypopg/actions/runs/1/job/2"),
            lambda d: d["jobs"].update(total_count=100),
            lambda d: d["jobs"].update(total_count=1),
        ):
            d = deepcopy(ORIGINAL); mutation(d)
            with self.subTest(mutation=str(mutation)), self.assertRaises(m.Denied): verify(d)

    def test_matrix_comes_from_manifest_not_fixed_count(self):
        d = deepcopy(ORIGINAL)
        d["majors"] = [16, 17, 18]
        with self.assertRaises(m.Denied): verify(d)  # Extra signed lanes are not silently accepted.
        d["jobs"]["jobs"] = [j for j in d["jobs"]["jobs"]
            if " / PostgreSQL 14 / " not in j["name"] and " / PostgreSQL 15 / " not in j["name"]]
        d["jobs"]["total_count"] = len(d["jobs"]["jobs"])
        self.assertEqual(len(verify(d)), 7)
        d["majors"] = [16, 17, 18, 19]
        with self.assertRaises(m.Denied): verify(d)
        for bad in ([], [True], [18, 18], [18, 17], "18"):
            d["majors"] = bad
            with self.subTest(majors=bad), self.assertRaises(m.Denied): verify(d)

    def test_obsolete_aggregate_names_cannot_fake_the_active_chain(self):
        d = deepcopy(ORIGINAL)
        d["jobs"]["jobs"][0]["name"] = "Audit real single manifest-only protected candidate main push"
        with self.assertRaises(m.Denied): verify(d)
        d = deepcopy(ORIGINAL)
        d["jobs"]["jobs"] = [j for j in d["jobs"]["jobs"] if " / PostgreSQL " not in j["name"]]
        d["jobs"]["total_count"] = len(d["jobs"]["jobs"])
        with self.assertRaises(m.Denied): verify(d)

if __name__ == "__main__": unittest.main()
