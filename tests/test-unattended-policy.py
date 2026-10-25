#!/usr/bin/env python3
"""No-network regressions for the Step 22 static policy gate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

from publication_policy_fixtures import manual_policy
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("unattended_policy", ROOT / "scripts" / "unattended-policy.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestUnattendedPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = manual_policy("unattended-publication.json")
        cls.fleet = manual_policy("automation-fleet.json")

    def fixtures(self):
        return copy.deepcopy(self.policy), copy.deepcopy(self.fleet)

    def test_historical_manual_fixture_is_observe_only(self):
        p, f = self.fixtures()
        result = module.evaluate(p, f)
        self.assertEqual(result["status"], "OBSERVE_ONLY")
        self.assertFalse(result["automaticPublicationAuthorized"])

    def test_registered_fleet_growth_is_static_only_in_both_modes(self):
        p,f=self.fixtures()
        row=copy.deepcopy(f["entries"][0])
        row["repository"]="pgextwin/future_extension"
        f["entries"].append(row)
        self.assertEqual(module.evaluate(p,f)["status"],"OBSERVE_ONLY")
        p["mode"]="UNATTENDED"
        f["releasePolicy"]="automatic-signed-schedule"
        for entry in f["entries"]:
            entry["releasePolicy"]=f["releasePolicy"]
        for control in p["controls"]:
            p["controls"][control]=True
        result=module.evaluate(p,f)
        self.assertIn(row["repository"],result["eligibleRepositories"])
        self.assertEqual(len(result["eligibleRepositories"]),18)
        self.assertIs(result["automaticPublicationAuthorized"],False)

    def test_malformed_dynamic_roster_is_denied(self):
        mutations=(
            lambda p,f:f.update(entries=[]),
            lambda p,f:f["entries"].append(None),
            lambda p,f:f["entries"][0].update(repository=None),
            lambda p,f:f["entries"][0].update(repository="other/extension"),
            lambda p,f:f["entries"][0].update(repository="pgextwin/evil\n"),
            lambda p,f:f["entries"][0].update(candidateEnabled=1),
            lambda p,f:p.update(schemaVersion=True),
            lambda p,f:f.update(schemaVersion=True),
        )
        for number,mutate in enumerate(mutations):
            p,f=self.fixtures()
            mutate(p,f)
            with self.subTest(case=number),self.assertRaises(module.PolicyDenied):
                module.evaluate(p,f)

    def test_seventeen_build_candidates_do_not_authorize_unattended_release(self):
        p, f = self.fixtures()
        self.assertEqual(len([x for x in f["entries"] if x["mode"] == "BUILD"]), 17)
        self.assertEqual(module.evaluate(p, f)["status"], "OBSERVE_ONLY")
        p["mode"] = "UNATTENDED"
        for key in p["controls"]:
            p["controls"][key] = True
        result = module.evaluate(p, f)
        self.assertEqual(result["status"], "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")
        self.assertEqual(len(result["eligibleRepositories"]), 17)
        self.assertFalse(result["automaticPublicationAuthorized"])

    def test_observe_mode_cannot_merge_or_publish(self):
        for flag in module.AUTOMATIC_CONTROLS:
            with self.subTest(flag=flag):
                p, f = self.fixtures()
                p["controls"][flag] = True
                with self.assertRaises(module.PolicyDenied):
                    module.evaluate(p, f)

    def test_future_automatic_signed_policy_is_static_only_and_requires_all_controls(self):
        p,f=self.fixtures()
        f["releasePolicy"]="automatic-signed-schedule"
        for row in f["entries"]:
            row["releasePolicy"]="automatic-signed-schedule"
        # OBSERVE cannot be relabelled as an automatic-release policy.
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p,f)
        p["mode"]="UNATTENDED"
        for key in p["controls"]:
            p["controls"][key]=True
        future=module.evaluate(p,f)
        self.assertEqual(future["status"],
                         "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")
        self.assertIs(future["automaticPublicationAuthorized"],False)
        self.assertEqual(len(future["eligibleRepositories"]),17)
        for change in (
            lambda x:x["entries"][0].update(releasePolicy="manual-only"),
            lambda x:x["entries"].append(copy.deepcopy(x["entries"][0])),
            lambda x:x["entries"][0].update(candidateEnabled=False),
        ):
            bad=copy.deepcopy(f)
            change(bad)
            with self.assertRaises(module.PolicyDenied):
                module.evaluate(p,bad)
        incomplete=copy.deepcopy(p)
        incomplete["controls"]["requireSbomAttestation"]=False
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(incomplete,f)

    def test_unknown_field_and_missing_guard_are_denied(self):
        p, f = self.fixtures()
        p["unexpected"] = "allowed"
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)
        p, f = self.fixtures()
        del p["controls"]["requireSbomAttestation"]
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_non_boolean_switch_is_denied(self):
        p, f = self.fixtures()
        p["controls"]["automaticFormalRelease"] = "false"
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_partial_unattended_rollout_is_denied(self):
        p, f = self.fixtures()
        p["mode"] = "UNATTENDED"
        for key in p["controls"]:
            p["controls"][key] = True
        p["controls"]["requireBlockingVulnerabilityPolicy"] = False
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_even_full_static_policy_never_authorizes_release(self):
        p, f = self.fixtures()
        p["mode"] = "UNATTENDED"
        # The complete existing fleet may pass the static preflight, but
        # never becomes automatically authorized to sign or publish.
        for key in p["controls"]:
            p["controls"][key] = True
        result = module.evaluate(p, f)
        self.assertEqual(result["status"], "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")
        self.assertFalse(result["automaticPublicationAuthorized"])
        self.assertEqual(len(result["eligibleRepositories"]), 17)

    def test_registered_members_share_explicit_candidate_opt_in(self):
        for repo in (x["repository"] for x in self.fleet["entries"]
                     if x["repository"] != module.PILOT):
            with self.subTest(repository=repo):
                p,f=self.fixtures()
                item=next(x for x in f["entries"] if x["repository"]==repo)
                self.assertEqual(item["mode"],"BUILD")
                self.assertIs(item["candidateEnabled"],True)
                item["mode"]="WATCH"
                with self.assertRaises(module.PolicyDenied):
                    module.evaluate(p,f)
                item["candidateEnabled"]=False
                result=module.evaluate(p,f)
                self.assertEqual(result["status"],"OBSERVE_ONLY")
                self.assertIs(result["automaticPublicationAuthorized"],False)
                item["mode"]="OFF"
                item["candidateEnabled"]=False
                self.assertEqual(module.evaluate(p,f)["status"],"OBSERVE_ONLY")

    def test_fleet_fail_closed_on_duplicate_or_extra_build(self):
        p, f = self.fixtures()
        f["entries"][0]["repository"] = f["entries"][1]["repository"]
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)
        p, f = self.fixtures()
        f["entries"][0]["candidateEnabled"] = False
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_duplicate_roster_and_partial_build_never_authorize_release(self):
        p, f = self.fixtures()
        f["entries"].append(copy.deepcopy(f["entries"][-1]))
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)
        p, f = self.fixtures()
        p["mode"]="UNATTENDED"
        for key in p["controls"]: p["controls"][key]=True
        result=module.evaluate(p, f)
        self.assertEqual(result["status"], "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")
        self.assertFalse(result["automaticPublicationAuthorized"])
        p, f = self.fixtures()
        p["mode"] = "UNATTENDED"
        for key in p["controls"]: p["controls"][key] = True
        f["entries"][0]["mode"] = "WATCH"
        f["entries"][0]["candidateEnabled"] = False
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_fleet_cannot_silently_change_release_policy(self):
        p, f = self.fixtures()
        f["releasePolicy"] = "automatic"
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)

    def test_invalid_schedule_and_major_scope_are_denied(self):
        for key, bad in (("scheduleUtc", "0 1 * * *"),
                         ("requiredMajorVersions", [14, 15, 16, 17, 18]),
                         ("pilotRepository", "pgextwin/pg_ivm")):
            with self.subTest(key=key):
                p, f = self.fixtures()
                p[key] = bad
                with self.assertRaises(module.PolicyDenied):
                    module.evaluate(p, f)


if __name__ == "__main__":
    unittest.main()
