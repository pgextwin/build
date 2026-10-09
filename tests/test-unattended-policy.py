#!/usr/bin/env python3
"""No-network regressions for the Step 22 static policy gate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("unattended_policy", ROOT / "scripts" / "unattended-policy.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestUnattendedPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "metadata" / "unattended-publication.json").read_text())
        cls.fleet = json.loads((ROOT / "metadata" / "automation-fleet.json").read_text())

    def fixtures(self):
        return copy.deepcopy(self.policy), copy.deepcopy(self.fleet)

    def test_current_deployment_is_observe_only(self):
        p, f = self.fixtures()
        result = module.evaluate(p, f)
        self.assertEqual(result["status"], "OBSERVE_ONLY")
        self.assertFalse(result["automaticPublicationAuthorized"])

    def test_observe_mode_cannot_merge_or_publish(self):
        for flag in module.AUTOMATIC_CONTROLS:
            with self.subTest(flag=flag):
                p, f = self.fixtures()
                p["controls"][flag] = True
                with self.assertRaises(module.PolicyDenied):
                    module.evaluate(p, f)

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
        for key in p["controls"]:
            p["controls"][key] = True
        result = module.evaluate(p, f)
        self.assertEqual(result["status"], "POLICY_READY_RUNTIME_EVIDENCE_REQUIRED")
        self.assertFalse(result["automaticPublicationAuthorized"])

    def test_fleet_fail_closed_on_duplicate_or_extra_build(self):
        p, f = self.fixtures()
        f["entries"][0]["repository"] = f["entries"][1]["repository"]
        with self.assertRaises(module.PolicyDenied):
            module.evaluate(p, f)
        p, f = self.fixtures()
        f["entries"][0]["mode"] = "BUILD"
        f["entries"][0]["candidateEnabled"] = True
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
