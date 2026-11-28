#!/usr/bin/env python3
"""Offline coverage of the central candidate enforcement contract."""

from datetime import datetime, timezone
import base64
import hashlib
from importlib import import_module
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import local_auth_central as central

NOW = datetime(2026, 11, 28, tzinfo=timezone.utc)
EXTENSION = "pg_bigm"
EXT_ROOT = f"extensions/{EXTENSION}"
MANIFEST = f"{EXT_ROOT}/extension.json"
OTHER = "extensions/pgaudit/extension.json"
POLICY_PATH = "metadata/local-candidate-authority.json"
POLICY = json.loads((ROOT / POLICY_PATH).read_text(encoding="utf-8"))
CANDIDATE_ID = "a" * 20
BRANCH = f"auto-candidate/{EXTENSION}/{CANDIDATE_ID}"


def change(filename, status="modified", **fields):
    return {"filename": filename, "status": status, **fields}


class NameStatusParserTests(unittest.TestCase):
    def test_tc01_supported_statuses_and_input_types(self):
        data = "A\0added\0C075\0old\0copy\0D\0deleted\0M\0変.json\0R100\0old\0new\0T\0type\0"
        expected = [
            change("added", "added"), change("copy", "copied", previous_filename="old"),
            change("deleted", "removed"), change("変.json"),
            change("new", "renamed", previous_filename="old"), change("type", "changed"),
        ]
        for value in (data, data.encode(), bytearray(data.encode())):
            self.assertEqual(central.changes_from_name_status(value), expected)
        self.assertEqual(central.changes_from_name_status(""), [])

    def test_tc01_rejects_malformed_streams(self):
        for data in (None, b"U\0x\0", b"X\0x\0", b"R\0x\0y\0", b"C101\0x\0y\0",
                     b"R0000\0x\0y\0", b"R-1\0x\0y\0", "R²\0x\0y\0",
                     b"M1\0x\0", b"R100\0x\0", b"M\0x", b"M\tfile\n", b"M\0\0",
                     b"\0", b"M\0x\0\0", b"M\0\xff\0", b"M\0a\nb\0", b"C0\0a\x7f\0b\0"):
            with self.subTest(data=data), self.assertRaises(central.TicketRejected) as caught:
                central.changes_from_name_status(data)
            self.assertEqual(caught.exception.code, "MALFORMED_CHANGE")


class ClassificationAndEnforcementTests(unittest.TestCase):
    def enforce(self, changes=None, **overrides):
        args = dict(policy=POLICY, now=NOW, repository=central.CENTRAL_REPOSITORY, extension=EXTENSION,
                    registered_extensions={EXTENSION, "pgaudit", "pg_permissions"}, branch=BRANCH,
                    changes=[change(MANIFEST)] if changes is None else changes)
        return central.enforce_central_candidate(**(args | overrides))

    def rejected(self, code, changes=None, **overrides):
        with self.assertRaises(central.TicketRejected) as caught:
            self.enforce(changes, **overrides)
        self.assertEqual(caught.exception.code, code)

    def paths_rejected(self, code, paths):
        for path in paths:
            with self.subTest(path=path):
                self.rejected(code, [change(path)])
                self.rejected(code, [change(MANIFEST), change(path)])

    def test_tc02_p1_positive(self):
        self.assertEqual(central.classify_central_path(MANIFEST), ("P1", EXTENSION))
        evidence = self.enforce()
        self.assertEqual(evidence["target"]["pathClasses"], ["P1"])  # NC-01
        patched = f"{EXT_ROOT}/patches/fix.patch"
        result = self.enforce([change(patched, "added")], scope_mode="extension_subtree")
        self.assertEqual(result["target"]["paths"], [patched])  # NC-02
        self.rejected("CANDIDATE_CHANGE_DENIED", [change(f"{EXT_ROOT}/adapter.ps1")])  # NC-08
        self.rejected("CANDIDATE_CHANGE_DENIED", [change(MANIFEST), change(f"{EXT_ROOT}/README.md")])
        for status in ("added", "unchanged"):
            self.rejected("CANDIDATE_CHANGE_DENIED", [change(MANIFEST, status)])

    def test_tc03_cross_extension_and_prefix_boundary_rejected(self):
        for name in ("pgaudit", "pg_bigm_extra", "pg_bigm2", "ghost_ext"):  # NC-03–05
            with self.subTest(name=name):
                self.rejected("CROSS_EXTENSION_DENIED", [change(f"extensions/{name}/extension.json")])
        self.rejected("CROSS_EXTENSION_DENIED", [change("extensions/pg_bigm_extra/extension.json")],
                      registered_extensions={EXTENSION, "pg_bigm_extra"})
        self.rejected("EXTENSION_NOT_REGISTERED", registered_extensions=set())
        self.rejected("INVALID_EXTENSION_NAME", extension="com0")
        self.rejected("CENTRAL_REPOSITORY_MISMATCH", repository="pgextwin/pg_bigm")

    def test_tc04_p2_multi_extension_rejected(self):
        permission = "extensions/pg_permissions/extension.json"
        for paths in ((MANIFEST, OTHER), (MANIFEST, OTHER, permission), (OTHER, permission)):  # NC-09–10
            with self.subTest(paths=paths):
                self.rejected("PATH_CLASS_P2_DENIED", [change(path) for path in paths])

    def test_tc05_p3_shared_build_rejected(self):
        self.paths_rejected("PATH_CLASS_P3_DENIED", (  # NC-11–13
            "scripts/central-package.py", "common/helper.ps1", "windows/build.ps1",
            "tests/test-ci-router.py", "schema/central-extension.schema.json", "scripts/ci-router.py"))

    def test_tc06_p4_ci_infrastructure_rejected(self):
        self.paths_rejected("PATH_CLASS_P4_DENIED", (  # NC-14–15
            ".github/workflows/validate.yml", ".github/workflows/build-extension.yml"))

    def test_tc07_p5_auth_signing_publisher_highest_priority(self):
        self.paths_rejected("PATH_CLASS_P5_DENIED", (  # NC-16–19
            POLICY_PATH, POLICY_PATH.upper(), "metadata/automation-fleet.json",
            "Schema/Local-Candidate-Authority.Schema.JSON",
            ".GITHUB/Workflows/Local-Authorized-Candidate.yml",
            ".github/workflows/build-extension-attested.yml", ".github/workflows/publisher-candidate-intake.yml",
            "Scripts/Local-Auth-Candidate.py", "scripts/local_auth_central.py", "scripts/fleet-publish-release.py"))
        self.rejected("PATH_CLASS_P5_DENIED", [
            change("scripts/ci-router.py"), change(".github/workflows/validate.yml"), change(POLICY_PATH)])

    def test_tc08_p6_docs_rejected(self):
        self.paths_rejected("PATH_CLASS_P6_DENIED", ("docs/local-auth-live.md",))  # NC-20

    def test_tc09_p7_unclassified_fail_closed(self):
        self.paths_rejected("PATH_CLASS_P7_DENIED", (  # NC-21–25
            "unknown/file.txt", "scratch/tmp.json", "README.md", "README_ja.md", "LICENSE",
            "config/extension.json", "evidence/x.json", "templates/extension/README.md",
            ".github/dependabot.yml", ".github/execution-requests/x.json",
            "extensions/stray.txt", "extensions/extension.json"))

    def test_tc10_rename_and_copy_both_sides_enforced(self):
        for path, code in (  # NC-26–30
            (OTHER, "PATH_CLASS_P2_DENIED"), ("config/extension.json", "PATH_CLASS_P7_DENIED"),
            ("metadata/leak.json", "PATH_CLASS_P5_DENIED"), ("scripts/x.py", "PATH_CLASS_P3_DENIED"),
            (".github/workflows/validate.yml", "PATH_CLASS_P4_DENIED"), ("docs/x.md", "PATH_CLASS_P6_DENIED"),
            ("extensions/PG_BIGM/old.json", "INVALID_PATH"),
        ):
            for old, new in ((path, MANIFEST), (MANIFEST, path)):
                with self.subTest(old=old, new=new):
                    self.rejected(code, [change(new, "renamed", previous_filename=old)])
        self.rejected("MALFORMED_CHANGE", [change(MANIFEST, "renamed")])  # NC-31
        self.rejected("PATH_CLASS_P2_DENIED", [  # NC-32
            change(MANIFEST, "copied", previous_filename="extensions/pgaudit/adapter.ps1")])
        for status in ("renamed", "copied"):  # NC-33 and same-extension copy
            changes = [change(f"{EXT_ROOT}/b.patch", status, previous_filename=f"{EXT_ROOT}/a.patch")]
            self.assertEqual(self.enforce(changes, scope_mode="extension_subtree")["target"]["paths"],
                             [f"{EXT_ROOT}/a.patch", f"{EXT_ROOT}/b.patch"])
            self.rejected("CANDIDATE_CHANGE_DENIED", changes)

    def test_tc11_delete_typechange_empty_and_windows_path_rejected(self):
        self.rejected("CROSS_EXTENSION_DENIED", [change(OTHER, "removed")])  # NC-34
        self.rejected("PATH_CLASS_P2_DENIED", [change(MANIFEST), change(OTHER, "removed")])  # NC-35
        self.rejected("CANDIDATE_CHANGE_DENIED", [change(MANIFEST, "removed")])  # NC-36
        for kind, path in (("P5", POLICY_PATH), ("P4", ".github/workflows/validate.yml"),
                           ("P3", "scripts/ci-router.py"), ("P7", "README.md")):  # NC-37
            self.rejected(f"PATH_CLASS_{kind}_DENIED", [change(path, "removed")])
        self.rejected("TYPECHANGE_DENIED", [change(MANIFEST, "changed")])  # NC-38
        self.rejected("EMPTY_CHANGE_SET", [])
        for path in ("Extensions/pg_bigm/extension.json", "extensions/PG_BIGM/extension.json",  # NC-06–07
                     f"{EXT_ROOT}/../pgaudit/extension.json", f"{EXT_ROOT}/CON.json",
                     f"{EXT_ROOT}/file .json", "/" + MANIFEST, MANIFEST.replace("/", "\\"),
                     f"{EXT_ROOT}/file.", f"{EXT_ROOT}/file ", f"{EXT_ROOT}/LPT0.txt",
                     f"{EXT_ROOT}/x\x7f.json", f"{EXT_ROOT}//file", f"{EXT_ROOT}/./file"):
            with self.subTest(path=path):
                self.rejected("INVALID_PATH", [change(path)])
        for invalid in ({}, [None], [change("")], [change(MANIFEST, [])],
                        [change(MANIFEST, "moved")], [change(MANIFEST, previous_filename=None)],
                        [change(MANIFEST, "renamed", previous_filename=1)]):
            self.rejected("MALFORMED_CHANGE", invalid)

    def test_tc12_branch_extension_and_legacy_reuse_controls(self):
        self.rejected("BRANCH_EXTENSION_MISMATCH", branch=f"auto-candidate/pgaudit/{CANDIDATE_ID}")  # NC-39
        legacy_branch = f"auto-candidate/{CANDIDATE_ID}"
        self.rejected("LEGACY_BRANCH_NOT_ALLOWED", branch=legacy_branch)  # NC-40
        self.assertTrue(self.enforce(branch=legacy_branch, allow_legacy_reuse=True)["authorized"])
        self.rejected("CROSS_EXTENSION_DENIED", [change(OTHER)], branch=legacy_branch, allow_legacy_reuse=True)
        self.rejected("BRANCH_CANDIDATE_ID_MISMATCH", expected_candidate_id="b" * 20)
        for invalid in ("auto-candidate/pg_bigm", "auto-candidate/pg_bigm/aaaa",
                        BRANCH + "\n", BRANCH.upper(), BRANCH + "/extra"):
            self.rejected("INVALID_CANDIDATE_BRANCH", branch=invalid)

    def test_tc13_deny_precedence_epoch_and_priority_order(self):
        self.rejected("DENY_MODE", [], policy={"mode": "DENY", "publication": True},
                      operation="sign", now=False, branch="bad", auth_binding={"ticket": []})
        self.rejected("INVALID_POLICY", policy=[])
        self.rejected("MODE_NOT_IMPLEMENTED", policy={"mode": "OBSERVE"})
        self.rejected("INVALID_CLOCK", now="2026-11-28")
        self.rejected("OUTSIDE_DELEGATION", now=datetime(2026, 12, 22, 15, tzinfo=timezone.utc))
        self.rejected("DELEGATION_UNSET", policy=dict(POLICY, delegationStartsAt=None))
        ticket = {"policyEpoch": 1, "issuerKeyId": POLICY["issuerKeyId"]}
        newer = dict(POLICY, policyEpoch=2)
        self.rejected("EPOCH_MISMATCH", policy=newer, auth_binding={"ticket": ticket})  # NC-41
        self.rejected("EPOCH_REVOKED", policy=dict(newer, revokedPolicyEpochs=[1]),
                      auth_binding={"ticket": ticket})
        self.rejected("ISSUER_MISMATCH", auth_binding={"ticket": dict(ticket, issuerKeyId="old")})
        ordered = [("P5", POLICY_PATH), ("P7", "README.md"), ("P4", ".github/workflows/validate.yml"),
                   ("P3", "scripts/ci-router.py"), ("P6", "docs/x.md"), ("P2", MANIFEST)]
        for index, (kind, _) in enumerate(ordered):
            changes = [change(path) for _, path in reversed(ordered[index:])] + [change(OTHER)]
            self.rejected(f"PATH_CLASS_{kind}_DENIED", changes)
        self.rejected("CROSS_EXTENSION_DENIED", [change(OTHER)])
        self.rejected("INVALID_PATH", [change(POLICY_PATH), change("/" + MANIFEST)])
        self.rejected("TYPECHANGE_DENIED", [change(POLICY_PATH), change(MANIFEST, "changed")])

    def test_tc14_publish_deny_and_requalify_rejected(self):
        self.rejected("PUBLICATION_DENIED", publication=True)  # NC-42
        self.rejected("PUBLICATION_DENIED", policy=dict(POLICY, publication=0))
        self.rejected("OPERATION_NOT_ALLOWED", operation="requalify")
        self.rejected("OPERATION_NOT_ALLOWED", operation="publish")
        result = self.enforce()
        self.assertIs(result["authorized"], True)
        self.assertIs(result["publication"], False)

    def run_claim_binding(self):
        repository = central.CENTRAL_REPOSITORY
        request_id = "b" * 32
        inputs = {"operation": "candidate", "repository": repository, "consumerRunId": 100,
                  "centralScope": central.central_scope(EXTENSION, BRANCH)}
        ticket = {"operation": "candidate", "repository": repository, "requestId": request_id,
                  "policyEpoch": POLICY["policyEpoch"], "issuerKeyId": POLICY["issuerKeyId"],
                  "inputsSha256": hashlib.sha256(central.canonical_json(inputs)).hexdigest()}
        live = {"authorized": False, "publication": False, "requestId": request_id,
                "issuerRepository": "pgextwin/local-auth-issuer", "issuerRunId": 120, "issuerRunAttempt": 1,
                "claimCommitSha": "c" * 40, "ticketSha256": "d" * 64}
        return {"ticket": ticket, "inputs_obj": inputs, "live_evidence": live, "consumer_run_id": 100}

    def test_nc43_run_claim_change_evidence_requires_all_bindings(self):
        binding = self.run_claim_binding()
        ticket, inputs, live = (binding[key] for key in ("ticket", "inputs_obj", "live_evidence"))
        evidence = self.enforce(auth_binding=binding)
        self.assertEqual(evidence["consumerRun"]["runId"], 100)
        self.assertEqual(evidence["issuerRun"]["runId"], 120)
        self.assertEqual(evidence["claim"]["requestId"], ticket["requestId"])
        for overrides in (
            {"consumer_run_id": 101},
            {"ticket": dict(ticket, inputsSha256="e" * 64)},
            {"inputs_obj": {key: value for key, value in inputs.items() if key != "centralScope"}},
            {"live_evidence": dict(live, requestId="a" * 32)},
            {"live_evidence": dict(live, authorized=True)},
            {"live_evidence": dict(live, publication=True)},
            {"live_evidence": {key: value for key, value in live.items() if key != "claimCommitSha"}},
        ):
            with self.subTest(overrides=overrides):
                self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH", auth_binding=binding | overrides)

    def test_required_binding_runs_at_step_eight_after_policy_and_path_checks(self):
        options = {"require_binding": True, "auth_binding": None}
        self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH", **options)
        self.rejected("DENY_MODE", [change("README.md")], policy=dict(POLICY, mode="DENY"), **options)
        self.rejected("PATH_CLASS_P7_DENIED", [change("README.md")], **options)

    def test_signed_branch_matches_only_same_candidate_on_legacy_reuse(self):
        options = {"require_binding": True, "auth_binding": self.run_claim_binding()}
        legacy = f"auto-candidate/{CANDIDATE_ID}"
        result = self.enforce(branch=legacy, expected_candidate_id=CANDIDATE_ID,
                              allow_legacy_reuse=True, **options)
        self.assertEqual(result["target"]["branch"], legacy)

        successor_id = "b" * 20
        self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH", branch=f"auto-candidate/{successor_id}",
                      expected_candidate_id=successor_id, allow_legacy_reuse=True, **options)
        self.rejected("RUN_CLAIM_CHANGE_BINDING_MISMATCH", branch=f"auto-candidate/{EXTENSION}/{successor_id}",
                      expected_candidate_id=successor_id, allow_legacy_reuse=False, **options)

    def test_tc19_checked_in_authority_remains_unactivated_for_central(self):
        authority = import_module("local-auth-candidate")
        sha = "a" * 40
        base = authority.API + central.CENTRAL_REPOSITORY
        self.assertEqual(POLICY["policyEpoch"], 1)

        def fetch(url):
            if url == base + "/branches/main":
                return {"name": "main", "protected": True, "commit": {"sha": sha}}
            path = url.removeprefix(base + "/contents/").removesuffix(f"?ref={sha}")
            self.assertIn(path, (POLICY_PATH, authority.MANIFEST))
            raw = (ROOT / path).read_bytes()
            blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            return {"path": path, "encoding": "base64", "sha": blob, "content": base64.b64encode(raw).decode()}

        with patch.object(authority.candidate, "execute", return_value=sha), \
                self.assertRaises(central.TicketRejected) as caught:
            authority.prepare(central.CENTRAL_REPOSITORY, sha, 100, fetch=fetch, now=NOW, extension=EXTENSION)
        self.assertEqual(caught.exception.code, "REPO_NOT_IN_FLEET")


if __name__ == "__main__":
    unittest.main()
