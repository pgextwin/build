#!/usr/bin/env python3
"""Issue75 Work GUI testimony is report-only; no real credentials or GO."""
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "issue75_gui_negative", ROOT/"scripts/issue-75-work-gui-readiness.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def fixture():
    return p.parse(p.GUI.read_bytes())

class GuiNegativeTests(TestCase):
    def test_gui_report_is_only_reported_provenance_not_authenticated_live(self):
        v=p.inspect(fixture())
        self.assertEqual(v["guiEvidenceProvenance"],"REPORTED_NOT_REAUTHENTICATED")
        self.assertEqual(v["withinPgextwinPrivateRepo"],"REPORTED_ABSENT")
        self.assertEqual(v["withinPgextwinEnvironments"],"REPORTED_ABSENT")
        self.assertEqual(v["withinPgextwinSelfHostedRunners"],"REPORTED_ABSENT")
        self.assertEqual(v["externalPrivateRuntime"],"UNOBSERVABLE")
        self.assertEqual(v["privateRuntimeReadiness"],"NOT_PROVEN")
        self.assertFalse(v["liveCredentialTestsAllowed"])
        self.assertFalse(v["publicationAuthorized"])
        self.assertEqual((v["goB"],v["g4"],v["g5"]),("NO_GO",)*3)

    def test_connector_and_gui_are_distinct_evidence_origins(self):
        d=fixture()
        self.assertIn("USER_SUPPLIED_WORK_GUI_GET_ONLY_REPORT",d["provenance"])
        original=p.existing.read(p.existing.RECORD.read_bytes())
        self.assertEqual(original["connectedInstallations"]["count"],2)
        self.assertEqual(original["connectedInstallations"]["pgextwinVisiblePublic"],18)
        self.assertEqual(d["pgextwin"]["repositories"],18)
        self.assertNotIn("installationId",json.dumps(d))

    def test_changed_repo_environment_runner_numbers_fail_closed(self):
        for field in fixture()["pgextwin"]:
            d=fixture()
            d["pgextwin"][field]=99
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture()
        d["pgextwin"]["privateRepositories"]=True
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_external_environment_unknown_cannot_be_proven(self):
        for index in range(len(fixture()["unknowns"])):
            d=fixture()
            d["unknowns"][index]="PROVEN"
            with self.subTest(index=index):
                with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture();d["unknowns"].append("ALL_PRIVATE_RUNNERS_ABSENT")
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_go_and_publication_denials_unalterable(self):
        for field in ("goB","g4","g5","privateExecutor","publicationAuthorized"):
            d=fixture()
            d[field]=True if field=="publicationAuthorized" else "GO"
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.inspect(d)

    def test_top_level_extra_credential_key_and_provenance_forgery(self):
        for key in ("privateKey","secretValue","token","authPrincipal"):
            d=fixture()
            d[key]="fake-no-real-credential"
            with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture();d["provenance"]="INDEPENDENTLY_VERIFIED_PRIVATE_SIGNER"
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_wrong_identity_or_missing_required_key_denied(self):
        d=fixture();d["observedDate"]="2026-10-17"
        with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture();d["evidenceKind"]="ISSUE75_REAL_WRITER_GO"
        with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture();d["schemaVersion"]=True
        with self.assertRaises(p.Deny):p.inspect(d)
        d=fixture();d.pop("unknowns")
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_bad_json_duplicate_keys_and_size_limits(self):
        for raw in (b"",b"[]",b"{}"*p.MAX_BYTES,
                    b'{"a":1,"a":2}',b"\x00",b"\xff"):
            with self.assertRaises(p.Deny):p.parse(raw)

    def test_existing_readiness_failure_causes_gui_failure(self):
        with mock.patch.object(p.existing,"validate",side_effect=RuntimeError("SENSITIVE")):
            with self.assertRaises(RuntimeError):p.inspect(fixture())
            capture=io.StringIO()
            with redirect_stdout(capture):rc=p.main(["--mode","static"])
        self.assertEqual(rc,2)
        self.assertNotIn("SENSITIVE",capture.getvalue())

    def test_cli_static_vs_real_denial(self):
        for mode,expected in (("static",0),("require-real",2)):
            capture=io.StringIO()
            with redirect_stdout(capture):ret=p.main(["--mode",mode])
            self.assertEqual(ret,expected)
            j=json.loads(capture.getvalue())
            self.assertFalse(j["publicationAuthorized"])
            self.assertFalse(j["liveCredentialTestsAllowed"])
            self.assertEqual(j["goB"],"NO_GO")

    def test_unsafe_public_ci_wiring_disallowed(self):
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-work-gui-readiness.py",wf)
        self.assertIn("scripts/issue-75-work-gui-readiness.py --mode static",wf)
        self.assertNotIn("issue-75-work-gui-readiness.py --mode require-real",wf)
        source=(ROOT/"scripts/issue-75-work-gui-readiness.py").read_text()
        for forbidden in ("subprocess.", "urllib.request", "gh release",
                          "create-github-app-token@", "secrets."):
            self.assertNotIn(forbidden,source)

if __name__=="__main__":
    main()
