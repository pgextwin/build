#!/usr/bin/env python3
"""Issue75 guarded architecture selection and privilege escalation denials."""
from __future__ import annotations
import importlib.util
import io
import json
from pathlib import Path
from contextlib import redirect_stdout
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "private_options",ROOT/"scripts/issue-75-private-runtime-options.py")
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def record():return p.read(p.EVIDENCE.read_bytes())

class OptionHostileTests(TestCase):
    def test_options_admitted_as_design_only_never_actual_go(self):
        x=p.evaluate(record())
        self.assertEqual(x["decision"],"NONPRIVILEGED_OPTIONS_CONTRACT_PASS_NO_LIVE_APPROVAL")
        self.assertEqual(x["alternativesChecked"],3)
        self.assertEqual(x["unprovenControls"],15)
        self.assertEqual(x["rollbackStepsDefined"],5)
        self.assertFalse(x["privateExecutorReady"])
        self.assertFalse(x["privilegedProbeAllowed"])
        self.assertFalse(x["publicationAuthorized"])
        self.assertEqual((x["goB"],x["g4"],x["g5"]),("NO_GO",)*3)

    def test_guards_reuse_existing_gui_and_signer_writer_pins(self):
        prior=p.gui.inspect(p.gui.parse(p.gui.GUI.read_bytes()))
        self.assertEqual(prior["guiEvidenceProvenance"],"REPORTED_NOT_REAUTHENTICATED")
        self.assertEqual(p.signer.SIGNER_SHA,record()["baseline"]["signerPin"])
        self.assertEqual(p.writer.REPO,"pgextwin/plpgsql_check")

    def test_forged_success_on_any_option_rejected(self):
        fields=("publicSignerOidcProven","privateWriterSeparatePrincipalProven",
                "privateRuntimeAvailable","privilegedExecutionAuthorized")
        for i in range(3):
            for f in fields:
                d=record();d["options"][i][f]=True
                with self.subTest(option=i,field=f):
                    with self.assertRaises(p.Deny):p.evaluate(d)
            d=record();d["options"][i]["go"]="GO"
            with self.assertRaises(p.Deny):p.evaluate(d)

    def test_private_option_not_equated_with_actual_free_environment(self):
        for i,key,value in ((0,"existingInfrastructure","PROVEN"),
                            (1,"existingInfrastructure","PROVEN"),
                            (2,"recommendation","PREFERRED_FOR_DESIGN_ONLY"),
                            (0,"architecture","PUBLIC_REPO_CREDENTIAL_WRITER"),
                            (1,"costFloor","$0"),
                            (0,"manualCostChangeRequired","NO"),
                            (2,"manualCostChangeRequired","APPROVED")):
            d=record();d["options"][i][key]=value
            with self.subTest(option=i,key=key):
                with self.assertRaises(p.Deny):p.evaluate(d)

    def test_credential_boundary_gate_must_remain_unproven(self):
        for field in record()["requiredControlStates"]:
            d=record();d["requiredControlStates"][field]="PROVEN"
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.evaluate(d)
        d=record();d["requiredControlStates"]["emergencyBypass"]="ALLOW"
        with self.assertRaises(p.Deny):p.evaluate(d)

    def test_rollback_and_phases_cannot_omit_or_skip(self):
        for i in range(5):
            d=record();d["rollout"].pop(i)
            with self.assertRaises(p.Deny):p.evaluate(d)
            d=record();d["rollout"][i]["ready"]="AUTHORIZED"
            with self.assertRaises(p.Deny):p.evaluate(d)
            d=record();d["rollout"][i]["rollback"]=""
            with self.assertRaises(p.Deny):p.evaluate(d)
            d=record();d["rollout"][i]["credentials"]="PUBLIC_TOKEN"
            with self.assertRaises(p.Deny):p.evaluate(d)

    def test_all_privileged_controls_and_success_flags_rejected(self):
        for field in record()["controls"]:
            d=record()
            d["controls"][field]="GO" if field in ("goB","g4","g5") else True
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.evaluate(d)
        d=record();d["controls"]["releaseTag"]="v2.10.15"
        with self.assertRaises(p.Deny):p.evaluate(d)

    def test_identity_replay_goa_evidence_and_boolean_confusion_rejected(self):
        for field,bad in (("buildProtectedMainBefore","a"*40),
                          ("workGuiDecision","PRIVATE_EXECUTOR_VERIFIED"),
                          ("workGuiProvenance","INDEPENDENT_SIGNED_ATTESTATION"),
                          ("originalGitBlobs",33),
                          ("additionalGitBlobs",True),
                          ("signerPin","a"*40),
                          ("publisherPin","a"*40)):
            d=record();d["baseline"][field]=bad
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.evaluate(d)

    def test_missing_duplicate_json_nul_and_oversize_denied(self):
        for raw in (b"",b"[]",b"{}"*p.MAX_BYTES,
                    b'{"a":1,"a":1}',b"\xff",b"\x00",b"{}"):
            with self.assertRaises(p.Deny):p.read(raw)

    def test_execution_mode_always_exits_two_and_no_go(self):
        for mode,rc in (("static",0),("require-execution",2)):
            cap=io.StringIO()
            with redirect_stdout(cap):ret=p.main(["--mode",mode])
            self.assertEqual(ret,rc)
            out=json.loads(cap.getvalue())
            self.assertFalse(out["privilegedProbeAllowed"])
            self.assertFalse(out["publicationAuthorized"])
            self.assertEqual(out["goB"],"NO_GO")

    def test_secret_like_exception_not_emitted(self):
        cap=io.StringIO()
        with mock.patch.object(p.gui,"inspect",side_effect=RuntimeError("PRIVATE_APP_KEY")):
            with redirect_stdout(cap):rc=p.main(["--mode","static"])
        self.assertEqual(rc,2)
        self.assertNotIn("PRIVATE_APP_KEY",cap.getvalue())
        self.assertEqual(json.loads(cap.getvalue())["decision"],
                         "DENY_PRIVATE_INFRASTRUCTURE_AND_PRINCIPAL_UNPROVEN")

    def test_required_ci_contains_inert_plan_checks_no_execution_mode(self):
        wf=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-private-runtime-options.py",wf)
        self.assertIn("scripts/issue-75-private-runtime-options.py --mode static",wf)
        self.assertNotIn("--mode require-execution",wf)
        text=(ROOT/"scripts/issue-75-private-runtime-options.py").read_text()
        for forbidden in ("urllib.request","subprocess.","requests.post(",
                          "gh release","workflow_dispatch","secrets."):
            self.assertNotIn(forbidden,text)

if __name__=="__main__":
    main()
