#!/usr/bin/env python3
"""Credentialless external Writer preboot hostile and local OS probe tests."""
from __future__ import annotations
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import os
import tempfile
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "issue75_external_preboot",ROOT/"scripts/issue-75-external-writer-preboot.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def baseline():return p.read(p.EVIDENCE.read_bytes())
def quote():
    return {
        "currency":"JPY","status":"USER_SUPPLIED_NOT_VERIFIED",
        "rateJPY":{"computeHour":"15.5","storageGBMonth":"3.00",
                   "egressGB":"2.25","monthlyFixed":"100"},
        "limit":{"computeHours":40,"storageGBMonths":10,"egressGB":4},
        "bufferPercent":20,"approval":"NOT_APPROVED",
        "reference":"EXAMPLE_NOT_A_REAL_VENDOR_QUOTE"}

class PrebootHostileTests(TestCase):
    def test_baseline_source_closure_and_execution_always_denied(self):
        out=p.inspect(baseline())
        self.assertEqual(out["classification"],
                         "CREDENTIALLESS_PREBOOT_GRAPH_VALID_NO_PRIVATE_RUNTIME")
        self.assertEqual(out["sourceBlobCount"],45)
        self.assertEqual(out["allowedCrossBoundaryDataFlows"],3)
        self.assertEqual(out["sanitizedJitKeys"],15)
        self.assertFalse(out["actualSignerOidcProven"])
        self.assertFalse(out["actualWriterAppProven"])
        self.assertFalse(out["actualCrossJobIsolationProven"])
        self.assertFalse(out["credentialProbeAllowed"])
        self.assertEqual((out["goB"],out["g4"],out["g5"]),("NO_GO",)*3)

    def test_credentials_cannot_flow_across_jobs_even_indirectly(self):
        changes=[
            (0,{"payload":"APP_PRIVATE_KEY"}),
            (1,{"payload":"INSTALLATION_TOKEN"}),
            (2,{"payload":"RAW_JWT"}),
            (2,{"to":"READER"}),
            (0,{"from":"WRITER"}),
            (1,{"to":"AUDITOR"}),
        ]
        for index,kv in changes:
            with self.subTest(index=index,kv=kv):
                d=baseline();d["flows"][index].update(kv)
                with self.assertRaises(p.Deny):p.inspect(d)
        d=baseline();d["flows"].append({"from":"WRITER","to":"READER",
                                         "payload":"SIGNED_PROVENANCE_NO_BEARER"})
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_taint_label_sanitized_jit_must_not_drift(self):
        d=baseline();d["jit"]["requiredMetadata"].append("authorizationHeader")
        with self.assertRaises(p.Deny):p.inspect(d)
        d=baseline();d["jit"]["forbiddenMaterial"].remove("installationToken")
        with self.assertRaises(p.Deny):p.inspect(d)
        d=baseline();d["jit"]["independentRuntimeEvidence"]=True
        with self.assertRaises(p.Deny):p.inspect(d)
        self.assertTrue(set(p.SAFE_META).isdisjoint(p.NO_CREDENTIALS))

    def test_fake_provisioning_and_app_grants_denied(self):
        for area,field,value in (
            ("workspace","provider","real-cloud"),
            ("workspace","privateHostId","host1"),
            ("workspace","workDir","/secret"),
            ("workspace","runnerImageSha256","a"*64),
            ("workspace","observedLive",True),
            ("writerApp","status","INSTALLED"),
            ("writerApp","appId",123),
            ("writerApp","installationId",123),
            ("writerApp","repositoryId",1),
            ("writerApp","requestedScopes",["contents:write","actions:write"]),
            ("writerApp","mintTestApproved",True)
        ):
            with self.subTest(area=area,field=field):
                d=baseline();d[area][field]=value
                with self.assertRaises(p.Deny):p.inspect(d)

    def test_reader_signer_writer_separation_denied_on_role_confusion(self):
        for who,field,value in (
            ("reader","realm","EXTERNAL_PRIVATE"),
            ("reader","hasWriterKey",True),
            ("signer","hasWriterKey",True),
            ("signer","hasReaderToken",True),
            ("writer","hasGithubActionsOidc",True),
            ("writer","hasReaderToken",True)
        ):
            with self.subTest(role=who,field=field):
                d=baseline();d["identities"][who][field]=value
                with self.assertRaises(p.Deny):p.inspect(d)

    def test_external_cost_not_wishful_quote_or_budget_approval(self):
        for field,value in (
            ("quoteStatus","VERIFIED_VENDOR_QUOTE"),
            ("monthlyLimitJPY",0),
            ("approvedBudgetJPY",200),
            ("approvalState","AUTHORIZED"),
            ("vendor","free"),
        ):
            d=baseline();d["cost"][field]=value
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.inspect(d)

    def test_old_pr133_15_controls_and_5_rollbacks_cannot_be_skipped(self):
        for field,value in (
            ("buildBefore","a"*40),
            ("signerPin","a"*40),
            ("publisherPin","a"*40),
            ("immutableSourceLedgerOriginal",33),
            ("immutableSourceLedgerAdditional",12),
            ("priorControls",14),
            ("priorRollbackPhases",4)
        ):
            d=baseline();d["reference"][field]=value
            with self.subTest(field=field):
                with self.assertRaises(p.Deny):p.inspect(d)
        with mock.patch.object(p.old,"evaluate",
                side_effect=RuntimeError("PRIVATE_KEY_FAKE")):
            with self.assertRaises(RuntimeError):p.inspect(baseline())
            out=io.StringIO()
            with redirect_stdout(out):rc=p.main(["--mode","static"])
        self.assertEqual(rc,2)
        self.assertNotIn("PRIVATE_KEY_FAKE",out.getvalue())

    def test_exact_schema_no_true_boolean_as_int_or_spurious_status(self):
        d=baseline();d["schemaVersion"]=True
        with self.assertRaises(p.Deny):p.inspect(d)
        for k in baseline()["controls"]:
            d=baseline()
            old=d["controls"][k]
            d["controls"][k]=("GO" if k in ("goB","g4","g5")
                              else not old if type(old) is bool else "GO")
            with self.subTest(k=k):
                with self.assertRaises(p.Deny):p.inspect(d)
        d=baseline();d["actualSecret"]="SHOULD_NOT_PUBLISH"
        with self.assertRaises(p.Deny):p.inspect(d)

    def test_local_mode_check_0700_readonly_and_not_runtime_attestation(self):
        if os.name == "nt":
            # Windows ACLs are not POSIX 0700 modes; fail closed instead of
            # treating the chmod compatibility bit as an isolation proof.
            with tempfile.TemporaryDirectory() as root:
                directory=Path(root)/"priv"
                directory.mkdir()
                with self.assertRaises(p.Deny):
                    p.inspect_private_dir(directory)
            return
        with tempfile.TemporaryDirectory() as root:
            directory=Path(root)/"priv"
            directory.mkdir(mode=0o700)
            os.chmod(directory,0o700)
            valid=p.inspect_private_dir(directory)
            self.assertTrue(valid["localDirectoryPermissionsChecked"])
            self.assertFalse(valid["privateExecutionTenancyAuthenticated"])
            self.assertFalse(valid["credentialProbeAllowed"])
            os.chmod(directory,0o750)
            with self.assertRaises(p.Deny):p.inspect_private_dir(directory)
            os.chmod(directory,0o700)
            link=Path(root)/"link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(p.Deny):p.inspect_private_dir(link)
            capture=io.StringIO()
            with redirect_stdout(capture):
                status=p.main(["--mode","local-dir","--workspace",str(directory)])
            self.assertEqual(status,0)
            self.assertFalse(json.loads(capture.getvalue())["workspaceCheck"]
                             ["actualCredentialIsolationProven"])

    def test_local_mode_cannot_accept_source_workspace(self):
        with self.assertRaises(p.Deny):p.inspect_private_dir(ROOT)
        with self.assertRaises(p.Deny):p.inspect_private_dir(Path("relative"))
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/"ordinary.txt"
            f.write_text("none")
            with self.assertRaises(p.Deny):p.inspect_private_dir(f)

    def test_hypothetical_cost_upper_bound_uses_exact_decimal(self):
        out=p.estimate_quote(quote())
        # 40*15.5 + 10*3 + 4*2.25 + 100 = 759, plus 20% -> 910.8 -> 911
        self.assertEqual(out["maximumEstimatedMonthlyJPY"],911)
        self.assertFalse(out["rateOrCurrencyAuthenticated"])
        self.assertFalse(out["provisioningBudgetApproved"])
        self.assertFalse(out["credentialProbeAllowed"])

    def test_malicious_quote_denials(self):
        cases=[
            (("currency",),"USD"),(("status",),"VENDOR_VERIFIED"),
            (("approval",),"APPROVED"),(("reference",),"private-key/Bearer"),
            (("bufferPercent",),True),(("bufferPercent",),101),
            (("rateJPY","computeHour"),"NaN"),
            (("rateJPY","computeHour"),"1e12"),
            (("rateJPY","computeHour"),"-3"),
            (("rateJPY","computeHour"),"1.00001"),
            (("rateJPY","computeHour"),"999999999"),
            (("limit","computeHours"),-1),
            (("limit","computeHours"),True),
            (("limit","computeHours"),10001)
        ]
        for path,value in cases:
            d=quote()
            if len(path)==2:d[path[0]][path[1]]=value
            else:d[path[0]]=value
            with self.subTest(path=path,value=value):
                with self.assertRaises(p.Deny):p.estimate_quote(d)
        d=quote();d["rateJPY"]["monthlyFixed"]="10000000"
        d["limit"]["computeHours"]=10000
        d["rateJPY"]["computeHour"]="10000000"
        with self.assertRaises(p.Deny):p.estimate_quote(d)

    def test_empty_and_duplicate_json_fail_closed(self):
        for raw in (b"",b"[]",b"\0",b"\xff",b"{}"*p.MAX_BYTES,
                    b'{"schemaVersion":1,"schemaVersion":2}',b"{}"):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(p.Deny):p.inspect(p.read(raw))

    def test_cli_modes_no_go_and_quote_never_budget_approval(self):
        for mode,expected in (("static",0),("require-live",2),("local-dir",2)):
            cap=io.StringIO()
            with redirect_stdout(cap):rc=p.main(["--mode",mode])
            self.assertEqual(rc,expected)
            data=json.loads(cap.getvalue())
            self.assertFalse(data["publicationAuthorized"])
            self.assertFalse(data["credentialProbeAllowed"])
            self.assertEqual(data["goB"],"NO_GO")
        with tempfile.TemporaryDirectory() as path:
            f=Path(path)/"example-quote.json"
            f.write_text(json.dumps(quote()))
            cap=io.StringIO()
            with redirect_stdout(cap):
                rc=p.main(["--mode","static","--quote",str(f)])
            self.assertEqual(rc,0)
            self.assertEqual(json.loads(cap.getvalue())["costBound"]
                             ["maximumEstimatedMonthlyJPY"],911)

    def test_no_secret_execution_paths_in_public_ci(self):
        workflow=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-external-writer-preboot.py",workflow)
        self.assertIn("scripts/issue-75-external-writer-preboot.py --mode static",
                      workflow)
        for forbidden in ("external-writer-preboot.py --mode require-live",
                          "external-writer-preboot.py --mode local-dir"):
            self.assertNotIn(forbidden,workflow)
        source=(ROOT/"scripts/issue-75-external-writer-preboot.py").read_text()
        for forbidden in ("requests.", "urllib.request", "subprocess.",
                          "gh release","secrets.","workflow_dispatch:",
                          "os.environ.get('GITHUB_TOKEN')"):
            self.assertNotIn(forbidden,source)

if __name__=="__main__":
    main()

