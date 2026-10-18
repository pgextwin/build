#!/usr/bin/env python3
"""Issue 75 Windows 11 local VM readiness hostile fixture tests."""
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase,main,mock

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/"tests/fixtures/issue-75-windows-host-synthetic.json"
spec=importlib.util.spec_from_file_location(
    "issue75_win_host",ROOT/"scripts/issue-75-windows-host-assessment.py")
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

def sample():return p.parse(FIX.read_bytes())

class HostAssessment(TestCase):
    def test_pro_vm_candidate_only_not_writer(self):
        x=p.assess(sample())
        self.assertEqual(x["classification"],"WINDOWS_LOCAL_HOST_FACTS_UNATTESTED")
        self.assertEqual(x["origin"],"SYNTHETIC_CI_FIXTURE_NOT_REAL")
        self.assertEqual(x["hostVirtualizationTriage"],
                         "LOCAL_HYPERV_VIRTUALIZATION_CANDIDATE_ONLY")
        self.assertTrue(x["windows11BuildDetected"])
        self.assertFalse(x["hypervEnabledReported"])
        self.assertTrue(x["hostDiskEncryptionAndFirewallReported"])
        self.assertTrue(x["localVMOnlyForNoSecretPilot"])
        for k in ("existingDedicatedHostProven","secretVaultAndAccessBoundaryProven",
                  "actualSignerOIDCProven","realWriterPrincipalProven",
                  "privateWriterRuntimeProven","credentialNonPropagationProven",
                  "privilegedExecutionAllowed","publicationAuthorized"):
            self.assertFalse(x[k])
        self.assertEqual((x["goB"],x["g4"],x["g5"]),("NO_GO",)*3)

    def test_home_requires_third_party_review_even_if_virtualization_present(self):
        for edition in ("Core","CoreSingleLanguage"):
            d=sample();d["windowsEdition"]=edition
            x=p.assess(d)
            self.assertEqual(x["hostVirtualizationTriage"],
                             "LOCAL_THIRD_PARTY_HYPERVISOR_LICENSE_REVIEW")
            self.assertFalse(x["privateWriterRuntimeProven"])

    def test_windows10_unknown_cpu_and_low_resources_fail_candidate(self):
        variations=[
            ("windowsBuild",19045),("windowsBuild",0),
            ("firmwareVirtualization","NO"),("firmwareVirtualization","UNKNOWN"),
            ("cpuSlat","NO"),("cpuSlat","UNKNOWN"),
            ("physicalMemoryAtLeast8GiB","NO"),
            ("systemDriveFreeAtLeast40GiB","NO"),
            ("windowsEdition","UNKNOWN")]
        for key,value in variations:
            d=sample();d[key]=value
            with self.subTest(key=key,value=value):
                x=p.assess(d)
                self.assertEqual(x["hostVirtualizationTriage"],
                                 "INSUFFICIENT_OR_UNKNOWN_LOCAL_VM_CAPABILITIES")
                self.assertFalse(x["privilegedExecutionAllowed"])

    def test_hyperv_enabled_is_not_isolation_or_permission_proof(self):
        d=sample()
        d["hyperVFeature"]="ENABLED"
        x=p.assess(d)
        self.assertTrue(x["hypervEnabledReported"])
        self.assertFalse(x["privateWriterRuntimeProven"])
        self.assertEqual(x["goB"],"NO_GO")

    def test_bitlocker_firewall_signals_not_writer_attestation(self):
        for key,value in (("systemDriveEncryptionProtected","NO"),
                          ("systemDriveEncryptionProtected","UNKNOWN"),
                          ("allFirewallProfilesEnabled","NO"),
                          ("allFirewallProfilesEnabled","UNKNOWN")):
            d=sample();d[key]=value
            with self.subTest(key=key,value=value):
                x=p.assess(d)
                self.assertFalse(x["hostDiskEncryptionAndFirewallReported"])
                self.assertFalse(x["credentialNonPropagationProven"])

    def test_reject_true_claims_secret_access_machine_identity_and_change(self):
        for key in ("machineIdentityIncluded","credentialAccessAttempted",
                    "systemSettingsChanged","privateWriterRuntimeProven",
                    "publicationAuthorized"):
            d=sample();d[key]=True
            with self.subTest(field=key):
                with self.assertRaises(p.Deny):p.assess(d)

    def test_reject_unknown_keys_raw_secret_and_fake_role_proofs(self):
        for key in ("privateKey","githubAppToken","hostname","serialNumber",
                    "actualOIDCJwt","cloudBudgetApproved","writerAuthorized"):
            d=sample();d[key]="SYNTHETIC_DO_NOT_LOG"
            with self.subTest(field=key):
                with self.assertRaises(p.Deny):p.assess(d)

    def test_boolean_not_integer_and_invalid_tri_state_fail(self):
        cases=[
            ("schemaVersion",True),
            ("windowsBuild",True),
            ("windowsBuild",-1),
            ("windowsBuild",1000000),
            ("windowsBuild","26100"),
            ("windowsEdition","ProfessionalAdmin"),
            ("windowsEdition","Windows 11 Pro host01"),
            ("hyperVFeature","INSTALLING"),
            ("firmwareVirtualization","ENABLED"),
            ("cpuSlat",True),
            ("physicalMemoryAtLeast8GiB",8),
            ("systemDriveFreeAtLeast40GiB",None),
            ("allFirewallProfilesEnabled","maybe"),
            ("observation","AUTHENTICATED_PRIVATE_RUNNER"),
            ("observation","SECRET_BEARING_REPORT")
        ]
        for k,v in cases:
            d=sample();d[k]=v
            with self.subTest(k=k,v=v):
                with self.assertRaises(p.Deny):p.assess(d)

    def test_duplicate_key_nul_utf8_and_invalid_shape_denied(self):
        for raw in (b"",b"[]",b'{"a":1,"a":2}',
                    b"\0",b"\xff",b"{}"*p.MAX_BYTES,b"{}"):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(p.Deny):
                    p.assess(p.parse(raw))

    def test_cli_analyze_can_never_be_approving_and_live_always_deny(self):
        for mode,status in (("analyze",0),("require-private",2)):
            capture=io.StringIO()
            with redirect_stdout(capture):
                got=p.main(["--mode",mode,"--facts",str(FIX)])
            self.assertEqual(got,status)
            j=json.loads(capture.getvalue())
            self.assertFalse(j["publicationAuthorized"])
            self.assertFalse(j["privilegedExecutionAllowed"])
            self.assertEqual(j["g4"],"NO_GO")

    def test_forged_old_source_denied_with_secret_free_error(self):
        c=io.StringIO()
        with mock.patch.object(p.old,"inspect",side_effect=RuntimeError("FAKE_APP_PRIVATE_KEY")):
            with redirect_stdout(c):
                ret=p.main(["--mode","analyze","--facts",str(FIX)])
        self.assertEqual(ret,2)
        self.assertNotIn("FAKE_APP_PRIVATE_KEY",c.getvalue())
        self.assertEqual(json.loads(c.getvalue())["classification"],
                         "DENY_UNTRUSTED_WINDOWS_HOST_FACTS")

    def test_read_only_powershell_source_has_no_credential_or_host_identity_dump(self):
        content=(ROOT/"scripts/issue-75-windows-host-readonly.ps1").read_text()
        for risky in ("Enable-WindowsOptionalFeature","Disable-WindowsOptionalFeature",
                      "Set-BitLockerVolume","Enable-BitLocker",
                      "New-VM ","Start-VM ","Install-Module",
                      "Set-NetFirewallProfile","Set-ItemProperty",
                      "Get-Credential","Get-Secret ","Get-ChildItem Env:",
                      "$env:USERNAME","$env:COMPUTERNAME",
                      "Get-BitLockerKeyProtector","Export-Clixml"):
            self.assertNotIn(risky,content)
        for safe in ("Get-CimInstance","Get-WindowsOptionalFeature",
                     "Get-BitLockerVolume","Get-NetFirewallProfile",
                     "Get-PSDrive","ConvertTo-Json"):
            self.assertIn(safe,content)
        self.assertIn("machineIdentityIncluded=$false",content)
        self.assertIn("credentialAccessAttempted=$false",content)

    def test_public_required_ci_tests_only_synthetic_fixture(self):
        content=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-windows-host-assessment.py",content)
        self.assertIn("issue-75-windows-host-assessment.py --mode analyze --facts tests/fixtures/issue-75-windows-host-synthetic.json",content)
        self.assertNotIn("issue-75-windows-host-readonly.ps1",content)
        self.assertNotIn("issue-75-windows-host-assessment.py --mode require-private",content)

if __name__=="__main__":
    main()
