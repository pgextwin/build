# Issue #75 — Existing Windows 11 VM, dedicated host and cloud: read-only readiness

As-of: 2026-10-18 JST. **No new host/VM, App, Secret, budget, runner, protected environment or Release was created or authorized.** The goal is to reduce real uncertainty about an EXISTING Windows 11 host while keeping live credentials outside an untrusted public CI or inadequately isolated machine.

## Independent source checks for platform/plan restrictions

- [Microsoft Hyper-V system requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements) and [Windows 11 requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements): client Hyper-V is supported on Windows 11 Pro/Enterprise class editions (Education editions as applicable), requires BIOS/UEFI enabled virtualization and SLAT plus adequate RAM. Windows 11 Home does not include the full Hyper-V role.
- [Microsoft BitLocker Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume) is a **read-only status** query. A protected OS volume is only an at-rest security signal, not host-owner isolation or live credential memory protection.
- [Microsoft Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview) is Pro/Enterprise/Education, not Home. It is ephemeral and not selected for persistent identity/vault/audited Writer duties.
- [Oracle VirtualBox Downloads and Extension Pack license](https://www.virtualbox.org/wiki/Downloads): core/base package is GPLv3; the optional Extension Pack has a separate PUEL with personal/educational limitations. Do not assume organizational commercial use of Extension Pack is licensed free. Third-party hypervisors may share a running Windows hypervisor backend; performance/compatibility needs an actual local test.
- [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and [GitHub environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments): standard public GitHub-hosted runner is free. Private usage is subject to allowance/billing, and GitHub Free cannot provide the same private Environment/reviewer protection model. Existing public protected-main CI SUCCESS remains a fact despite an Actions $0 Usage blocked view. Do not infer a private budget or paid-plan approval.

## Comparison, ordered by *reversible, nonsecret initial trials*

| Mode | Cost and prerequisite | Isolation/security tradeoff | Operational consequence | Current acceptance |
| --- | --- | --- | --- | --- |
| **Windows 11 Pro Hyper-V local VM** | Potentially zero **new service charge** if a suitable personally approved computer, spare RAM/disk, virtual firmware and legally licensed guest OS already exist; electricity, host overhead, backups and maintenance remain. Hyper-V role may require enablement and reboot—**not authorized by this PR** | Separate guest OS, possible isolated vSwitch and guest vault, but **same physical administrator** can access the VM; host OS compromise can compromise keys. BitLocker on host and guest at rest is useful but insufficient. A machine used interactively for development is not an independently governed signer/writer principal | Host must remain powered/unlocked only as approved, Windows Update/reboots may interrupt availability. Verify firewall, restore, boot, snapshots, storage disposal and separation of private vault | Recommended **no-secret pilot on verified host only**, never a real Writer by itself |
| **Windows 11 Home + VirtualBox base VM** | Potentially zero extra base hypervisor license charge, but actual Windows license/guest license, hardware capability, and Extension Pack rights need checking. Home lacks full Hyper-V; a Linux guest can avoid Windows guest licensing when suitable | Similar host administrator/single-machine risk; VM GUI/config vulnerabilities and host sharing. VirtualBox base GPLv3 is not an approval of PUEL Extension Pack for organizational deployment | Need actual hypervisor compatibility and persistence, host backup and run policy; avoid Extension Pack until licensing resolved | Conditional **no-secret pilot**, never an independent credential boundary |
| **Existing physically separate, privately governed host** | Best future low-spend option **if it already exists** and owner permits it, but existing inventory is **UNOBSERVABLE**. Need owner, exact hosting/asset and authorized operation; energy, backup/security tools are not necessarily free | Stronger governance is possible via different administrators/VM boundaries, dedicated vault, restricted egress, hardware-backed key access and independent audit. Physical separation alone does not prove identity isolation | Assign owner, patch/update windows, full disk encryption, boot attestation, immutable tool images, backups, token revocation emergency plan, and no public CI job receipt of the key | **Preferred future Writer-host candidate IF independently authenticated and approved** |
| **Cloud private VM** | Contractual charges for compute/storage/network/egress/backup/logging/vault and possibly tax. Never assume free tier; actual vendor region/SKU and spend hard cap need a quote and approval. No current deployment/budget | Provider tenancy, managed IAM/vault/private network possible; root operator/CI token and supply-chain trust still need proof | Billing alerts/hard cutoff, deletion/restore drill, keys and audit-retention in separate approved scope, break-glass action, provider incident controls | Conditional, **NO_GO** until quote and explicit budget and security approval |

**Scope recommendation:** Do not create a new cloud account, new public/private GitHub environment, a VM, change Windows features, disable antivirus/firewall or place a Writer key on a local machine as part of this PR. Using a development workstation as a **credential-bearing** private Writer is NOT accepted just because Hyper-V, BitLocker or Windows Firewall are enabled. Its valuable immediate role is *read-only capability discovery and no-secret VM feasibility*.

## Actually runnable no-secret Windows 11 probe

Two new files:
- `scripts/issue-75-windows-host-readonly.ps1`: native PowerShell 5.1+ read-only queries (Win32_OperatingSystem, Windows edition registry value, CPU firmware virtualization/SLAT, Get-WindowsOptionalFeature Hyper-V state, physical memory at least 8 GiB, system disk free at least 40 GiB, Get-BitLockerVolume protection state and Get-NetFirewallProfile). The values are **only YES/NO/UNKNOWN** or an edition/build from a strict allowlist. No computer name, serial, username, IP, credential, private key, protector/recovery key or detailed memory/file paths are emitted. Errors become UNKNOWN. No administrator/elevation, install, enable, reboot or configuration change is attempted.
- `scripts/issue-75-windows-host-assessment.py`: strict, fail-closed **unattested** assessment. Reuses existing `issue-75-external-writer-preboot.py` and thereby all original 32+13 Git Blob source, 15 unproven controls/5 rollbacks and deny gates; makes only a triage category, never actual credential authorization.
- `tests/fixtures/issue-75-windows-host-synthetic.json` is **synthetic data**, NOT an observation of the owner's physical workstation. Public App15368 CI only uses this synthetic fixture and hostile tests; no PowerShell probe and no Windows host access is performed by public CI.

Example, on a real Windows 11 computer (user runs locally only after approving read-only diagnostics; does not expose secrets):

```powershell
# From the locally checked-out pgextwin/build repository; keep the facts in Temp:
$facts = Join-Path $env:TEMP ("issue-75-host-" + [guid]::NewGuid().ToString('N') + ".json")
& .\scripts\issue-75-windows-host-readonly.ps1 |
  Set-Content -LiteralPath $facts -Encoding utf8
$assessment = '.\scripts\issue-75-windows-host-assessment.py'
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
  & $py.Source -3 $assessment --mode analyze --facts $facts
} else {
  # Set this to an already available interpreter, including a managed runtime.
  $pythonExe = 'C:\path\to\existing\python.exe'
  & $pythonExe $assessment --mode analyze --facts $facts
}
```

PowerShell 5.1 `Set-Content -Encoding utf8` writes a UTF-8 BOM; the Python JSON parser accepts it. `py` is optional. If absent, call an already available Python interpreter by its full path; a `python.exe` App Execution Alias under `WindowsApps` may only open the Microsoft Store. Run the probe outside public GitHub CI and keep the identity-free facts in the local temporary directory. Do not copy the JSON into the repository or publish its raw contents; share only an independently reviewed, sanitized summary if formal reporting is needed.

The protected source-ledger JSON and pinned Signer workflow are fixed to LF in `.gitattributes`. This preserves their exact committed Git Blob IDs in Windows checkouts with `core.autocrlf=true`; a hostile regression test forces that checkout setting.

`--mode analyze` returning zero means only the *self-reported OS/CPU/disk/safety signals* could be evaluated. Possible results:
- `LOCAL_HYPERV_VIRTUALIZATION_CANDIDATE_ONLY`: Windows 11 build, supported client edition, virtualization+SLAT, 8GiB RAM+40GiB free. **Not proof Hyper-V is installed, VM bootable, safe, or Signer/Writer can be trusted.**
- `LOCAL_THIRD_PARTY_HYPERVISOR_LICENSE_REVIEW`: Windows Home + hardware passed. Determine VirtualBox base/package rights before selecting.
- `INSUFFICIENT_OR_UNKNOWN_LOCAL_VM_CAPABILITIES`: one or more prerequisites insufficient/unknown, including OS or edition. Unknown is not a recommendation to disable system security.
- `--mode require-private` returns exit code **2 always**. No local Windows host facts can meet approved private executor trust without independent identities, audit and permitted spend.

**Threat note:** ordinary CIM, registry, BitLocker/Firewall outputs are unprivileged local observations, can be spoofed by a compromised host and do not prove TPM-sealed app secrets, measured boot, secure boot, isolated user accounts or a hardware-backed vault. BitLocker protection may be off even if disk is encrypted, so do not silently treat encryption coverage as a security pass. Locale-neutral status reduces OCR/string dependence, but permissions might make individual readings UNKNOWN.

## Reusing prior exact security gates

- Build main source before PR: `b33275448047363787c498a81e2af2bbed2c580a`.
- Original 32+13 Git Blobs accepted in prior source negative ledger; 15 required independent authorization controls and five recovery/rollback phases in PR #133; 3 allowed credential-free data flows and 15 sanitized JIT field names from PR #134. NONE of these are a real positive live signer or Writer.
- Active Signer OIDC verified cryptography and five-checkout non-persistence fix remain unmet. Writer must be an independently authenticated GitHub App installation limited to intended repo, with ≤1h short-lived test token and verified revoke **only after separate safe approval**, not the Catalog App, GitHub default token or Windows login.
- Provider/tenancy confirmation, named private host owner, billable SKU/tax, quota/spending hard stop, at-rest and in-use vault isolation, independently verified source/tool hashes and signatures, Deny test of cross-job credentials, JIT signed receipt and schema-v2 recovery remain required.
- As always: GO B/G4/G5 **NO_GO**, formal P1 **65/70**, independent source **40/40**, historical PG14–18 plpgsql_check **five DENY**, formal Release/distribution **DENY**, old GO A FAILURE unwaived. No changes to GitHub App/Secret, production pins, protection, roles, host, budget, release or tags.

**Next safe action:** Run the read-only Windows probe locally if the user wants to select a no-secret VM trial, or first GET-inventory any **already authorized physically separate host**. Do not provision infrastructure or mint credentials from this assessment.

