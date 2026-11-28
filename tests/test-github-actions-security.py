from pathlib import Path
import json
import re
import sys

WORKFLOW_DIR = Path(".github/workflows")
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.*))?\s*$")
VERSION_COMMENT = re.compile(r"\bv\d+(?:\.\d+){0,2}\b")
ATTEST_PIN = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
SYFT_VERSION = "1.54.1"
SYFT_WINDOWS_AMD64_SHA256 = "8b56e8285e295e0bbed26eeea9b16ed51c493be97ccdf42dae6326c84fe8e19f"
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"
GRYPE_VERSION = "0.120.1"
GRYPE_WINDOWS_AMD64_SHA256 = "32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d"

errors = []

for workflow in sorted(list(WORKFLOW_DIR.glob("*.yml")) + list(WORKFLOW_DIR.glob("*.yaml"))):
    text = workflow.read_text(encoding="utf-8")

    if re.search(r"^\s*permissions:\s*write-all\s*$", text, re.MULTILINE):
        errors.append(f"{workflow}: permissions: write-all is forbidden")

    if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE):
        errors.append(f"{workflow}: pull_request_target is forbidden")

    for line_no, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue

        target, comment = match.groups()

        if target.startswith("./"):
            continue

        if "@" not in target:
            errors.append(f"{workflow}:{line_no}: remote uses reference has no @ref: {target}")
            continue

        dependency, ref = target.rsplit("@", 1)
        if not FULL_SHA.fullmatch(ref):
            errors.append(
                f"{workflow}:{line_no}: remote dependency must use a full 40-character commit SHA: {target}"
            )
            continue

        if dependency.startswith("actions/") and not (comment and VERSION_COMMENT.search(comment)):
            errors.append(
                f"{workflow}:{line_no}: GitHub-owned action SHA pin must keep a same-line version comment"
            )


def check_self_pin(path: Path, text: str) -> None:
    if text.count("repository: ${{ job.workflow_repository }}") < 2:
        errors.append(
            f"{path.name}: shared build source checkout must use job.workflow_repository in matrix and build jobs"
        )

    if text.count("ref: ${{ job.workflow_sha }}") < 2:
        errors.append(
            f"{path.name}: shared build source checkout must use job.workflow_sha in matrix and build jobs"
        )

    if re.search(r"repository:\s*pgextwin/build[\s\S]{0,200}?ref:\s*(?:main|refs/heads/main)\b", text):
        errors.append(f"{path.name}: mutable pgextwin/build main checkout is forbidden")


normal_workflow = WORKFLOW_DIR / "build-extension.yml"
normal_text = normal_workflow.read_text(encoding="utf-8")
check_self_pin(normal_workflow, normal_text)

license_step_pattern = re.compile(
    r"^      - name: Verify upstream license files match packaging repository\n"
    r"(.*?)(?=^      - name:|\Z)",
    re.MULTILINE | re.DOTALL,
)

for forbidden in (
    "contents: write",
    "id-token: write",
    "attestations: write",
    "artifact-metadata: write",
    "actions/attest@",
    "gh attestation verify",
    "attest_provenance:",
):
    if forbidden in normal_text:
        errors.append(
            f"build-extension.yml: normal build must remain read-only and attestation-free; found {forbidden}"
        )

attested_workflow = WORKFLOW_DIR / "build-extension-attested.yml"
if not attested_workflow.exists():
    errors.append("build-extension-attested.yml: dedicated attested release-build workflow is required")
    attested_text = ""
else:
    attested_text = attested_workflow.read_text(encoding="utf-8")
    check_self_pin(attested_workflow, attested_text)

    if re.search(r"^\s*contents:\s*write\s*$", attested_text, re.MULTILINE):
        errors.append("build-extension-attested.yml: attested build must not request contents: write")

    for permission in ("contents: read", "id-token: write", "attestations: write", "artifact-metadata: write"):
        if permission not in attested_text:
            errors.append(f"build-extension-attested.yml: missing required permission {permission}")

    if attested_text.count(ATTEST_PIN) != 2:
        errors.append(
            "build-extension-attested.yml: exactly two actions/attest v4.2.2 steps "
            "(build provenance + SBOM) must use the approved full SHA pin"
        )

    subject = "subject-path: ${{ steps.sbom.outputs.zip_path }}"
    if attested_text.count(subject) != 2:
        errors.append(
            "build-extension-attested.yml: both attestations must use the final ZIP as subject"
        )

    if "sbom-path: ${{ steps.sbom.outputs.sbom_path }}" not in attested_text:
        errors.append("build-extension-attested.yml: SBOM attestation must use the generated SPDX JSON")

    if "Generate build provenance attestation" not in attested_text:
        errors.append("build-extension-attested.yml: SLSA build provenance attestation must be preserved")
    if "Generate SBOM attestation" not in attested_text:
        errors.append("build-extension-attested.yml: SPDX SBOM attestation is required")
    if "Verify build provenance attestation" not in attested_text:
        errors.append("build-extension-attested.yml: build provenance verification is required")
    if "Verify SBOM attestation and predicate" not in attested_text:
        errors.append("build-extension-attested.yml: SBOM attestation verification is required")
    if f'--predicate-type "{SPDX_PREDICATE}"' not in attested_text:
        errors.append("build-extension-attested.yml: SBOM verification must select SPDX 2.3 predicate type")
    if "--format json" not in attested_text or "scripts/verify-sbom-attestation.py" not in attested_text:
        errors.append(
            "build-extension-attested.yml: verified SBOM predicate must be compared semantically with generated JSON"
        )

    signer = "PGEXTWIN_SIGNER_WORKFLOW: ${{ job.workflow_repository }}/.github/workflows/build-extension-attested.yml"
    if attested_text.count(signer) < 2:
        errors.append(
            "build-extension-attested.yml: both verification steps must constrain the signer workflow"
        )

    order = [
        attested_text.find("- name: Package Windows binary"),
        attested_text.find("- name: Validate final package metadata"),
        attested_text.find("- name: Install checksum-pinned Syft"),
        attested_text.find("- name: Generate SPDX 2.3 SBOM"),
        attested_text.find("- name: Validate SPDX 2.3 SBOM"),
        attested_text.find("- name: Install checksum-pinned Grype"),
        attested_text.find("- name: Scan validated SPDX SBOM for known vulnerabilities"),
        attested_text.find("- name: Validate and summarize vulnerability report"),
        attested_text.find("- name: Generate build provenance attestation"),
        attested_text.find("- name: Generate SBOM attestation"),
        attested_text.find("- name: Verify build provenance attestation"),
        attested_text.find("- name: Verify SBOM attestation and predicate"),
        attested_text.find("- name: Upload package artifact"),
    ]
    if any(index < 0 for index in order) or order != sorted(order):
        errors.append(
            "build-extension-attested.yml: required order is package -> metadata -> "
            "Syft -> SBOM -> validate -> Grype -> vulnerability report validation -> "
            "provenance attestation -> SBOM attestation -> both verifications -> upload"
        )

normal_order = [
    normal_text.find("- name: Package Windows binary"),
    normal_text.find("- name: Validate final package metadata"),
    normal_text.find("- name: Install checksum-pinned Syft"),
    normal_text.find("- name: Generate SPDX 2.3 SBOM"),
    normal_text.find("- name: Validate SPDX 2.3 SBOM"),
    normal_text.find("- name: Install checksum-pinned Grype"),
    normal_text.find("- name: Scan validated SPDX SBOM for known vulnerabilities"),
    normal_text.find("- name: Validate and summarize vulnerability report"),
    normal_text.find("- name: Upload package artifact"),
]
if any(index < 0 for index in normal_order) or normal_order != sorted(normal_order):
    errors.append(
        "build-extension.yml: required order is package -> metadata -> Syft -> SBOM -> validate -> Grype -> vulnerability report validation -> upload"
    )

for workflow_name, workflow_text in (
    ("build-extension.yml", normal_text),
    ("build-extension-attested.yml", attested_text),
):
    if workflow_text:
        license_step = license_step_pattern.search(workflow_text)
        license_step_text = license_step.group(1) if license_step else ""
        license_commands = (
            "needs.matrix.outputs.verify_upstream_license == 'true'",
            "PGEXTWIN_LICENSE_FILES: ${{ toJSON(matrix.licenseFiles) }}",
            "Set-Content -LiteralPath $licenseConfig.FullName -Value $env:PGEXTWIN_LICENSE_FILES",
            'python ".pgextwin-build/scripts/verify-license-bytes.py"',
            "--license-files $licenseConfig.FullName",
            '--upstream-dir "upstream"',
            '--packaging-dir "."',
            '--stage-dir ".pgextwin-verified-licenses"',
            "--restore-worktrees",
            "if ($LASTEXITCODE -ne 0) { throw",
        )
        license_order = [license_step_text.find(command) for command in license_commands]
        if -1 in license_order or license_order != sorted(license_order):
            errors.append(f"{workflow_name}: license step must enforce the shared verifier's result")

    if workflow_text:
        for required in (
            "scripts/validate-package-metadata.py",
            "scripts/install-syft.ps1",
            "scripts/generate-sbom.ps1",
            "scripts/validate-sbom.py",
            'dist/*.spdx.json',
            f'--expected-tool-version "{SYFT_VERSION}"',
            "scripts/install-grype.ps1",
            "scripts/scan-vulnerabilities.ps1",
            "scripts/validate-vulnerability-report.py",
            "dist/*.vulnerabilities.json",
            f'--expected-scanner-version "{GRYPE_VERSION}"',
        ):
            if required not in workflow_text:
                errors.append(f"{workflow_name}: missing required Step 8 contract: {required}")

package_entry = Path("scripts/invoke-windows-package.ps1").read_text(encoding="utf-8")
package_lib = Path("scripts/windows-package.ps1").read_text(encoding="utf-8")
for required in (
    "scripts/invoke-windows-package.ps1",
    "-Action Prepare",
    "-Action Finalize",
    "VERIFY_LICENSE: ${{ needs.matrix.outputs.verify_upstream_license }}",
    "-VerifyLicense:($env:VERIFY_LICENSE -eq 'true')",
):
    if required not in normal_text:
        errors.append(f"build-extension.yml: missing normal packaging binding: {required}")
    if required not in attested_text:
        errors.append(f"build-extension-attested.yml: missing signer packaging binding: {required}")
package_order = [
    package_entry.find(name)
    for name in (
        "Invoke-PackageLicenseVerification", "& $buildHook", "Copy-PackageFiles",
        "smoke-test.ps1", "Write-WindowsPackageStage",
    )
]
if -1 in package_order or package_order != sorted(package_order):
    errors.append("invoke-windows-package.ps1: enforce license verification, build, install, smoke and staging in order")
for required in (
    "verify-license-bytes.py", "--verified-list $manifest", "--restore-worktrees",
    "if ($LASTEXITCODE -ne 0) { throw 'Upstream license byte verification failed.' }",
):
    if required not in package_lib:
        errors.append(f"windows-package.ps1: missing verified license staging binding: {required}")
for step in ("Install PostgreSQL ${{ matrix.major }}", "Package Windows binary", "Upload package artifact"):
    if step not in normal_text or (attested_text and step not in attested_text):
        errors.append(f"Build workflows: missing shared build step {step}")

parity = (WORKFLOW_DIR / "windows-package-parity.yml").read_text(encoding="utf-8")
for forbidden in ("contents: write", "id-token: write", "attestations: write", "artifact-metadata: write", "actions/attest@"):
    if forbidden in parity:
        errors.append(f"windows-package-parity.yml: parity must remain read-only: {forbidden}")

installer = Path("scripts/install-syft.ps1").read_text(encoding="utf-8")
for required in (
    f'$SyftVersion = "{SYFT_VERSION}"',
    f'$SyftArchiveSha256 = "{SYFT_WINDOWS_AMD64_SHA256}"',
    "https://github.com/anchore/syft/releases/download/v${SyftVersion}/${ArchiveName}",
    "Get-FileHash",
):
    if required not in installer:
        errors.append(f"install-syft.ps1: missing pinned Syft trust control: {required}")

installer_lower = installer.lower()
for forbidden in ("releases/latest", "curl |", "irm ", "iex "):
    if forbidden in installer_lower:
        errors.append(f"install-syft.ps1: floating or pipe-to-shell install pattern is forbidden: {forbidden}")


grype_installer = Path("scripts/install-grype.ps1").read_text(encoding="utf-8")
for required in (
    '$Version = "0.120.1"',
    '$AssetName = "grype_0.120.1_windows_amd64.zip"',
    f'$ExpectedSha256 = "{GRYPE_WINDOWS_AMD64_SHA256}"',
    "https://github.com/anchore/grype/releases/download/v$Version/$AssetName",
    "Get-FileHash",
):
    if required not in grype_installer:
        errors.append(f"install-grype.ps1: missing pinned Grype trust control: {required}")

grype_installer_lower = grype_installer.lower()
for forbidden in ("releases/latest", "curl |", "irm ", "iex "):
    if forbidden in grype_installer_lower:
        errors.append(f"install-grype.ps1: floating or pipe-to-shell install pattern is forbidden: {forbidden}")

grype_config = Path("config/grype-report-only.yaml").read_text(encoding="utf-8")
for required in (
    "only-fixed: false",
    "only-notfixed: false",
    'ignore-wontfix: ""',
    'fail-on-severity: ""',
    "ignore: []",
    "exclude: []",
    "vex-documents: []",
    "vex-add: []",
    "validate-age: true",
    "require-update-check: true",
):
    if required not in grype_config:
        errors.append(f"grype-report-only.yaml: missing report-only control: {required}")

generator = Path("scripts/generate-sbom.ps1").read_text(encoding="utf-8")
for required in (
    'spdx-json@2.3=$sbomPath',
    '--source-name $zip.BaseName',
    '--source-version $ExtensionVersion',
    '--source-supplier "pgextwin"',
):
    if required not in generator:
        errors.append(f"generate-sbom.ps1: missing canonical source/SBOM setting: {required}")

# Retired routes must remain inert even when archived body checks are not run.
# Keep this list independent of fixture existence so deleting an archive cannot
# silently permit its old workflow to return.
for retired in (
    "release-extension", "issue-75-principal-boundaries",
    "issue-75-wave3-actions-readonly", "validate-issue75-pr-oneoffs",
    "chocolatey-components-benchmark",
):
    for suffix in (".yml", ".yaml"):
        if (WORKFLOW_DIR / (retired + suffix)).exists():
            errors.append(f"{retired}{suffix}: retired workflow must remain archived")


# Muse owns only these build timers; the Publisher canary is not relocated.
# This in-repo contract is CI-verifiable; it does not prove live timer delivery.
dispatcher_manifest = Path("config/muse-dispatcher-control.json")
dispatcher_timers = {
    "postgresql-update-watch.yml": ("00:00", {"dry_run": "false"}),
}


def workflow_trigger(text: str, event: str):
    # Read the literal block-style on: entrances used by these workflows.
    triggers = re.search(r"^on:[ \t]*\n((?:[ \t]+[^\n]*\n|\n)*)", text, re.MULTILINE)
    if triggers:
        return re.search(
            rf"^  {event}:[ \t]*\n((?: {{4}}[^\n]*\n|\n)*)", triggers[1], re.MULTILINE
        )
    return None


dispatcher_controls = {}
if dispatcher_manifest.exists():
    try:
        dispatcher_controls = json.loads(dispatcher_manifest.read_text(encoding="utf-8"))
        if not isinstance(dispatcher_controls, dict):
            raise ValueError("expected an object keyed by workflow filename")
    except (OSError, ValueError) as exc:
        errors.append(f"{dispatcher_manifest}: invalid dispatcher manifest: {exc}")
        dispatcher_controls = {}

valid_dispatcher_controls = set()
for workflow_name, control in dispatcher_controls.items():
    if workflow_name not in dispatcher_timers:
        errors.append(f"{dispatcher_manifest}: workflow outside dispatcher timer allowlist: {workflow_name}")
        continue
    workflow_path = WORKFLOW_DIR / workflow_name
    if not workflow_path.is_file():
        errors.append(f"{dispatcher_manifest}: missing workflow {workflow_name}")
        continue
    dispatch = workflow_trigger(workflow_path.read_text(encoding="utf-8"), "workflow_dispatch")
    if dispatch is None:
        errors.append(f"{workflow_name}: dispatcher control requires workflow_dispatch entrance")
        continue
    daily_utc, inputs = dispatcher_timers[workflow_name]
    if control != {"daily_utc": daily_utc, "ref": "main", "inputs": inputs}:
        errors.append(f"{workflow_name}: dispatcher control must use daily {daily_utc} UTC, ref=main, inputs={inputs}")
        continue
    declared_inputs = set(re.findall(r"^      ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*$", dispatch[1], re.MULTILINE))
    if declared_inputs != set(inputs) or (inputs and "    inputs:\n" not in dispatch[1]):
        errors.append(f"{workflow_name}: dispatcher inputs must match workflow_dispatch input declarations")
        continue
    if "dry_run" in inputs and not re.search(
        r"^      dry_run:[ \t]*\n(?: {8}[^\n]*\n)*? {8}type: boolean[ \t]*$", dispatch[1], re.MULTILINE
    ):
        errors.append(f"{workflow_name}: dispatcher dry_run input must retain type: boolean")
        continue
    valid_dispatcher_controls.add(workflow_name)

for workflow_name in dispatcher_timers:
    workflow_path = WORKFLOW_DIR / workflow_name
    if not workflow_path.is_file() or (
        workflow_trigger(workflow_path.read_text(encoding="utf-8"), "schedule") is None
        and workflow_name not in valid_dispatcher_controls
    ):
        errors.append(f"{workflow_name}: requires schedule: or a valid Muse dispatcher control")


# Step 13 update-watch workflows are the only non-release workflows allowed to write Issues.
extension_watch = WORKFLOW_DIR / "check-extension-updates.yml"
postgres_watch = WORKFLOW_DIR / "postgresql-update-watch.yml"

for watch_path in (extension_watch, postgres_watch):
    if not watch_path.exists():
        errors.append(f"{watch_path.name}: Step 13 watcher workflow is required")
        continue
    watch_text = watch_path.read_text(encoding="utf-8")
    for required in ("contents: read", "issues: write"):
        if required not in watch_text:
            errors.append(f"{watch_path.name}: missing required least-privilege scope {required}")
    for forbidden in (
        "contents: write",
        "pull-requests: write",
        "actions: write",
        "id-token: write",
        "attestations: write",
        "security-events: write",
    ):
        if forbidden in watch_text:
            errors.append(f"{watch_path.name}: forbidden permission {forbidden}")

if extension_watch.exists():
    update_text = extension_watch.read_text(encoding="utf-8")
    for required in (
        "workflow_call:",
        "repository: ${{ job.workflow_repository }}",
        "ref: ${{ job.workflow_sha }}",
        "scripts/check-upstream-update.py",
        "scripts/reconcile-update-issue.py",
    ):
        if required not in update_text:
            errors.append(f"check-extension-updates.yml: missing immutable watcher control {required}")
    for forbidden in ("git clone", "git checkout", "windows/ci/", "build-extension.yml@"):
        if forbidden in update_text:
            errors.append(f"check-extension-updates.yml: candidate source execution/build is forbidden: {forbidden}")

if postgres_watch.exists():
    postgres_text = postgres_watch.read_text(encoding="utf-8")
    for required in (
        "workflow_dispatch:",
        "scripts/check-postgresql-updates.py",
        "scripts/reconcile-update-issue.py",
    ):
        if required not in postgres_text:
            errors.append(f"postgresql-update-watch.yml: missing required control {required}")

for watch_path in (extension_watch, postgres_watch):
    if watch_path.exists():
        watch_text = watch_path.read_text(encoding="utf-8")
        if "\\${args[@]}" in watch_text:
            errors.append(f"{watch_path.name}: escaped shell argv expansion is forbidden")
        if "${args[@]}" not in watch_text:
            errors.append(f"{watch_path.name}: shell argv array expansion is required")

for build_name in ("build-extension.yml", "build-extension-attested.yml", "promote-verified-release.yml"):
    build_text = (WORKFLOW_DIR / build_name).read_text(encoding="utf-8")
    if "issues: write" in build_text:
        errors.append(f"{build_name}: issues: write must remain isolated from build/release workflows")

def central_signing_errors(caller_text, reusable_text, upload_reference):
    import yaml

    caller = yaml.load(caller_text, Loader=yaml.BaseLoader)
    reusable = yaml.load(reusable_text, Loader=yaml.BaseLoader)
    read = {"contents": "read", "actions": "read"}
    signing = {"contents": "read", "id-token": "write", "attestations": "write"}
    caller_jobs = caller["jobs"]
    signer_jobs = reusable["jobs"]
    invoke = caller_jobs.get("invoke_central_signer", {})
    problems = []

    if set(caller["on"]) != {"schedule", "issue_comment"} or set(reusable["on"]) != {"workflow_call"}:
        problems.append("central workflows: only the genuine caller events and reusable workflow_call are allowed")
    if (caller.get("permissions") != read or reusable.get("permissions") != signing
            or {name: job.get("permissions") for name, job in caller_jobs.items()} != {
                "authenticate_and_prepare": read,
                "invoke_central_signer": {**read, **signing},
                "verify_central_claims": read,
            }
            or {name: job.get("permissions") for name, job in signer_jobs.items()} != {
                "package": {"contents": "read"},
                "attest": None,
            }):
        problems.append("central workflows: unexpected permissions or signing isolation")
    if not re.fullmatch(
        r"pgextwin/build/\.github/workflows/central-extension-attested\.yml@[a-f0-9]{40}",
        invoke.get("uses", ""),
    ) or any("secrets" in job for document in (caller, reusable) for job in document["jobs"].values()):
        problems.append("central caller: fixed reusable SHA and no secret forwarding required")

    for label, source, document in (
        ("central caller", caller_text, caller), ("central signer", reusable_text, reusable),
    ):
        steps = [step for job in document["jobs"].values() for step in job.get("steps", [])]
        if not any(step.get("uses") == upload_reference for step in steps) or any(
            step.get("uses", "").startswith("actions/upload-artifact@")
            and step["uses"] != upload_reference for step in steps
        ):
            problems.append(f"{label}: upload-artifact must use the validate.yml v7.0.2 pin")
        for step in steps:
            action = step.get("uses", "")
            if action and not re.fullmatch(r"actions/[a-z-]+@[a-f0-9]{40}", action):
                problems.append(f"{label}: invalid pinned action {action}")
            if action and not re.search(
                rf"^\s*(?:- )?uses:\s*{re.escape(action)}\s+# v[0-9]+\.[0-9]+\.[0-9]+\s*$",
                source, re.MULTILINE,
            ):
                problems.append(f"{label}: missing same-line action version comment for {action}")
    return problems


central_caller = WORKFLOW_DIR / "central-signed-main.yml"
central_signer = WORKFLOW_DIR / "central-extension-attested.yml"
upload_v7 = re.search(
    r"(actions/upload-artifact@[a-f0-9]{40}) # v7\.0\.2",
    (WORKFLOW_DIR / "validate.yml").read_text(encoding="utf-8"),
)
if not all(path.is_file() for path in (central_caller, central_signer)) or upload_v7 is None:
    errors.append("central signing workflows and validate.yml upload-artifact v7.0.2 pin are required")
else:
    errors.extend(central_signing_errors(
        central_caller.read_text(encoding="utf-8"),
        central_signer.read_text(encoding="utf-8"),
        upload_v7.group(1),
    ))

def central_publisher_errors(raw):
    from hashlib import sha256

    jobs = (b"  central_publisher_intake_request:", b"  isolated_central_formal_publisher:")
    owner = b"  isolated_owner_source_formal_publisher:"
    combo = b"  isolated_external_direct_catalog_pr:"
    if any(raw.count(marker) != 1 for marker in (*jobs, owner, combo)):
        return ["central Publisher and existing owner/Combo 6 jobs must occur exactly once"]
    start, publisher, end, combo_start = (raw.index(marker) for marker in (*jobs, owner, combo))
    if not start < publisher < end < combo_start:
        return ["central Publisher jobs must be inserted before the existing owner and Combo 6 jobs"]
    result = []
    for name, segment, expected in (
        ("PREFIX", raw[:start], "b74f8f84c5f0781132b29490f7979fc01b3349b674d3a65c5a6c926c418d6e1b"),
        ("SUFFIX", raw[end:], "4305bcc14fd603d34f69bcea22f5be8fd255cb7aa399b07680cab8f548b08612"),
        ("COMBO6", raw[combo_start:], "03a7be885792674048a6f31d8d27297afd34076c759de916cc92f00f8cce657a"),
    ):
        if sha256(segment).hexdigest() != expected:
            result.append(f"publisher-candidate-intake.yml: {name} changed")
    intake, publish = raw[start:publisher].decode(), raw[publisher:end].decode()
    for job in (intake, publish):
        for check in ("github.event_name == 'issue_comment'", "github.ref == 'refs/heads/main'",
                      "github.repository == 'pgextwin/build'", "!github.event.issue.pull_request",
                      "github.event.issue.number == 311", "github.run_attempt == '1'",
                      "startsWith(github.event.comment.body, '/pgextwin publish-central ')",
                      "ref: ${{ github.sha }}", "persist-credentials: false"):
            if check not in job:
                result.append(f"central Publisher trust condition missing: {check}")
        if re.search(r"^ *\w[\w-]*: (?:write|write-all)$", job, re.M):
            result.append("central Publisher workflow credentials must be read-only")
        for use in re.findall(r"^ *-? *uses: (\S+)", job, re.M):
            if not re.fullmatch(r"actions/(checkout|setup-python|upload-artifact|download-artifact)@[a-f0-9]{40}",
                                use):
                result.append("central Publisher actions must be trusted and pinned")
        if any("${{" in block and "github.event.comment" in block
               for block in re.findall(r"^ *run:.*(?:\n {10,}[^\n]*)*", job, re.M)):
            result.append("central Publisher must pass comments through environment variables")
    if "environment:" in intake or "PUBLISHER_PRIVATE_KEY" in intake or "central-publisher-run.py" in intake:
        result.append("central intake must be physically read-only")
    prepare, sep, write = publish.partition("- name: Recheck admission and publish")
    if ("    environment: publisher\n" not in publish or
            "    needs: central_publisher_intake_request\n" not in publish or
            "    concurrency: central-publisher-intake-formal\n" not in publish or not sep or
            "PUBLISHER_PRIVATE_KEY" in prepare or "--phase prepare" not in prepare or
            "--phase publish" not in write or write.count("PUBLISHER_PRIVATE_KEY:") != 1 or
            "CENTRAL_PUBLISHER_PREPARED_SHA256: ${{ steps.prepare.outputs.prepared_sha256 }}" not in write):
        result.append("central publish must use the isolated environment and same-job prepare gate")
    return result


errors.extend(central_publisher_errors((WORKFLOW_DIR / "publisher-candidate-intake.yml").read_bytes()))

if errors:
    print("GitHub Actions trust policy validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print("GitHub Actions trust policy validation passed.")
