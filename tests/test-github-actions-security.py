from pathlib import Path
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
        attested_text.find("- name: Finalize and validate package metadata"),
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
    normal_text.find("- name: Finalize and validate package metadata"),
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
        for required in (
            "scripts/finalize-package.ps1",
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

for step in (
    "Install PostgreSQL ${{ matrix.major }}",
    "Build extension",
    "Install extension into test PostgreSQL",
    "Functional smoke test",
    "Package Windows binary",
    "Upload package artifact",
):
    if step not in normal_text:
        errors.append(f"build-extension.yml: missing shared build step {step}")
    if attested_text and step not in attested_text:
        errors.append(f"build-extension-attested.yml: missing shared build step {step}")

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

release_workflow = WORKFLOW_DIR / "release-extension.yml"
if not release_workflow.exists():
    errors.append("release-extension.yml: dedicated release reusable workflow is required")
else:
    release_text = release_workflow.read_text(encoding="utf-8")

    if not re.search(r"^\s*contents:\s*write\s*$", release_text, re.MULTILINE):
        errors.append("release-extension.yml: release job must explicitly request contents: write")

    for forbidden in ("id-token: write", "attestations: write", "artifact-metadata: write"):
        if forbidden in release_text:
            errors.append(
                f"release-extension.yml: publication workflow must not request attestation permission {forbidden}"
            )

    if "printf '%s\\n' ./*.zip ./*.spdx.json ./*.vulnerabilities.json | LC_ALL=C sort" not in release_text:
        errors.append(
            "release-extension.yml: checksum input must include ZIP, SPDX JSON, and vulnerability JSON in stable sorted order"
        )
    if 'sha256sum "${release_assets[@]}" > SHA256SUMS.txt' not in release_text:
        errors.append("release-extension.yml: SHA256SUMS.txt generation must be preserved")
    if release_text.count("dist/*.spdx.json") != 2:
        errors.append("release-extension.yml: create/update publication paths must both include SPDX JSON assets")
    if release_text.count("dist/*.vulnerabilities.json") != 2:
        errors.append("release-extension.yml: create/update publication paths must both include vulnerability JSON assets")
    if "gh attestation verify <zip-file>" not in release_text:
        errors.append("release-extension.yml: future release notes must document provenance verification")
    if SPDX_PREDICATE not in release_text:
        errors.append("release-extension.yml: future release notes must document SPDX SBOM attestation verification")
    if "pgextwin/build/.github/workflows/build-extension-attested.yml" not in release_text:
        errors.append("release-extension.yml: release notes must identify the attested signer workflow")


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
        "schedule:",
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

for build_name in ("build-extension.yml", "build-extension-attested.yml", "release-extension.yml"):
    build_text = (WORKFLOW_DIR / build_name).read_text(encoding="utf-8")
    if "issues: write" in build_text:
        errors.append(f"{build_name}: issues: write must remain isolated from build/release workflows")

if errors:
    print("GitHub Actions trust policy validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print("GitHub Actions trust policy validation passed.")
