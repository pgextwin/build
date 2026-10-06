from pathlib import Path
import re
import sys

WORKFLOW_DIR = Path(".github/workflows")
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.*))?\s*$")
VERSION_COMMENT = re.compile(r"\bv\d+(?:\.\d+){0,2}\b")
ATTEST_PIN = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"

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

    if ATTEST_PIN not in attested_text:
        errors.append("build-extension-attested.yml: actions/attest v4.2.2 must use the approved full SHA pin")

    if "subject-path: dist/*.zip" not in attested_text:
        errors.append("build-extension-attested.yml: final dist ZIP must be the provenance subject")

    if "gh attestation verify" not in attested_text:
        errors.append("build-extension-attested.yml: provenance must be verified with GitHub CLI")

    signer = "PGEXTWIN_SIGNER_WORKFLOW: ${{ job.workflow_repository }}/.github/workflows/build-extension-attested.yml"
    if signer not in attested_text:
        errors.append("build-extension-attested.yml: verification must constrain the attested signer workflow")

    order = [
        attested_text.find("- name: Package Windows binary"),
        attested_text.find("- name: Generate build provenance attestation"),
        attested_text.find("- name: Verify build provenance attestation"),
        attested_text.find("- name: Upload package artifact"),
    ]
    if any(index < 0 for index in order) or order != sorted(order):
        errors.append(
            "build-extension-attested.yml: required order is package -> attest -> verify -> upload"
        )

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

    if "sha256sum ./*.zip > SHA256SUMS.txt" not in release_text:
        errors.append("release-extension.yml: SHA256SUMS.txt generation must be preserved")

    if "gh attestation verify <zip-file>" not in release_text:
        errors.append("release-extension.yml: future release notes must document provenance verification")

    if "pgextwin/build/.github/workflows/build-extension-attested.yml" not in release_text:
        errors.append("release-extension.yml: release notes must identify the attested signer workflow")

if errors:
    print("GitHub Actions trust policy validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print("GitHub Actions trust policy validation passed.")
