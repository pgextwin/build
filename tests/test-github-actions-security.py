from pathlib import Path
import re
import sys

WORKFLOW_DIR = Path(".github/workflows")
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(.*))?\s*$")
VERSION_COMMENT = re.compile(r"\bv\d+(?:\.\d+){0,2}\b")

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

build_workflow = WORKFLOW_DIR / "build-extension.yml"
build_text = build_workflow.read_text(encoding="utf-8")

if build_text.count("repository: ${{ job.workflow_repository }}") < 2:
    errors.append(
        "build-extension.yml: shared build source checkout must use job.workflow_repository in matrix and build jobs"
    )

if build_text.count("ref: ${{ job.workflow_sha }}") < 2:
    errors.append(
        "build-extension.yml: shared build source checkout must use job.workflow_sha in matrix and build jobs"
    )

if re.search(r"repository:\s*pgextwin/build[\s\S]{0,200}?ref:\s*(?:main|refs/heads/main)\b", build_text):
    errors.append("build-extension.yml: mutable pgextwin/build main checkout is forbidden")

if re.search(r"^\s*contents:\s*write\s*$", build_text, re.MULTILINE):
    errors.append("build-extension.yml: build reusable workflow must not request contents: write")

if not re.search(
    r"attest_provenance:\s*\n(?:\s+.*\n)*?\s+type:\s*boolean\s*\n\s+default:\s*false\s*$",
    build_text,
    re.MULTILINE,
):
    errors.append("build-extension.yml: attest_provenance must be a boolean input defaulting to false")

attest_pin = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
if attest_pin not in build_text:
    errors.append("build-extension.yml: actions/attest v4.2.2 must use the approved full SHA pin")

for permission in ("id-token: write", "attestations: write", "artifact-metadata: write"):
    if permission not in build_text:
        errors.append(f"build-extension.yml: attested build contract must request {permission}")

if build_text.count("if: ${{ inputs.attest_provenance }}") < 2:
    errors.append("build-extension.yml: attestation generation and verification must be opt-in gated")

if "subject-path: dist/*.zip" not in build_text:
    errors.append("build-extension.yml: final dist ZIP must be the provenance subject")

if "gh attestation verify" not in build_text:
    errors.append("build-extension.yml: attested release build must verify provenance with GitHub CLI")

if "--signer-workflow $env:PGEXTWIN_SIGNER_WORKFLOW" not in build_text:
    errors.append("build-extension.yml: verification must constrain the reusable signer workflow")

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

if errors:
    print("GitHub Actions trust policy validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print("GitHub Actions trust policy validation passed.")
