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

if errors:
    print("GitHub Actions trust policy validation failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print("GitHub Actions trust policy validation passed.")
