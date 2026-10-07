#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(messages):
    for message in messages:
        print(f"- {message}", file=sys.stderr)
    raise SystemExit(1)


def ensure_relative_path(value: str, label: str, errors):
    if "\\" in value:
        errors.append(f"{label} must use repository/package-relative POSIX separators: {value}")
        return
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        errors.append(f"{label} must be relative and must not traverse parents: {value}")
    if not pure.parts or str(pure) in ("", "."):
        errors.append(f"{label} must name a file path.")


def validate_semantics(contract, manifest, repository_root: Path):
    errors = []

    if contract["extension"] != manifest.get("name"):
        errors.append(
            f"contract extension '{contract['extension']}' does not match extension manifest name '{manifest.get('name')}'."
        )

    smoke_script = contract["smokeTest"]["script"]
    ensure_relative_path(smoke_script, "smokeTest.script", errors)
    smoke_path = repository_root / Path(*PurePosixPath(smoke_script).parts)
    if not smoke_path.is_file():
        errors.append(f"smoke test script does not exist: {smoke_script}")

    scenario_ids = [scenario["id"] for scenario in contract["functionalScenarios"]]
    duplicates = sorted(
        {scenario_id for scenario_id in scenario_ids if scenario_ids.count(scenario_id) > 1}
    )
    if duplicates:
        errors.append(
            f"functional scenario IDs must be unique: {', '.join(duplicates)}"
        )
    if not scenario_ids:
        errors.append("at least one functional scenario is required.")

    runtime = contract["runtimeRequirements"]
    setup = contract["testSetup"]
    coverage = contract["coverage"]

    allowed_setup = {
        "none": {"none"},
        "shared": {"shared"},
        "session": {"session"},
        "either": {"shared", "session"},
        "optional": {"none", "shared", "session"},
        "unknown": {"none", "shared", "session"},
    }
    if setup["preload"] not in allowed_setup[runtime["preload"]]:
        errors.append(
            f"testSetup.preload '{setup['preload']}' is incompatible with "
            f"runtimeRequirements.preload '{runtime['preload']}'."
        )

    if setup["backgroundWorker"] and not runtime["backgroundWorker"]:
        errors.append(
            "test setup cannot enable background-worker behavior when "
            "runtimeRequirements.backgroundWorker is false."
        )

    if coverage["backgroundWorker"] == "covered":
        if not runtime["backgroundWorker"]:
            errors.append(
                "backgroundWorker coverage cannot be covered when the extension "
                "has no background-worker runtime characteristic."
            )
        if not setup["backgroundWorker"]:
            errors.append(
                "backgroundWorker coverage is covered but testSetup.backgroundWorker is false."
            )
    elif not runtime["backgroundWorker"] and coverage["backgroundWorker"] != "not-applicable":
        errors.append(
            "backgroundWorker coverage must be not-applicable when the extension "
            "has no background-worker runtime characteristic."
        )
    elif runtime["backgroundWorker"] and coverage["backgroundWorker"] == "not-applicable":
        errors.append(
            "backgroundWorker coverage cannot be not-applicable when the extension "
            "has a background-worker runtime characteristic."
        )

    client = runtime["clientExecutable"]
    for index, package_path in enumerate(client["packagePaths"]):
        ensure_relative_path(
            package_path,
            f"runtimeRequirements.clientExecutable.packagePaths[{index}]",
            errors,
        )

    if client["required"] and not client["packagePaths"]:
        errors.append(
            "a required client executable must declare at least one package path."
        )
    if not client["required"] and client["packagePaths"]:
        errors.append(
            "client executable package paths must be empty when "
            "runtimeRequirements.clientExecutable.required is false."
        )

    if coverage["clientExecutable"] == "covered":
        if not client["required"] or not client["packagePaths"]:
            errors.append(
                "clientExecutable coverage requires a declared required client "
                "executable and package path."
            )
    elif client["required"] and coverage["clientExecutable"] == "not-applicable":
        errors.append(
            "clientExecutable coverage cannot be not-applicable when a client executable is required."
        )
    elif not client["required"] and coverage["clientExecutable"] != "not-applicable":
        errors.append(
            "clientExecutable coverage must be not-applicable when no client executable is required."
        )

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate pgextwin Test Contract v2.")
    parser.add_argument("--schema", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--extension-config", required=True)
    parser.add_argument("--repository-root", default=".")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    contract_path = Path(args.contract)
    manifest_path = Path(args.extension_config)
    repository_root = Path(args.repository_root).resolve()

    try:
        schema = load_json(schema_path)
        contract = load_json(contract_path)
        manifest = load_json(manifest_path)
    except Exception as exc:
        print(f"Test Contract input read failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

    Draft202012Validator.check_schema(schema)
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(contract),
        key=lambda error: list(error.absolute_path),
    )
    if schema_errors:
        messages = []
        for error in schema_errors:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            messages.append(f"schema {location}: {error.message}")
        print("Test Contract schema validation failed:", file=sys.stderr)
        fail(messages)

    semantic_errors = validate_semantics(contract, manifest, repository_root)
    if semantic_errors:
        print("Test Contract semantic validation failed:", file=sys.stderr)
        fail(semantic_errors)

    print(
        f"Test Contract v2 validation passed for {contract['extension']} "
        f"with {len(contract['functionalScenarios'])} functional scenario(s)."
    )


if __name__ == "__main__":
    main()
