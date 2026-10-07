#!/usr/bin/env python3
import copy
import importlib.util
import json
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "test-contract.schema.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "test-contract-valid.json"
VALIDATOR_PATH = ROOT / "scripts" / "validate-test-contract.py"

schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)

spec = importlib.util.spec_from_file_location("validate_test_contract", VALIDATOR_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def assert_valid(instance, label):
    errors = list(validator.iter_errors(instance))
    if errors:
        raise AssertionError(f"{label} unexpectedly invalid: {errors[0].message}")


def assert_invalid(instance, label):
    if validator.is_valid(instance):
        raise AssertionError(f"{label} unexpectedly passed schema validation")


assert_valid(fixture, "valid fixture")

case = copy.deepcopy(fixture)
case["contractVersion"] = 3
assert_invalid(case, "unsupported contractVersion")

case = copy.deepcopy(fixture)
del case["extension"]
assert_invalid(case, "extension missing")

case = copy.deepcopy(fixture)
case["functionalScenarios"][0]["id"] = "Bad Scenario"
assert_invalid(case, "invalid scenario ID")

case = copy.deepcopy(fixture)
case["functionalScenarios"] = []
assert_invalid(case, "zero functional scenarios")

case = copy.deepcopy(fixture)
case["runtimeRequirements"]["preload"] = "startup"
assert_invalid(case, "invalid preload mode")

case = copy.deepcopy(fixture)
case["smokeTest"]["script"] = "../windows/ci/smoke-test.ps1"
assert_invalid(case, "parent-traversing path")

case = copy.deepcopy(fixture)
case["smokeTest"]["script"] = "C:/temp/smoke-test.ps1"
assert_invalid(case, "absolute Windows path")

case = copy.deepcopy(fixture)
case["coverage"]["upgrade"] = "tested"
assert_invalid(case, "invalid coverage status")

with tempfile.TemporaryDirectory() as temp:
    repo = Path(temp)
    smoke = repo / "windows" / "ci" / "smoke-test.ps1"
    smoke.parent.mkdir(parents=True)
    smoke.write_text("# fixture\n", encoding="utf-8")
    manifest = {"name": "fixture_extension"}

    semantic_errors = module.validate_semantics(fixture, manifest, repo)
    if semantic_errors:
        raise AssertionError(f"valid semantic fixture failed: {semantic_errors}")

    case = copy.deepcopy(fixture)
    case["functionalScenarios"].append(copy.deepcopy(case["functionalScenarios"][0]))
    errors = module.validate_semantics(case, manifest, repo)
    if not any("unique" in error for error in errors):
        raise AssertionError("duplicate scenario ID was not rejected")

    errors = module.validate_semantics(fixture, {"name": "other_extension"}, repo)
    if not any("does not match" in error for error in errors):
        raise AssertionError("extension/manifest mismatch was not rejected")

    case = copy.deepcopy(fixture)
    case["smokeTest"]["script"] = "windows/ci/missing.ps1"
    errors = module.validate_semantics(case, manifest, repo)
    if not any("does not exist" in error for error in errors):
        raise AssertionError("missing smoke-test script was not rejected")

    case = copy.deepcopy(fixture)
    case["runtimeRequirements"]["clientExecutable"]["packagePaths"] = []
    errors = module.validate_semantics(case, manifest, repo)
    if not any("package path" in error for error in errors):
        raise AssertionError("covered client executable without path was not rejected")

    case = copy.deepcopy(fixture)
    case["runtimeRequirements"]["preload"] = "shared"
    case["testSetup"]["preload"] = "none"
    errors = module.validate_semantics(case, manifest, repo)
    if not any("incompatible" in error for error in errors):
        raise AssertionError("incompatible runtime/test preload modes were not rejected")

print("Test Contract v2 schema and semantic validator tests passed.")
