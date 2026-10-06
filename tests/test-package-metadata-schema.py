#!/usr/bin/env python3
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "package-info.schema.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "package-info-valid.json"

schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())


def assert_valid(instance, label):
    errors = list(validator.iter_errors(instance))
    if errors:
        raise AssertionError(f"{label} unexpectedly invalid: {errors[0].message}")


def assert_invalid(instance, label):
    if validator.is_valid(instance):
        raise AssertionError(f"{label} unexpectedly passed schema validation")


assert_valid(fixture, "valid fixture")

case = copy.deepcopy(fixture)
del case["upstream"]["commit"]
assert_invalid(case, "missing required upstream.commit")

case = copy.deepcopy(fixture)
case["upstream"]["commit"] = "deadbeef"
assert_invalid(case, "malformed SHA")

case = copy.deepcopy(fixture)
case["package"]["architecture"] = "arm64"
assert_invalid(case, "wrong architecture")

case = copy.deepcopy(fixture)
case["source"]["packagingRepository"] = "not-a-repository"
assert_invalid(case, "invalid repository")

case = copy.deepcopy(fixture)
case["postgresql"]["major"] = 0
assert_invalid(case, "invalid PostgreSQL major")

case = copy.deepcopy(fixture)
case["workflowRun"]["url"] = "not a uri"
assert_invalid(case, "invalid workflow run URL")

print("PACKAGE-INFO.json schema tests passed.")
