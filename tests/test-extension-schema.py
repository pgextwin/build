import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "extension.schema.json"
FIXTURES = ROOT / "tests" / "fixtures"


def load(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def assert_rejected(validator: Draft202012Validator, manifest: dict, case_name: str) -> None:
    if validator.is_valid(manifest):
        raise RuntimeError(f"Expected extension.schema.json to reject {case_name}.")


def main() -> None:
    schema = load(SCHEMA)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    manifests = sorted(FIXTURES.glob("extension-*.json"))
    if not manifests:
        raise RuntimeError("No extension manifest fixtures found.")

    errors = []
    for path in manifests:
        for error in sorted(validator.iter_errors(load(path)), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.path) or "<root>"
            errors.append(f"{path.name}:{location}: {error.message}")

    if errors:
        raise RuntimeError("\n".join(errors))

    base = load(FIXTURES / "extension-packaging-license.json")

    only_packaging = copy.deepcopy(base)
    only_packaging["license"]["files"] = [base["license"]["files"][1]]
    assert_rejected(validator, only_packaging, "files with only packaging origin")

    missing_sha = copy.deepcopy(base)
    del missing_sha["license"]["files"][1]["sha256"]
    assert_rejected(validator, missing_sha, "packaging license without sha256")

    bad_sha_upper = copy.deepcopy(base)
    bad_sha_upper["license"]["files"][1]["sha256"] = "A" * 64
    assert_rejected(validator, bad_sha_upper, "packaging license with uppercase sha256")

    bad_sha_short = copy.deepcopy(base)
    bad_sha_short["license"]["files"][1]["sha256"] = "a" * 63
    assert_rejected(validator, bad_sha_short, "packaging license with short sha256")

    mixed_origin_upstream = copy.deepcopy(base)
    mixed_origin_upstream["license"]["files"][1]["upstreamPath"] = "LICENSE"
    assert_rejected(validator, mixed_origin_upstream, "packaging license combined with upstreamPath")

    bad_generated_source = copy.deepcopy(base)
    bad_generated_source["license"]["files"][2]["generatedSource"] = "packaging"
    assert_rejected(validator, bad_generated_source, "build license with invalid generatedSource")

    missing_generated_path = copy.deepcopy(base)
    del missing_generated_path["license"]["files"][2]["generatedPath"]
    assert_rejected(validator, missing_generated_path, "build license without generatedPath")

    per_pg_only_packaging = copy.deepcopy(base)
    per_pg_only_packaging["license"] = {
        "verifyAgainstUpstream": True,
        "perPostgresql": {
            "17": [copy.deepcopy(base["license"]["files"][1])],
        },
    }
    assert_rejected(validator, per_pg_only_packaging, "perPostgresql with only packaging origin")

    print(f"extension.schema.json validated against {len(manifests)} fixture(s).")


if __name__ == "__main__":
    main()
