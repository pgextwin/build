import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "extension.schema.json"
FIXTURES = ROOT / "tests" / "fixtures"


def load(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


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

    print(f"extension.schema.json validated against {len(manifests)} fixture(s).")


if __name__ == "__main__":
    main()
