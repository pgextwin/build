#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
from pathlib import Path


PREDICATE_TYPE = "https://spdx.dev/Document/v2.3"


def fail(message: str) -> None:
    print(f"SBOM attestation comparison failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        fail(f"cannot parse JSON '{path}': {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare a verified GitHub SPDX attestation with the local SBOM and ZIP."
    )
    parser.add_argument("--verification-json", required=True)
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--zip", required=True)
    args = parser.parse_args()

    verification = load_json(Path(args.verification_json))
    local_sbom = load_json(Path(args.sbom))
    zip_path = Path(args.zip)
    expected_digest = sha256_file(zip_path)

    if not isinstance(verification, list) or not verification:
        fail("gh attestation verify JSON result is empty or not an array")

    candidates = []
    for item in verification:
        try:
            statement = item["verificationResult"]["statement"]
        except (KeyError, TypeError):
            continue
        if statement.get("predicateType") == PREDICATE_TYPE:
            candidates.append(statement)

    if not candidates:
        fail(f"no verified statement has predicateType {PREDICATE_TYPE}")

    matching = None
    for statement in candidates:
        for subject in statement.get("subject") or []:
            digest = (subject.get("digest") or {}).get("sha256", "").lower()
            if subject.get("name") == zip_path.name and digest == expected_digest:
                matching = statement
                break
        if matching is not None:
            break

    if matching is None:
        fail(
            "no verified SPDX attestation subject matches the final ZIP name and SHA-256 "
            f"({zip_path.name}, {expected_digest})"
        )

    predicate = matching.get("predicate")
    if predicate != local_sbom:
        fail(
            "verified attestation predicate is not semantically identical to the generated SPDX JSON"
        )

    if predicate.get("spdxVersion") != "SPDX-2.3":
        fail("verified predicate does not contain SPDX-2.3")

    print("SBOM attestation comparison passed.")
    print(f"Predicate type: {PREDICATE_TYPE}")
    print(f"Subject: {zip_path.name}")
    print(f"Subject SHA-256: {expected_digest}")
    print("Predicate: semantically identical to generated SPDX JSON")


if __name__ == "__main__":
    main()
