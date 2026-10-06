#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse


def fail(message: str) -> None:
    print(f"SBOM validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        fail(f"cannot parse JSON '{path}': {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_package_info(zip_path: Path):
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            names = [name for name in archive.namelist() if name == "PACKAGE-INFO.json"]
            if len(names) != 1:
                fail(
                    f"expected exactly one root PACKAGE-INFO.json in final ZIP, found {len(names)}"
                )
            return json.loads(archive.read(names[0]).decode("utf-8-sig"))
    except zipfile.BadZipFile as exc:
        fail(f"final artifact is not a readable ZIP: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a pgextwin Syft SPDX 2.3 SBOM against its final ZIP."
    )
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--zip", required=True)
    parser.add_argument("--expected-extension", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-tool-version", default="1.54.0")
    args = parser.parse_args()

    sbom_path = Path(args.sbom)
    zip_path = Path(args.zip)
    if not sbom_path.is_file():
        fail(f"SBOM file not found: {sbom_path}")
    if not zip_path.is_file():
        fail(f"final ZIP not found: {zip_path}")

    expected_sbom_name = f"{zip_path.stem}.spdx.json"
    if sbom_path.name != expected_sbom_name:
        fail(
            f"SBOM filename must correspond to final ZIP: expected "
            f"'{expected_sbom_name}', found '{sbom_path.name}'"
        )
    if not zip_path.stem.startswith(f"{args.expected_extension}-"):
        fail(
            f"final ZIP basename '{zip_path.stem}' does not identify "
            f"expected extension '{args.expected_extension}'"
        )

    package_info = load_package_info(zip_path)
    try:
        package_name = package_info["package"]["name"]
        upstream_version = package_info["upstream"]["version"]
    except (KeyError, TypeError):
        fail("embedded PACKAGE-INFO.json lacks package.name or upstream.version")
    if package_name != args.expected_extension:
        fail(
            f"PACKAGE-INFO.json package.name mismatch: expected "
            f"'{args.expected_extension}', found '{package_name}'"
        )
    if str(upstream_version) != args.expected_version:
        fail(
            f"PACKAGE-INFO.json upstream.version mismatch: expected "
            f"'{args.expected_version}', found '{upstream_version}'"
        )

    document = load_json(sbom_path)
    if document.get("spdxVersion") != "SPDX-2.3":
        fail(f"spdxVersion must be SPDX-2.3, found {document.get('spdxVersion')!r}")
    if document.get("dataLicense") != "CC0-1.0":
        fail(f"dataLicense must be CC0-1.0, found {document.get('dataLicense')!r}")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        fail(f"document SPDXID must be SPDXRef-DOCUMENT, found {document.get('SPDXID')!r}")

    namespace = document.get("documentNamespace")
    if not isinstance(namespace, str) or not namespace:
        fail("documentNamespace is missing")
    if not urlparse(namespace).scheme:
        fail(f"documentNamespace is not an absolute URI: {namespace!r}")

    creation_info = document.get("creationInfo")
    if not isinstance(creation_info, dict):
        fail("creationInfo is missing")
    creators = creation_info.get("creators")
    if not isinstance(creators, list) or not creators:
        fail("creationInfo.creators is missing or empty")
    expected_creator = f"Tool: syft-{args.expected_tool_version}"
    if expected_creator not in creators:
        fail(
            f"creationInfo.creators does not contain exact generator "
            f"'{expected_creator}': {creators!r}"
        )

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("packages is missing or empty; source identity was not represented")

    source_package = next(
        (package for package in packages if package.get("name") == zip_path.stem),
        None,
    )
    if source_package is None:
        fail(
            f"source/root package matching final ZIP basename '{zip_path.stem}' was not found"
        )
    if str(source_package.get("versionInfo")) != args.expected_version:
        fail(
            f"source package versionInfo mismatch: expected '{args.expected_version}', "
            f"found {source_package.get('versionInfo')!r}"
        )
    if source_package.get("supplier") != "Organization: pgextwin":
        fail(
            "source package supplier must identify pgextwin as the distributor; "
            f"found {source_package.get('supplier')!r}"
        )

    source_spdx_id = source_package.get("SPDXID")
    if not isinstance(source_spdx_id, str) or not source_spdx_id.startswith("SPDXRef-"):
        fail("source package SPDXID is missing or malformed")

    described = document.get("documentDescribes")
    relationships = document.get("relationships") or []
    describes_via_relationship = any(
        relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and relationship.get("relationshipType") == "DESCRIBES"
        and relationship.get("relatedSpdxElement") == source_spdx_id
        for relationship in relationships
        if isinstance(relationship, dict)
    )
    describes_via_property = (
        isinstance(described, list) and source_spdx_id in described
    )
    if not (describes_via_property or describes_via_relationship):
        fail(
            "SPDX document does not DESCRIBE the final ZIP source package "
            "via documentDescribes or an SPDXRef-DOCUMENT DESCRIBES relationship"
        )

    expected_zip_sha256 = sha256_file(zip_path)
    checksums = source_package.get("checksums") or []
    source_sha256 = next(
        (
            checksum.get("checksumValue", "").lower()
            for checksum in checksums
            if checksum.get("algorithm") == "SHA256"
        ),
        None,
    )
    if source_sha256 != expected_zip_sha256:
        fail(
            "source package SHA-256 does not match final ZIP; "
            f"expected {expected_zip_sha256}, found {source_sha256!r}"
        )

    files = document.get("files")
    file_count = len(files) if isinstance(files, list) else 0
    detected_packages = [
        package for package in packages if package.get("SPDXID") != source_spdx_id
    ]
    detected_summary = ", ".join(
        f"{package.get('name', '<unnamed>')}@{package.get('versionInfo', '<unknown>')}"
        for package in detected_packages[:20]
    )
    if len(detected_packages) > 20:
        detected_summary += f", ... (+{len(detected_packages) - 20} more)"
    if not detected_summary:
        detected_summary = (
            "(none; native package content is represented by the source/root package "
            "and file inventory)"
        )

    print("SBOM validation passed.")
    print(f"SPDX version: {document['spdxVersion']}")
    print(f"Document name: {document.get('name')}")
    print(f"Document namespace: {namespace}")
    print(f"Source package: {source_package['name']} {source_package.get('versionInfo')}")
    print(f"Source supplier: {source_package.get('supplier')}")
    print(f"Source ZIP SHA-256: {source_sha256}")
    print(f"Generator: {expected_creator}")
    print(f"Package count: {len(packages)}")
    print(f"File count: {file_count}")
    print(f"Automatically cataloged packages: {detected_summary}")


if __name__ == "__main__":
    main()
