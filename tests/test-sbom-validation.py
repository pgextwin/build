#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-sbom.py"
PACKAGE_INFO_FIXTURE = ROOT / "tests" / "fixtures" / "package-info-valid.json"


def run_case(document, expected_success: bool, label: str) -> None:
    with tempfile.TemporaryDirectory(prefix="pgextwin-sbom-test-") as tmp:
        temp = Path(tmp)
        zip_path = temp / "pg_bigm-v1.2-20250903-pg18-windows-x64.zip"
        sbom_path = temp / "pg_bigm-v1.2-20250903-pg18-windows-x64.spdx.json"

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("PACKAGE-INFO.json", PACKAGE_INFO_FIXTURE.read_bytes())
            archive.writestr("lib/pg_bigm.dll", b"fixture")

        digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
        document["packages"][0]["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": digest}
        ]
        sbom_path.write_text(json.dumps(document), encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--sbom",
                str(sbom_path),
                "--zip",
                str(zip_path),
                "--expected-extension",
                "pg_bigm",
                "--expected-version",
                "1.2",
                "--expected-tool-version",
                "1.54.1",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if (result.returncode == 0) != expected_success:
            raise AssertionError(
                f"{label}: unexpected validator result {result.returncode}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )


base = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "pg_bigm-v1.2-20250903-pg18-windows-x64",
    "documentNamespace": "https://anchore.com/syft/file/fixture-1234",
    "creationInfo": {
        "creators": ["Organization: Anchore, Inc", "Tool: syft-1.54.1"],
        "created": "2026-10-07T00:00:00Z",
    },
    "packages": [
        {
            "name": "pg_bigm-v1.2-20250903-pg18-windows-x64",
            "SPDXID": "SPDXRef-DocumentRoot-File-pg-bigm",
            "versionInfo": "1.2",
            "supplier": "Organization: pgextwin",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": "SPDXRef-DocumentRoot-File-pg-bigm",
            "relationshipType": "DESCRIBES",
        }
    ],
}

run_case(json.loads(json.dumps(base)), True, "valid SPDX 2.3 fixture")

wrong_version = json.loads(json.dumps(base))
wrong_version["spdxVersion"] = "SPDX-2.2"
run_case(wrong_version, False, "wrong SPDX version")

wrong_tool = json.loads(json.dumps(base))
wrong_tool["creationInfo"]["creators"][1] = "Tool: syft-1.53.0"
run_case(wrong_tool, False, "wrong Syft version")

wrong_supplier = json.loads(json.dumps(base))
wrong_supplier["packages"][0]["supplier"] = "Organization: upstream"
run_case(wrong_supplier, False, "wrong source supplier")

print("SBOM validator regression tests passed.")
