#!/usr/bin/env python3
"""Archived Release workflow body; never an executable publishing route."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"


class RetiredReleaseHistory(unittest.TestCase):
    def test_archived_create_only_release_body(self):
        errors = []
        # Keep historical create-only contract checks without an executable old Release route.
        release_workflow = (ROOT / "tests/fixtures/historical-workflows/release-extension.yml")
        if not release_workflow.exists():
            errors.append("archived release-extension.yml: required historical fixture missing")
        else:
            release_text = release_workflow.read_text(encoding="utf-8")

            if not re.search(r"^\s*contents:\s*write\s*$", release_text, re.MULTILINE):
                errors.append("release-extension.yml: release job must explicitly request contents: write")

            for forbidden in ("id-token: write", "attestations: write", "artifact-metadata: write"):
                if forbidden in release_text:
                    errors.append(
                        f"release-extension.yml: publication workflow must not request attestation permission {forbidden}"
                    )

            if "printf '%s\\n' ./*.zip ./*.spdx.json ./*.vulnerabilities.json | LC_ALL=C sort" not in release_text:
                errors.append(
                    "release-extension.yml: checksum input must include ZIP, SPDX JSON, and vulnerability JSON in stable sorted order"
                )
            if 'sha256sum "${release_assets[@]}" > SHA256SUMS.txt' not in release_text:
                errors.append("release-extension.yml: SHA256SUMS.txt generation must be preserved")
            if release_text.count("dist/*.spdx.json") != 1:
                errors.append("release-extension.yml: create-only publication must include SPDX JSON assets")
            if release_text.count("dist/*.vulnerabilities.json") != 1:
                errors.append("release-extension.yml: create-only publication must include vulnerability JSON assets")
            for forbidden in ("gh release edit", "gh release upload", "--clobber"):
                if forbidden in release_text:
                    errors.append("release-extension.yml: existing release mutation is forbidden: " + forbidden)
            if release_text.count("gh release create") != 1:
                errors.append("release-extension.yml: exactly one create-only publication path required")
            if "gh attestation verify <zip-file>" not in release_text:
                errors.append("release-extension.yml: future release notes must document provenance verification")
            if SPDX_PREDICATE not in release_text:
                errors.append("release-extension.yml: future release notes must document SPDX SBOM attestation verification")
            if "pgextwin/build/.github/workflows/build-extension-attested.yml" not in release_text:
                errors.append("release-extension.yml: release notes must identify the attested signer workflow")
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
