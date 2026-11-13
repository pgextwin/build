"""Hostile offline tests for source-owned pg_permissions signed ZIP and SPDX (DENY)."""
import importlib.util
from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "permissions_signed_audit", ROOT / "scripts/issue112-permissions-owned-source-signed-audit.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def files():
    result = {"LICENSE": b"Copyright (c) 2018-2023, CYBERTEC\nprovided that the above copyright notice\n",
              "pg_permissions.control": b"default_version = '1.4'\n"}
    for i in range(7):
        result[f"pg_permissions--1.{i}.sql"] = f"-- test SQL {i}\n".encode()
    return result


def pair(source, pg, **override):
    receipt = {
        "schemaVersion": gate.SCHEMA, "status": "CANDIDATE_ONLY",
        "kind": gate.KIND, "upstreamRepository": gate.SOURCE_REPO,
        "upstreamCommit": gate.SOURCE_SHA, "upstreamPackageVersion": "1.4.1",
        "sqlExtensionDefaultVersion": "1.4", "postgresqlMajor": pg,
        "fullUpstreamLicenseIncluded": True,
        "sourceFileSha256": {n: gate.sha256(v) for n, v in sorted(source.items())},
    }
    receipt.update({f: False for f in gate.FLAGS})
    receipt.update(override)
    contents = {"LICENSE": source["LICENSE"],
                "SOURCE-INPUTS.json": json.dumps(receipt, sort_keys=True).encode() + b"\n"}
    contents.update({"share/extension/" + n: v for n, v in source.items() if n != "LICENSE"})
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, raw in sorted(contents.items()):
            info = zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, raw)
    zip_raw = buf.getvalue()
    spdx = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "name": "pgextwin-private-pg_permissions-1.4.1-pg" + pg,
        "documentNamespace": "https://spdx.org/spdxdocs/pgextwin-issue112-private-" +
                             gate.sha256(zip_raw),
        "packages": [{
            "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
            "sourceInfo": "Exact pinned source commit " + gate.SOURCE_SHA,
            "checksums": [{"algorithm": "SHA256", "checksumValue": gate.sha256(zip_raw)}],
        }],
        "files": [{
            "fileName": "./" + n,
            "licenseConcluded": "NOASSERTION",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": hashlib.sha1(raw).hexdigest()},
                {"algorithm": "SHA256", "checksumValue": gate.sha256(raw)},
            ],
        } for n, raw in sorted(contents.items())],
    }
    return zip_raw, spdx


def populate(root, source):
    for pg in gate.MAJORS:
        raw, spdx = pair(source, pg)
        (root / f"pg_permissions-source-pg{pg}.zip").write_bytes(raw)
        (root / f"pg_permissions-source-pg{pg}.spdx.json").write_text(json.dumps(spdx))


class SignedPermissionsTests(unittest.TestCase):
    def test_main_event_only_and_no_publisher(self):
        w = (ROOT / ".github/workflows/issue112-permissions-owned-source-signed.yml").read_text()
        for marker in ("github.event_name == 'push'", "github.ref == 'refs/heads/main'",
                       "github.run_attempt == 1", 'main["protected"] is True',
                       'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6',
                       "needs: [sign, independent_audit]"):
            self.assertIn(marker, w)
        for forbidden in ("workflow_dispatch:", "pull_request_target:", "contents: write",
                          "external-direct-provider-publisher"):
            self.assertNotIn(forbidden, w)
        self.assertIn("private-candidates/*", w)
        self.assertIn("issue112_pg_permissions_private_sbom.py", w)

    def test_exact_ten_zip_and_spdx_files(self):
        source = files()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            populate(root, source)
            hashes = gate.inspect_local(root, source)
            self.assertEqual(len(hashes), 10)
            self.assertEqual(len({hashes[f"pg_permissions-source-pg{pg}.zip"]
                                  for pg in gate.MAJORS}), 5)

    def test_reject_authorization_tampering_and_spdx_hash(self):
        source = files()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            populate(root, source)
            target = root / "pg_permissions-source-pg18.zip"
            raw, _ = pair(source, "18", publisherAuthorized=True)
            target.write_bytes(raw)
            with self.assertRaisesRegex(gate.Denied, "receipt"):
                gate.inspect_local(root, source)
            raw, spdx = pair(source, "18")
            target.write_bytes(raw)
            spdx["files"][0]["checksums"][1]["checksumValue"] = "0" * 64
            (root / "pg_permissions-source-pg18.spdx.json").write_text(json.dumps(spdx))
            with self.assertRaisesRegex(gate.Denied, "SPDX individual"):
                gate.inspect_local(root, source)
            (root / "extra.zip").write_bytes(b"unexpected")
            with self.assertRaisesRegex(gate.Denied, "missing or unexpected"):
                gate.inspect_local(root, source)

    def test_signer_ref_and_source_digest_bound(self):
        ok = types.SimpleNamespace(returncode=0, stdout=json.dumps(
            [{"verificationResult": {"verified": True}}]))
        with mock.patch.object(gate.subprocess, "run", return_value=ok) as call:
            gate.verify_attestation(".", "pgextwin/build", "a" * 40, {"example.zip": "b" * 64})
        cmd = call.call_args.args[0]
        for expected in ("--source-digest", "--source-ref", "refs/heads/main",
                         "--signer-workflow", "pgextwin/build/" + gate.WORKFLOW):
            self.assertIn(expected, cmd)
        with mock.patch.object(gate.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=1, stdout="")):
            with self.assertRaisesRegex(gate.Denied, "cryptographic"):
                gate.verify_attestation(".", "pgextwin/build", "a" * 40, {"x": "b" * 64})

    def test_dual_audit_rejects_mismatched_sha_and_permission(self):
        receipt = {
            "status": "SIGNED_SOURCE_NONPUBLISHING", "repository": "pgextwin/build",
            "mainSha": "c" * 40, "runId": "123", "runAttempt": 1,
            "event": "push", "PUBLISH": "DENY", "publicGetAuthorized": False,
            "releaseAuthorized": False, "publisherAuthorized": False,
            "artifactSha256": {
                f"pg_permissions-source-pg{pg}.{suffix}": "a" * 64
                for pg in gate.MAJORS for suffix in ("zip", "spdx.json")},
        }
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.json", Path(d) / "b.json"
            def write(x, y):
                a.write_text(json.dumps(dict(x, auditor="first")))
                b.write_text(json.dumps(dict(y, auditor="second")))
            args = types.SimpleNamespace(first=str(a), second=str(b),
                                         sha="c" * 40, run_id="123")
            write(receipt, receipt)
            with mock.patch("builtins.print"):
                gate.join(args)
            write(receipt, dict(receipt, publisherAuthorized=True))
            with self.assertRaisesRegex(gate.Denied, "not a qualifying"):
                gate.join(args)
            tampered = dict(receipt, artifactSha256=dict(receipt["artifactSha256"]))
            tampered["artifactSha256"]["pg_permissions-source-pg18.zip"] = "0" * 64
            write(receipt, tampered)
            with self.assertRaisesRegex(gate.Denied, "disagreement"):
                gate.join(args)


if __name__ == "__main__":
    unittest.main()
