"""Hostile offline tests for independent Issue112 source-owned signed candidate gate."""
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "track_signed_audit", ROOT / "scripts/issue112-track-owned-source-signed-audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def sample_files():
    files = {
        "LICENSE": b"Copyright (c) 2015-2023, Julien Rouhaud\n"
                   b"provided that the above copyright notice\n",
        "pg_track_settings.control": b"default_version = '2.1.2'\n",
    }
    for i in range(12):
        files[f"pg_track_settings--{i}.sql"] = f"-- local test {i}\n".encode()
    return files


def archive(files, pg, **flags):
    meta = {
        "schemaVersion": audit.SCHEMA, "status": "CANDIDATE_ONLY",
        "kind": audit.KIND, "upstreamRepository": audit.SOURCE_REPO,
        "upstreamCommit": audit.SOURCE_SHA, "upstreamVersion": "2.1.2",
        "postgresqlMajor": pg, "rightsNoticeIncluded": True,
        "sourceFileSha256": {k: audit.sha256(v) for k, v in sorted(files.items())},
    }
    meta.update({k: False for k in audit.FLAGS})
    meta.update(flags)
    members = {"LICENSE": files["LICENSE"],
               "SOURCE-INPUTS.json": (json.dumps(meta, sort_keys=True) + "\n").encode()}
    members.update({"share/extension/" + k: v for k, v in files.items() if k != "LICENSE"})
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, raw)
    return output.getvalue()


class SignedSourceGateTests(unittest.TestCase):
    def test_signing_only_on_original_protected_main(self):
        workflow = (ROOT / ".github/workflows/issue112-track-owned-source-signed.yml").read_text()
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.run_attempt == 1", workflow)
        self.assertIn("main[\"protected\"] is True", workflow)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", workflow)
        self.assertIn("needs: [sign, independent_audit]", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull_request_target:", workflow)

    def test_original_source_members_and_all_five_digests(self):
        files = sample_files()
        with tempfile.TemporaryDirectory() as folder:
            for pg in audit.MAJORS:
                (Path(folder) / f"pg_track_settings-source-pg{pg}.zip").write_bytes(
                    archive(files, pg))
            hashes = audit.inspect_local(folder, files)
            self.assertEqual(len(hashes), 5)
            self.assertEqual(len(set(hashes.values())), 5)

    def test_reject_publish_flag_modified_source_and_extra_archive(self):
        files = sample_files()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for pg in audit.MAJORS:
                (root / f"pg_track_settings-source-pg{pg}.zip").write_bytes(archive(files, pg))
            target = root / "pg_track_settings-source-pg18.zip"
            target.write_bytes(archive(files, "18", publisherAuthorized=True))
            with self.assertRaisesRegex(audit.Denied, "metadata/source/deny"):
                audit.inspect_local(root, files)
            target.write_bytes(archive(files, "18"))
            files["pg_track_settings.control"] = b"malicious replacement"
            with self.assertRaisesRegex(audit.Denied, "source member byte mismatch"):
                audit.inspect_local(root, files)
            (root / "unexpected.zip").write_bytes(b"poisoned")
            with self.assertRaisesRegex(audit.Denied, "missing or unexpected"):
                audit.inspect_local(root, files)

    def test_signature_verifier_pins_source_and_signer(self):
        with tempfile.TemporaryDirectory() as folder:
            cp = types.SimpleNamespace(returncode=0,
                                       stdout=json.dumps([{"verificationResult": {}}]))
            with mock.patch.object(audit.subprocess, "run", return_value=cp) as call:
                audit.verify_attestation(folder, "pgextwin/build", "a" * 40, {"file.zip": "b" * 64})
            cmd = call.call_args.args[0]
            self.assertIn("--source-digest", cmd)
            self.assertIn("--source-ref", cmd)
            self.assertIn("refs/heads/main", cmd)
            self.assertIn("--signer-workflow", cmd)
            self.assertIn("pgextwin/build/" + audit.WORKFLOW, cmd)
            with mock.patch.object(audit.subprocess, "run",
                                   return_value=types.SimpleNamespace(returncode=1, stdout="")):
                with self.assertRaisesRegex(audit.Denied, "cryptographic"):
                    audit.verify_attestation(folder, "pgextwin/build", "a" * 40,
                                             {"file.zip": "b" * 64})

    def test_dual_join_fails_on_different_bytes_or_publisher_permission(self):
        receipt = {
            "status": "SIGNED_SOURCE_NONPUBLISHING",
            "repository": "pgextwin/build", "mainSha": "c" * 40,
            "runId": "123", "runAttempt": 1, "event": "push",
            "PUBLISH": "DENY", "publicGetAuthorized": False,
            "releaseAuthorized": False, "publisherAuthorized": False,
            "zipSha256": {f"pg_track_settings-source-pg{pg}.zip": str(pg) for pg in audit.MAJORS},
        }
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder) / "a.json", Path(folder) / "b.json"
            def write(first, second):
                a.write_text(json.dumps(dict(first, auditor="first")))
                b.write_text(json.dumps(dict(second, auditor="second")))
            args = types.SimpleNamespace(first=str(a), second=str(b),
                                         sha="c" * 40, run_id="123")
            write(receipt, receipt)
            with mock.patch("builtins.print"):
                audit.join(args)
            write(receipt, dict(receipt, publisherAuthorized=True))
            with self.assertRaisesRegex(audit.Denied, "not a qualifying"):
                audit.join(args)
            write(receipt, dict(receipt, zipSha256=dict(receipt["zipSha256"],
                                                        **{"pg_track_settings-source-pg18.zip": "mismatch"})))
            with self.assertRaisesRegex(audit.Denied, "evidence disagreement"):
                audit.join(args)


if __name__ == "__main__":
    unittest.main()
