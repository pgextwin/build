#!/usr/bin/env python3
"""Issue75 actual local POSIX fsync/create-only behavior; NO live Publisher."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    "private_prewrite", ROOT/"scripts"/"issue-75-durable-prewrite-seal.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def record():
    return {
        "schemaVersion":1,
        "requestId":"a"*64,
        "repository":"pgextwin/pgtap",
        "sourceSha":"b"*40,
        "signerWorkflowSha":"c"*40,
        "tag":"v1.0-windows.1",
        "runId":192837,
        "attempt":1,
        "assetHashes":{"pgtap-pg18.zip":"d"*64,
                       "pgtap-pg18.spdx.json":"e"*64},
    }

class DurablePrewriteTests(TestCase):
    def test_owner_only_create_once_fsync_and_read_is_not_a_receipt(self):
        with TemporaryDirectory() as folder:
            first=m.seal(folder,record())
            self.assertEqual(first["classification"],
                             "LOCAL_CREATE_ONLY_SEAL_NOT_PUBLICATION_AUTHORITY")
            self.assertEqual(first["goB"],"NO_GO")
            self.assertFalse(first["mutationAuthorized"])
            self.assertFalse(first["retryAuthorized"])
            path=Path(folder)/(record()["requestId"]+".json")
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            second=m.inspect(folder,record()["requestId"])
            self.assertEqual(second["recordSha256"],first["recordSha256"])
            self.assertEqual(second["classification"],
                             "LOCAL_READ_ONLY_SEAL_NO_REMOTE_VERIFICATION")
            self.assertFalse(second["publicationAuthorized"])
            with self.assertRaises(m.Deny):m.seal(folder,record())
            self.assertEqual(path.read_text().count("\n"),1)
            self.assertEqual(json.loads(path.read_text()),record())

    def test_all_three_allowlisted_and_invalid_targets_denied(self):
        for target in sorted(m.TARGETS):
            with self.subTest(target=target), TemporaryDirectory() as folder:
                r=record()
                r["repository"]=target
                m.seal(folder,r)
                self.assertFalse(m.inspect(folder,r["requestId"])["retryAuthorized"])
        for target in ("pgextwin/catalog","pgextwin/website",
                       "pgextwin/plpgsql_check","pgextwin/pgtap/",
                       "attacker/pgtap","",None,True):
            with self.subTest(invalid=target), TemporaryDirectory() as folder:
                r=record()
                r["repository"]=target
                with self.assertRaises(m.Deny):m.seal(folder,r)
                self.assertEqual(list(Path(folder).iterdir()),[])

    def test_malformed_duplicate_and_sensitive_extra_fields_denied(self):
        mutated=[
            ("schemaVersion",True),("requestId","../evil"),
            ("sourceSha","x"*40),("signerWorkflowSha","f"*39),
            ("tag","../fake"),("runId",True),("attempt",0),
            ("attempt",1001),("assetHashes",{}),
            ("assetHashes",{"pgtap.zip":"d"*64}),
            ("assetHashes",{"pgtap.zip":"d"*64,
                             "bad/asset.spdx.json":"e"*64}),
            ("assetHashes",{"pgtap.zip":"d"*64,
                             "pgtap.spdx.json":"e"*63}),
        ]
        for field,value in mutated:
            with self.subTest(field=field,value=str(value)[:30]):
                r=record()
                r[field]=value
                with TemporaryDirectory() as folder:
                    with self.assertRaises(m.Deny):m.seal(folder,r)
                    self.assertEqual(list(Path(folder).iterdir()),[])
        for extra in ("token","authorization","privateKey",
                      "publicationAuthorized","goB","path"):
            with self.subTest(extra=extra), TemporaryDirectory() as folder:
                r=record()
                r[extra]="attacker"
                with self.assertRaises(m.Deny):m.seal(folder,r)

    def test_symlink_weak_permissions_and_workspace_are_denied(self):
        with TemporaryDirectory() as root:
            good=Path(root)/"store"
            good.mkdir(mode=0o700)
            sym=Path(root)/"alias"
            sym.symlink_to(good)
            with self.assertRaises(m.Deny):m.seal(str(sym),record())
            os.chmod(good,0o755)
            with self.assertRaises(m.Deny):m.seal(str(good),record())
            os.chmod(good,0o700)
            with mock.patch.dict(os.environ,{"GITHUB_WORKSPACE":str(root)}):
                with self.assertRaises(m.Deny):m.seal(str(good),record())
            with self.assertRaises(m.Deny):m.seal("relative/store",record())

    def test_fsync_failure_keeps_uncertain_file_quarantined(self):
        with TemporaryDirectory() as folder:
            with mock.patch.object(m.os,"fsync",side_effect=OSError("offline failure")):
                with self.assertRaises(m.Deny):m.seal(folder,record())
            path=Path(folder)/(record()["requestId"]+".json")
            self.assertTrue(path.exists())  # Never delete uncertain bytes.
            with self.assertRaises(m.Deny):m.seal(folder,record())
            # Even a wholly matching read cannot authorize a replay.
            self.assertFalse(m.inspect(folder,record()["requestId"])["retryAuthorized"])

    def test_corrupted_truncated_symlink_and_replaced_file_denied(self):
        with TemporaryDirectory() as folder:
            r=record()
            m.seal(folder,r)
            file=Path(folder)/(r["requestId"]+".json")
            file.write_text(file.read_text().replace("pgextwin/pgtap","pgextwin/website"))
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            file.write_text(json.dumps(r))  # Noncanonical/unsealed, no newline
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            file.unlink()
            file.symlink_to(Path(folder)/"nonexistent")
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            file.unlink()
            file.write_text('{"schemaVersion":1,"schemaVersion":1}\n')
            os.chmod(file,0o600)
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            file.chmod(0o644)
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])

    def test_library_does_not_invoke_any_publisher_or_credentials(self):
        source=(ROOT/"scripts"/"issue-75-durable-prewrite-seal.py").read_text()
        for forbidden in ("if __name__ ==", "requests.", "urllib.",
                          "GITHUB_TOKEN","GH_TOKEN","gh release",
                          "workflow_dispatch","subprocess","create-github-app-token"):
            self.assertNotIn(forbidden,source)
        workflow=(ROOT/".github/workflows/validate.yml").read_text()
        self.assertIn("tests/test-issue-75-durable-prewrite-seal.py",workflow)
        self.assertNotIn("issue-75-durable-prewrite-seal.py --mode",workflow)

if __name__=="__main__":
    main()
