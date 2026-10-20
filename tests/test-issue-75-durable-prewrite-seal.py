#!/usr/bin/env python3
"""Issue75 actual local POSIX fsync/create-only behavior; NO live Publisher."""
from __future__ import annotations
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import stat
from concurrent.futures import ThreadPoolExecutor
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

    def test_fsync_failure_keeps_uncertain_tag_claim_quarantined(self):
        with TemporaryDirectory() as folder:
            r=record()
            with mock.patch.object(m.os,"fsync",side_effect=OSError("offline failure")):
                with self.assertRaises(m.Deny):m.seal(folder,r)
            tag=Path(folder)/m._tag_name(r["repository"],r["tag"])
            path=Path(folder)/(r["requestId"]+".json")
            self.assertTrue(tag.exists())  # Never delete uncertain bytes.
            self.assertFalse(path.exists())  # Tag reserved FIRST.
            with self.assertRaises(m.Deny):m.seal(folder,r)
            changed=record()
            changed["requestId"]="f"*64
            with self.assertRaises(m.Deny):m.seal(folder,changed)
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])

    def test_fsync_after_tag_claim_before_request_keeps_orphan_quarantined(self):
        with TemporaryDirectory() as folder:
            original=m.os.fsync
            count=0
            def second_write_failure(fd):
                nonlocal count
                count += 1
                if count == 3:  # durable tag file+directory, then request fsync
                    raise OSError("synthetic request durability failure")
                return original(fd)
            with mock.patch.object(m.os,"fsync",side_effect=second_write_failure):
                with self.assertRaises(m.Deny):m.seal(folder,record())
            r=record()
            self.assertTrue((Path(folder)/m._tag_name(r["repository"],r["tag"])).exists())
            self.assertTrue((Path(folder)/(r["requestId"]+".json")).exists())
            with self.assertRaises(m.Deny):m.seal(folder,r)
            self.assertFalse(m.inspect(folder,r["requestId"])["retryAuthorized"])

    def test_same_tag_different_request_id_is_denied_without_writing_second(self):
        with TemporaryDirectory() as folder:
            first=record()
            m.seal(folder,first)
            other=record()
            other["requestId"]="f"*64
            other["runId"]=999999
            with self.assertRaises(m.Deny):m.seal(folder,other)
            self.assertFalse((Path(folder)/(other["requestId"]+".json")).exists())
            self.assertEqual(len(list(Path(folder).iterdir())),2)
            self.assertEqual(
                m.inspect(folder,first["requestId"])["classification"],
                "LOCAL_READ_ONLY_SEAL_NO_REMOTE_VERIFICATION",
            )

    def test_same_tag_in_other_repository_is_independent(self):
        with TemporaryDirectory() as folder:
            a=record()
            b=record()
            b["repository"]="pgextwin/pg_variables"
            b["requestId"]="f"*64
            m.seal(folder,a)
            m.seal(folder,b)
            self.assertNotEqual(m._tag_name(a["repository"],a["tag"]),
                                m._tag_name(b["repository"],b["tag"]))
            self.assertNotEqual(m.inspect(folder,a["requestId"])["tagClaimSha256"],
                                m.inspect(folder,b["requestId"])["tagClaimSha256"])

    def test_tag_claim_removed_or_replaced_denies_readback(self):
        with TemporaryDirectory() as folder:
            r=record()
            m.seal(folder,r)
            tag=Path(folder)/m._tag_name(r["repository"],r["tag"])
            tag.write_text('{"requestId":"evil"}\\n')
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            tag.unlink()
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])
            tag.symlink_to(Path(folder)/(r["requestId"]+".json"))
            with self.assertRaises(m.Deny):m.inspect(folder,r["requestId"])

    def test_concurrent_claim_same_target_tag_exactly_one_wins(self):
        with TemporaryDirectory() as folder:
            first=record()
            second=record()
            second["requestId"]="f"*64
            def attempt(r):
                try:
                    return m.seal(folder,r)["classification"]
                except m.Deny:
                    return "DENIED"
            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes=list(executor.map(attempt,[first,second]))
            self.assertEqual(outcomes.count("LOCAL_CREATE_ONLY_SEAL_NOT_PUBLICATION_AUTHORITY"),1)
            self.assertEqual(outcomes.count("DENIED"),1)
            self.assertEqual(len(list(Path(folder).iterdir())),2)
            winner = first if (Path(folder)/(first["requestId"]+".json")).exists() else second
            self.assertFalse(m.inspect(folder,winner["requestId"])["retryAuthorized"])

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
