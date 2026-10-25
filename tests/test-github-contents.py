#!/usr/bin/env python3
"""Transport success never grants source, signature or publication authority."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("github_contents",ROOT/"scripts/github_contents.py")
contents=importlib.util.module_from_spec(spec);spec.loader.exec_module(contents)
PATH="config/extension.json"


def response(raw):
    return {"path":PATH,"encoding":"base64","size":len(raw),
            "sha":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
            "content":base64.encodebytes(raw).decode()}


class ContentsTests(unittest.TestCase):
    def test_github_wrapping_preserves_exact_original_bytes(self):
        value={"name":"pg_ivm","upstream":{"commit":"a"*40},"note":"日本語"}
        raw=(json.dumps(value,ensure_ascii=False,indent=2)+"\n").encode()
        source=response(raw)
        for encoded in (source["content"],source["content"].replace("\n","\r\n"),
                        base64.b64encode(raw).decode()):
            item={**source,"content":encoded}
            self.assertEqual(contents.decode_json_file(item,PATH),value)

    def test_wrong_path_encoding_digest_size_and_corruption_are_denied(self):
        good=response(b'{"name":"pg_ivm"}')
        for change in (
            lambda x:x.update(path="config/release-promotion.json"),
            lambda x:x.update(encoding="utf-8"),
            lambda x:x.update(sha="a"*40),
            lambda x:x.update(sha=True),
            lambda x:x.update(size=True),
            lambda x:x.update(size=x["size"]+1),
            lambda x:x.update(content=x["content"]+"!"),
            lambda x:x.update(content=" "+x["content"]),
            lambda x:x.update(content=base64.b64encode(b'{"name":"other"}').decode()),
        ):
            obj=deepcopy(good);change(obj)
            with self.subTest(change=change),self.assertRaises(ValueError):
                contents.decode_json_file(obj,PATH)

    def test_same_hash_does_not_allow_duplicate_keys_nonfinite_or_nonobject_json(self):
        for raw in (b'{"name":"pg_ivm","name":"other"}',b'{"x":NaN}',
                    b'{"x":Infinity}',b'[]',b'null',b'{',b'\xff',b''):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                contents.decode_json_file(response(raw),PATH)

    def test_oversized_source_is_rejected(self):
        raw=b'{"value":"'+b'x'*contents.MAX_FILE_BYTES+b'"}'
        with self.assertRaises(ValueError):
            contents.decode_json_file(response(raw),PATH)

    def test_both_workflow_readers_explicitly_request_checks_read_only(self):
        for path in ("automatic-postmerge-audit-readonly.yml","verify-native-pr-candidate.yml"):
            source=(ROOT/".github/workflows"/path).read_text()
            block=source.split("    permissions:\n",1)[1].split("    steps:\n",1)[0]
            permissions=dict(re.findall(r"^      ([a-z-]+): ([a-z]+)$",block,re.M))
            self.assertEqual(permissions,{"contents":"read","actions":"read",
                                          "pull-requests":"read","checks":"read"})


if __name__=="__main__":
    unittest.main()
