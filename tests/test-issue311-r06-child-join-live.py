#!/usr/bin/env python3
"""Offline hostile-boundary tests. No claim of genuine Run or live App CAS."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("r06_live", ROOT / "scripts/issue311-r06-child-join-live.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def declaration():
    return {"schemaVersion": 1, "kind": "pgextwin-r06-original-child-join",
        "requestId": "r-20261030-r06join17test01", "mode": "AUDIT_ONLY", "requestedBy": "ShutenOishi",
        "createdAt": "2026-10-29T22:00:00Z", "expiresAt": "2026-10-29T22:20:00Z",
        "central": {"requestId": "r-20261029-r06prepare17test07", "runId": 100, "headSha": "a"*40,
                    "artifactId": 101, "zipSha256": "b"*64},
        "children": [{"repo": r, "runId": i+200, "requestId": "r-20261030-r06local" + str(i) + "test07"}
                     for i, r in enumerate(sorted(mod.targets()))],
        "missingCompletionRepo": "pgextwin/orafce", "publicReleaseAuthorized": False,
        "stateWriteScope": "BUILD_ONLY_REQUEST_LIFECYCLE"}


class BoundaryTests(unittest.TestCase):
    def test_authentic_central_scan_flag_is_not_the_app_state_flag(self):
        self.assertTrue(mod.central_scope({"publicationAuthorized": False}))
        self.assertFalse(mod.central_scope({"publisherAuthorized": False}))
        self.assertFalse(mod.central_scope({"publicationAuthorized": True}))
        self.assertFalse(mod.central_scope({"publicationAuthorized": False, "publisherAuthorized": False}))

    def validate(self, request):
        path = ".github/execution-requests/" + request["requestId"] + ".json"
        return mod.validate_request(json.dumps(request).encode(), path,
            now=datetime(2026, 10, 29, 22, 1, tzinfo=timezone.utc))

    def test_exact_scope_is_inert_and_rejects_privileged_or_incomplete(self):
        good = declaration()
        self.assertEqual(self.validate(good), good)
        mutations = [lambda r: r.update(publicReleaseAuthorized=True),
                     lambda r: r.update(mode="PUBLISH_ELIGIBLE"),
                     lambda r: r.update(stateWriteScope="PUBLISHER"),
                     lambda r: r.update(command="dispatch"),
                     lambda r: r.update(missingCompletionRepo="pgextwin/pg_bigm"),
                     lambda r: r["children"].pop(),
                     lambda r: r["children"].__setitem__(0, copy.deepcopy(r["children"][1])),
                     lambda r: r["children"][0].update(runId=True),
                     lambda r: r["central"].update(runId=True),
                     lambda r: r["central"].update(zipSha256="f"*40),
                     lambda r: r.update(expiresAt="2026-10-29T23:00:00Z"),
                     lambda r: r.update(expiresAt="2026-10-29T22:00:30Z")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad = copy.deepcopy(good)
                mutate(bad)
                with self.assertRaises(ValueError):
                    self.validate(bad)

    def test_zip_rehash_entry_and_duplicate_json_fail_before_any_writer(self):
        def zipped(entries):
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                for name, raw in entries:
                    z.writestr(name, raw)
            return out.getvalue()
        raw = zipped([("original.json", '{"publicationAuthorized":false}')])
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(mod.single_zip(raw, digest, "original.json"), {"publicationAuthorized": False})
        for altered, claimed, name in [
            (raw, "f"*64, "original.json"),
            (raw, digest, "else.json"),
            (raw[:-1]+bytes([raw[-1]^1]), digest, "original.json"),
        ]:
            with self.assertRaises(ValueError):
                mod.single_zip(altered, claimed, name)
        for entries in [[("original.json", "{}"), ("extra.json", "{}")],
                        [("original.json", '{"scope":0,"scope":1}')]]:
            altered = zipped(entries)
            with self.assertRaises(ValueError):
                mod.single_zip(altered, hashlib.sha256(altered).hexdigest(), "original.json")

    def test_cross_cycle_expired_skipped_declaration_denied_before_cas(self):
        central = {"requestId": "r-20261029-r06prepare17test07", "sourceRunId": 100,
            "sourceHeadSha": "a"*40, "sourceArtifactId": 101, "sourceZipSha256": "b"*64,
            "created_at": "2026-10-29T21:00:00Z", "targetMainSha": {"pgextwin/pg_cron": "c"*40}}
        c = {"repo": "pgextwin/pg_cron", "parentSha": "c"*40,
             "run": {"created_at": "2026-10-29T21:10:00Z"},
             "request": {"schemaVersion": 1, "kind": "pgextwin-local-prepare", "mode": "PREPARE",
                 "requestId": "r-20261030-r06localcrontest07", "centralRequestId": central["requestId"],
                 "sourceRunId": 100, "sourceHeadSha": "a"*40, "sourceArtifactId": 101,
                 "sourceZipSha256": "b"*64, "targetMainSha": "c"*40,
                 "expiresAt": "2026-10-29T21:20:00Z", "publicReleaseAuthorized": False}}
        self.assertIs(mod.preflight_child(central, c), c)
        for field, value in [("sourceRunId", 999), ("centralRequestId", "cross-cycle"),
                             ("sourceZipSha256", "d"*64), ("publicReleaseAuthorized", True),
                             ("expiresAt", "2026-10-29T21:09:59Z")]:
            bad = copy.deepcopy(c)
            bad["request"][field] = value
            with self.assertRaises(ValueError):
                mod.preflight_child(central, bad)

    def test_actual_terminal_preserves_normal_and_quarantines_anomalies_without_replay(self):
        children = [{"repo": r, "receipt": {"result": "NO_UPDATE"}} for r in sorted(mod.targets())]
        initial = mod.life.new("r-20261030-r06join17test01", "d"*64, "a"*40,
            sorted(mod.targets()), "2026-10-29T21:20:00Z")
        bound = mod.life.bind_source(initial, 0, "source", run_id=500, attempt=1, head_sha="a"*40)
        with self.assertRaises(ValueError):
            mod.bounded_terminal(bound, children, 500, 501, "e"*64, now="2026-10-29T21:19:59Z")
        terminal = mod.bounded_terminal(bound, children, 500, 501, "e"*64, now="2026-10-29T21:21:00Z")
        self.assertEqual(terminal["eventTransport"], "BOUNDED_WATCHDOG")
        self.assertEqual(list(terminal["targets"].values()).count("NO_UPDATE"), 13)
        self.assertEqual(list(terminal["targets"].values()).count("QUARANTINED"), 4)
        mod.store.require_transition(bound, terminal)
        with self.assertRaises(ValueError):
            mod.life._apply(terminal, 2, "second-event", {"op": "replay"}, lambda s: s.update(terminal=None))
        changed = copy.deepcopy(children)
        normal = next(x for x in changed if x["repo"] not in mod.ANOMALIES)
        normal["receipt"]["result"] = "UPDATE_PRESENT_NOT_AUTHORIZED"
        quarantine = mod.bounded_terminal(bound, changed, 500, 501, "e"*64, now="2026-10-29T21:21:00Z")
        self.assertEqual(quarantine["targets"][normal["repo"]], "QUARANTINED")

    def test_cross_host_artifact_redirect_drops_authorization(self):
        original = urllib.request.Request("https://api.github.com/repos/pgextwin/build/actions/artifacts/1/zip",
                                          headers={"Authorization": "Bearer DO_NOT_FORWARD"})
        after = mod.SafeRedirect().redirect_request(original, None, 302, "Found", {},
                                                    "https://artifacts.example.com/original.zip")
        self.assertIsNone(after.get_header("Authorization"))
        with self.assertRaises(ValueError):
            mod.SafeRedirect().redirect_request(original, None, 302, "Found", {}, "http://example.com/unsafe")


if __name__ == "__main__":
    unittest.main()
