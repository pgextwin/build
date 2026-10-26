#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from unittest.mock import patch
from publication_policy_fixtures import manual_policy
spec = importlib.util.spec_from_file_location("probe", Path(__file__).resolve().parents[1] / "scripts/probe-publisher-app.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class ProofTests(unittest.TestCase):
    def exercise(self, bad=None, event="workflow_dispatch", extra_member=False,
                 release_policy="manual-only", explicit=False):
        fleet = {"schemaVersion": 1, "releasePolicy": "manual-only", "entries": [
            {"repository": "pgextwin/future_extension", "mode": "BUILD",
             "candidateEnabled": True, "releasePolicy": "manual-only"}]}
        if extra_member:
            fleet["entries"].append({
                "repository": "pgextwin/second_extension", "mode": "BUILD",
                "candidateEnabled": True, "releasePolicy": "manual-only"})
        if explicit:
            fleet = manual_policy("automation-fleet.json")
        fleet["releasePolicy"]=release_policy
        for row in fleet["entries"]:
            row["releasePolicy"]=release_policy
        calls = []
        revoked = False
        selected_repository = "pgextwin/future_extension"
        def api(method, path, token, body=None):
            nonlocal revoked, selected_repository
            calls.append((method, path))
            if path == "/app":
                return {"id": 5451798 if bad != "identity" else 15368, "slug": "pgextwin-publisher"}
            if path == "/app/installations/174720074":
                return {"id":174720074,"app_id":5451798,"account":{"login":"pgextwin"},
                    "repository_selection":"all","permissions":{"contents":"write","metadata":"read"}}
            if path.endswith("/access_tokens"):
                from datetime import datetime, timezone, timedelta
                revoked = False
                selected_repository = "pgextwin/" + body["repositories"][0]
                return {"token":"synthetic-private-token-never-print","repository_selection":"selected",
                    "permissions":{"contents":"write","metadata":"read"},
                    "expires_at":(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat().replace("+00:00", "Z")}
            if path.startswith("/installation/repositories"):
                if revoked:
                    raise HTTPError("https://api.github.com", 403 if bad=="revocation-403"
                                    else 401, "revoked", {}, None)
                return {"total_count": 2 if bad == "scope" else 1,
                        "repositories":[{"full_name":selected_repository}]}
            if path.endswith("/git/blobs"):
                if bad == "write":
                    raise ValueError("synthetic-private-token-never-print")
                import base64, hashlib
                data=base64.b64decode(body["content"])
                return {"sha":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()}
            if path == "/installation/token":
                revoked = True
                return {}
            raise AssertionError(path)
        env={"GITHUB_REPOSITORY":"pgextwin/build","GITHUB_REF":"refs/heads/main",
            "GITHUB_EVENT_NAME":event,"PUBLISHER_APP_ID":"5451798",
            "PUBLISHER_INSTALLATION_ID":"174720074","PUBLISHER_PRIVATE_KEY":"synthetic-key"}
        with tempfile.TemporaryDirectory() as tmp:
            previous=os.getcwd()
            try:
                os.chdir(tmp)
                Path("metadata").mkdir()
                Path("metadata/automation-fleet.json").write_text(json.dumps(fleet))
                pilot_policy = {
                    "schemaVersion":1,"mode":"OBSERVE","defaultAction":"DENY",
                    "pilotRepository":"pgextwin/unknown_pilot" if bad=="pilot"
                                      else "pgextwin/future_extension"}
                if explicit:
                    pilot_policy = p.unattended.with_explicit_merge_identities(
                        manual_policy("unattended-publication.json"))
                    if release_policy == "automatic-signed-schedule":
                        pilot_policy["mode"] = "UNATTENDED"
                        pilot_policy["controls"] = {name: True for name in pilot_policy["controls"]}
                    if bad == "schema": pilot_policy["schemaVersion"] = 3
                    if bad == "mode": pilot_policy["mode"] = "UNKNOWN"
                    if bad == "actor": pilot_policy["candidateMergeIdentity"]["actors"] = ["other-operator"]
                    if bad == "identity-control": pilot_policy["controls"]["requireTrustedCandidateMergeIdentity"] = False
                Path("metadata/unattended-publication.json").write_text(json.dumps(pilot_policy))
                output=io.StringIO()
                with patch.dict(os.environ,env), patch.object(p,"jwt",return_value="synthetic-jwt"), patch.object(p,"api",side_effect=api), contextlib.redirect_stdout(output):
                    if bad or event not in ("workflow_dispatch", "schedule", "push"):
                        with self.assertRaises(ValueError): p.run()
                    else: p.run()
                if not bad and event in ("workflow_dispatch","schedule","push"):
                    report=json.loads(Path("publisher-app-proof.json").read_text())
                    self.assertIs(report["publicationAuthorized"],False)
                    self.assertTrue(all(row["tokenRevoked"] for row in report["repositories"]))
                self.assertNotIn("synthetic-private-token", output.getvalue())
                self.assertNotIn("synthetic-key", output.getvalue())
            finally: os.chdir(previous)
        return calls

    def test_live_shape_fixture_and_future_membership(self):
        calls=self.exercise()
        self.assertIn(("POST","/repos/pgextwin/future_extension/git/blobs"), calls)
        self.assertIn(("DELETE","/installation/token"), calls)
        self.assertFalse(any("/releases" in path or "/refs" in path for _,path in calls))

    def test_automatic_fleet_policy_preserves_nonpublishing_proof(self):
        for event in ("push","schedule","workflow_dispatch"):
            with self.subTest(event=event):
                calls=self.exercise(event=event,extra_member=event!="workflow_dispatch",
                                    release_policy="automatic-signed-schedule")
                self.assertEqual(sum(method=="POST" and path.endswith("/access_tokens")
                                     for method,path in calls),1)
                self.assertFalse(any("/releases" in path or "/refs" in path for _,path in calls))
                self.assertEqual(calls[-2:],[("DELETE","/installation/token"),
                    ("GET","/installation/repositories?per_page=100")])

    def test_shared_fleet_contract_rejects_mixed_and_unknown_policies(self):
        for policy in ("automatic-signed-schedule","manual-only","automatic",None):
            fleet={"schemaVersion":1,"releasePolicy":policy,"entries":[
                {"repository":"pgextwin/future_extension","mode":"BUILD",
                 "candidateEnabled":True,"releasePolicy":"unapproved"}]}
            with self.subTest(policy=policy),self.assertRaises(ValueError):
                p.repositories(fleet)
    def test_live_token_revocation_is_confirmed(self):
        calls=self.exercise()
        self.assertEqual(calls[-2:],[
            ("DELETE","/installation/token"),
            ("GET","/installation/repositories?per_page=100")])

    def test_unconfirmed_revocation_is_rejected(self):
        calls=self.exercise("revocation-403")
        self.assertIn(("DELETE","/installation/token"),calls)

    def test_protected_push_and_schedule_only_probe_existing_pilot(self):
        for event in ("push", "schedule"):
            with self.subTest(event=event):
                calls=self.exercise(event=event,extra_member=True)
                self.assertEqual([path for method,path in calls if
                    method=="POST" and path.endswith("/git/blobs")],
                    ["/repos/pgextwin/future_extension/git/blobs"])
                self.assertEqual(sum(1 for method,path in calls
                    if method=="POST" and path.endswith("/access_tokens")),1)
                self.assertEqual(calls[-2:],[
                    ("DELETE","/installation/token"),
                    ("GET","/installation/repositories?per_page=100")])

    def test_auto_proof_fails_closed_for_unregistered_pilot_or_bad_event(self):
        for event,bad in (("schedule","pilot"),("pull_request",None)):
            with self.subTest(event=event,bad=bad):
                calls=self.exercise(bad=bad, event=event)
                self.assertFalse(any(method=="POST" for method,path in calls))

    def test_explicit_policy_uses_shared_validation_before_scoped_proof(self):
        for event in ("push", "schedule"):
            for release_policy in ("manual-only", "automatic-signed-schedule"):
                with self.subTest(event=event, release_policy=release_policy):
                    calls = self.exercise(event=event, explicit=True, release_policy=release_policy)
                    self.assertEqual([path for method, path in calls
                                      if method == "POST" and path.endswith("/git/blobs")],
                                     ["/repos/pgextwin/plpgsql_check/git/blobs"])
                    self.assertEqual(calls[-2:], [("DELETE", "/installation/token"),
                        ("GET", "/installation/repositories?per_page=100")])

    def test_unknown_explicit_policy_is_denied_before_key_or_app_use(self):
        for bad in ("schema", "mode", "actor", "identity-control"):
            with self.subTest(bad=bad):
                calls = self.exercise(bad=bad, event="push", explicit=True,
                                      release_policy="automatic-signed-schedule")
                self.assertEqual(calls, [])

    def test_wrong_identity_never_mints(self):
        self.assertFalse(any(path.endswith("/access_tokens") for _,path in self.exercise("identity")))
    def test_expanded_scope_rejected_and_revoked(self):
        calls=self.exercise("scope")
        self.assertIn(("DELETE","/installation/token"),calls)
        self.assertFalse(any(path.endswith("/git/blobs") for _,path in calls))
    def test_write_failure_revokes(self):
        self.assertIn(("DELETE","/installation/token"),self.exercise("write"))
    def test_empty_and_duplicate_fleet_denied(self):
        for rows in ([],[{"repository":[]}]):
            with self.assertRaises(ValueError):
                p.repositories({"schemaVersion":1,"releasePolicy":"manual-only","entries":rows})

if __name__=="__main__": unittest.main()
