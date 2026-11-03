#!/usr/bin/env python3
"""#524: owner formal-source command is distinct, live, protected and READ-ONLY."""
from __future__ import annotations
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from unittest import TestCase,main
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj
selector=load("owner_publish_source_request_test","scripts/publisher-owner-source-publish-request.py")
admission=selector.admission
fixtures=load("owner_source_existing_admission_fixtures","tests/test-publisher-owner-source-admission.py")
policies=load("owner_source_dual_policy_fixtures","tests/test-owner-source-publish-policy.py")
SHA=fixtures.SHA
REPO=fixtures.REPO
COMMAND="/pgextwin publish-owner-source "+REPO+" 41486380278"

def event():
    x=fixtures.event()
    x["comment"]["body"]=COMMAND
    return x

def local_content(obj):
    return {"type":"file","encoding":"base64",
            "content":base64.b64encode(json.dumps(obj).encode()).decode()}

def selected_inputs():
    a=policies.synthetic()
    a["owner_central"]["allowedRepositories"]=[REPO]
    a["owner_local"]["sourceKind"]=selector.admission.SOURCE_KIND
    # The registered 17-member synthetic fleet already includes plpgsql_check.
    # Keep the complete roster intact: central policy cannot shrink to a pilot.
    a["repository"]=REPO
    return a

class RequestTests(TestCase):
    def test_new_request_exactly_authenticated_not_old_admit_request(self):
        args=(event(),event()["comment"],fixtures.run(),fixtures.branch(),fixtures.env())
        self.assertEqual(admission.authenticate_request(
            *args,request_pattern=admission.PUBLISH_REQUEST),(REPO,41486380278))
        with self.assertRaises(admission.Denied):
            admission.authenticate_request(*args)
        wrong=fixtures.event()
        with self.assertRaises(admission.Denied):
            admission.authenticate_request(
                wrong,wrong["comment"],fixtures.run(),fixtures.branch(),
                fixtures.env(),request_pattern=admission.PUBLISH_REQUEST)

    def test_source_selection_requires_optin_before_expensive_signer_check(self):
        # Even a genuine event and original signed Run cannot bypass the
        # protected default DENY policy, so no real Sigstore is invoked.
        from unittest.mock import patch
        x=selected_inputs()
        x["owner_central"]["mode"]="DENY"
        x["owner_central"]["allowedRepositories"]=[]
        def get(repo,path):
            if path=="branches/main":
                return fixtures.branch()
            if path.startswith("contents/config/release-promotion.json"):
                return local_content(x["local"])
            if path.startswith("contents/config/owner-source-publication.json"):
                return local_content(x["owner_local"])
            raise AssertionError("unexpected GitHub resource "+path)
        with patch.object(admission,"get",side_effect=get),patch.object(
             admission,"admit") as expensive:
            with self.assertRaises(selector.policy.Denied):
                selector.select(event=event(),live=event()["comment"],
                    run=fixtures.run(),branch=fixtures.branch(),
                    env=fixtures.env(),fleet=x["fleet"],central=x["central"],
                    owner_central=x["owner_central"],unattended=x["unattended"],
                    boundary=x["boundary"],lifecycle={},scratch=Path("/tmp"))
            expensive.assert_not_called()

    def test_selection_only_returns_nonpublishing_source_witness(self):
        x=selected_inputs()
        evidence={
            "sourceKind":admission.SOURCE_KIND,"sourceEvent":"issue_comment",
            "sourceRunId":41486380278,"mainSha":SHA,
            "sourceCommentId":4444,"originalAndFreshDualSigstoreAgree":True,
            "SHA256":{"test.zip":"a"*64},"publicationAuthorized":False,
            "publishableReceipt":False,"PUBLISH":"DENY"}
        def get(repo,path):
            if path=="branches/main":
                return fixtures.branch()
            if path.startswith("contents/config/release-promotion.json"):
                return local_content(x["local"])
            if path.startswith("contents/config/owner-source-publication.json"):
                return local_content(x["owner_local"])
            raise AssertionError(path)
        with patch.object(admission,"get",side_effect=get),patch.object(
             admission,"admit",return_value=evidence) as verify:
            result=selector.select(event=event(),live=event()["comment"],
                run=fixtures.run(),branch=fixtures.branch(),env=fixtures.env(),
                fleet=x["fleet"],central=x["central"],
                owner_central=x["owner_central"],unattended=x["unattended"],
                boundary=x["boundary"],lifecycle={},scratch=Path("/tmp"))
        verify.assert_called_once()
        self.assertEqual(result["sourceRunId"],41486380278)
        self.assertEqual(result["sourceSigningCommentId"],4444)
        self.assertEqual(result["publisherRequestCommentId"],3333)
        for field in ("publicationAuthorized","publishableReceipt","publisherWriteAuthorized"):
            self.assertFalse(result[field])
        self.assertEqual(result["PUBLISH"],"DENY")

    def test_wrong_comment_actor_run_attempt_or_action_is_rejected(self):
        for edit in (
            lambda e,v:e["comment"].update(body=COMMAND+" extra"),
            lambda e,v:e["comment"].update(updated_at="2099-01-01T00:00:00Z"),
            lambda e,v:e.update(action="edited"),
            lambda e,v:e["sender"].update(login="attacker"),
        ):
            e=event();v=fixtures.env();edit(e,v)
            with self.assertRaises(admission.Denied):
                admission.authenticate_request(
                    e,e["comment"],fixtures.run(),fixtures.branch(),v,
                    request_pattern=admission.PUBLISH_REQUEST)

    def test_workflow_owner_readonly_proof_never_enters_environment(self):
        text=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        segment=text.split("  independent_owner_source_publish_request:",1)[1].split(
            "  independent_real_signed_source:",1)[0]
        self.assertIn("publisher-owner-source-publish-request.py",segment)
        self.assertIn("/pgextwin publish-owner-source ",segment)
        self.assertIn("github.event_name == 'issue_comment'",segment)
        for bad in ("environment: publisher","PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",
                    "secrets.","contents: write","gh release create"):
            self.assertNotIn(bad,segment)
        self.assertIn("PUBLISH_DENY",segment)

if __name__=="__main__":
    main()
