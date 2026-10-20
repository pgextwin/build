"""Meaningful adversarial metadata tests. Synthetic fixtures never certify GO."""
from copy import deepcopy
import base64
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publication_readonly", ROOT / "scripts/chat-publication-readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SHA, HEAD, BASE = "a" * 40, "b" * 40, "c" * 40
REPO, TAG = "pgextwin/pgtap", "v1.0.0-windows.1"
HUMAN = {"login": "ShutenOishi", "type": "User"}


class FakeReader:
    def __init__(self, data):
        self.data, self.calls = data, []

    def get(self, path):
        m.Reader.allowed(path)
        self.calls.append(path)
        return deepcopy(self.data[path])


def fixture(mode="push", request=False):
    env = {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_NAME": mode,
           "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
           "GITHUB_ACTOR": HUMAN["login"], "GITHUB_REF": "refs/heads/main"}
    event = {"repository": {"full_name": REPO}, "sender": dict(HUMAN),
             "ref": "refs/heads/main", "before": BASE, "after": SHA,
             "created": False, "deleted": False, "commits": [{"id": SHA}]}
    pr = {"number": 4, "merged": mode == "push", "state": "closed" if mode == "push" else "open",
          "merge_commit_sha": SHA, "changed_files": 1, "user": dict(HUMAN), "merged_by": dict(HUMAN),
          "base": {"ref": "main", "sha": BASE, "repo": {"full_name": REPO}},
          "head": {"sha": HEAD, "ref": "setup/read-only", "repo": {"full_name": REPO}}}
    files = [{"filename": ".github/workflows/windows.yml", "sha": "d" * 40, "status": "modified"}]
    branch = {"protected": True, "commit": {"sha": SHA if mode != "pull_request" else BASE},
              "protection": {"required_status_checks": {"checks": [
                  {"context": "Windows required summary", "app_id": 15368}]}}}
    data = {"branches/main": branch, "pulls/4": pr, "pulls/4/files?per_page=100": files,
            "actions/runs/123": {"id": 123, "run_attempt": 1, "event": mode,
                "path": ".github/workflows/windows.yml", "head_sha": HEAD if mode == "pull_request" else SHA,
                "head_branch": "main", "repository": {"full_name": REPO},
                "actor": dict(HUMAN), "triggering_actor": dict(HUMAN)},
            "commits/" + SHA: {"sha": SHA, "parents": [{"sha": BASE}], "files": files,
                "commit": {"verification": {"verified": True, "reason": "valid"}},
                "committer": {"login": "web-flow"}},
            "commits/" + SHA + "/pulls?per_page=100": [pr],
            "commits/" + HEAD + "/check-runs?per_page=100": {"total_count": 1, "check_runs": [
                {"name": "Windows required summary", "head_sha": HEAD, "status": "completed",
                 "conclusion": "success", "app": {"id": 15368}}]}}
    if mode == "pull_request":
        env["GITHUB_REF"] = "refs/pull/4/merge"
        event.update(number=4, pull_request={"head": {"sha": HEAD}})
    if request:
        req = {"schemaVersion": 1, "type": "pgextwin-chat-authorized-release", "repository": REPO,
               "releaseTag": TAG, "packagingMainSha": BASE, "candidatePr": 1,
               "candidateHeadSha": "e" * 40, "candidateRunId": 100, "decisionRunId": 99,
               "operatorLogin": HUMAN["login"], "confirmRelease": "PUBLISH"}
        set_request(data, req)
    return env, event, data


def set_request(data, request=None, raw=None):
    if raw is None:
        raw = json.dumps(request).encode()
    path = m.PREFIX + TAG + ".json"
    file = {"filename": path, "sha": m.auth.git_blob_sha(raw), "status": "added"}
    data["pulls/4/files?per_page=100"] = [file]
    data["commits/" + SHA]["files"] = [file]
    data["pulls/4"]["head"]["ref"] = "auth-release/" + TAG
    data["contents/" + path + "?ref=" + HEAD] = {"type": "file", "path": path,
        "encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode(), "sha": file["sha"]}


class ObserverTests(TestCase):
    def check(self, fx):
        env, event, data = fx
        return m.inspect(env, event, FakeReader(data))

    def assert_denied(self, fx, mutate):
        env, event, data = deepcopy(fx)
        mutate(env, event, data)
        with self.assertRaises((m.Denied, m.auth.Denied, ValueError, KeyError, TypeError)):
            self.check((env, event, data))

    def test_setup_pr_and_push_are_harmless_and_never_receipts(self):
        for mode in ("pull_request", "push"):
            with self.subTest(mode=mode):
                out = self.check(fixture(mode))
                self.assertEqual(out["status"], "NO_AUTHORIZATION")
                self.assertEqual(out["publication"], "DENY")
                for key in ("publishableReceipt", "publicationAuthorized", "catalogProposalAuthorized",
                            "mutationsEnabled", "independentWriterVerified", "effectiveClassicProtectionVerified"):
                    self.assertIs(out[key], False)
                if mode == "push":
                    self.assertTrue(out["commitSignatureVerified"])
                    self.assertEqual(out["requiredHeadChecksObserved"], ["Windows required summary"])

    def test_request_format_alone_cannot_enable_publication(self):
        for mode in ("pull_request", "push"):
            out = self.check(fixture(mode, request=True))
            self.assertEqual(out["status"], "VALID_REQUEST_FORMAT_PUBLICATION_DENIED")
            self.assertFalse(out["publishableReceipt"])
            self.assertEqual((out["goB"], out["g4"], out["g5"]), ("NO_GO",) * 3)

    def test_dispatch_cannot_become_publish(self):
        out = self.check(fixture("workflow_dispatch"))
        self.assertEqual(out["status"], "WINDOWS_DISPATCH_IS_NOT_PUBLICATION_AUTHORIZATION")
        self.assertFalse(out["mutationsEnabled"])

    def test_runtime_identity_replay_and_push_denials(self):
        cases = [lambda e,v,d:e.update(GITHUB_RUN_ATTEMPT="2"),
                 lambda e,v,d:e.update(GITHUB_REPOSITORY="pgextwin/evil"),
                 lambda e,v,d:e.update(GITHUB_REF="refs/heads/other"),
                 lambda e,v,d:e.update(GITHUB_EVENT_NAME="issue_comment"),
                 lambda e,v,d:v.update(before=HEAD),
                 lambda e,v,d:v.update(after=HEAD),
                 lambda e,v,d:v.update(created=True),
                 lambda e,v,d:v.update(deleted=True),
                 lambda e,v,d:v["commits"].append({"id": SHA}),
                 lambda e,v,d:d["actions/runs/123"].update(head_sha=HEAD),
                 lambda e,v,d:d["actions/runs/123"].update(run_attempt=True),
                 lambda e,v,d:d["actions/runs/123"].update(path=".github/workflows/promote.yml"),
                 lambda e,v,d:d["actions/runs/123"]["repository"].update(full_name="pgextwin/evil"),
                 lambda e,v,d:d["actions/runs/123"]["triggering_actor"].update(login="other"),
                 lambda e,v,d:d["branches/main"].update(protected=False),
                 lambda e,v,d:d["branches/main"]["commit"].update(sha=HEAD),
                 lambda e,v,d:d["commits/"+SHA]["parents"].append({"sha":HEAD}),
                 lambda e,v,d:d["commits/"+SHA]["commit"]["verification"].update(verified=False),
                 lambda e,v,d:d["commits/"+SHA]["committer"].update(login="other"),
                 lambda e,v,d:d["commits/"+SHA+"/pulls?per_page=100"].clear(),
                 lambda e,v,d:d["commits/"+SHA+"/pulls?per_page=100"].append(deepcopy(d["pulls/4"])),
                 lambda e,v,d:d["pulls/4"].update(merged=False),
                 lambda e,v,d:d["pulls/4"]["merged_by"].update(type="Bot"),
                 lambda e,v,d:d["pulls/4"].update(changed_files=2)]
        for index, mutate in enumerate(cases):
            with self.subTest(case=index):
                self.assert_denied(fixture(), mutate)

    def test_ci_unknown_duplicate_skipped_old_sha_and_wrong_app_denied(self):
        for field, value in (("conclusion", "skipped"), ("conclusion", "failure"),
                             ("status", "in_progress"), ("head_sha", SHA), ("app", {"id": 1})):
            self.assert_denied(fixture(), lambda e,v,d,f=field,x=value:
                               d["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"][0].update({f:x}))
        for mutate in (
            lambda e,v,d:d["commits/"+HEAD+"/check-runs?per_page=100"].update(total_count=2),
            lambda e,v,d:d["commits/"+HEAD+"/check-runs?per_page=100"]["check_runs"].clear(),
            lambda e,v,d:d["branches/main"]["protection"]["required_status_checks"]["checks"][0].update(app_id=-1),
            lambda e,v,d:d["branches/main"]["protection"]["required_status_checks"].update(checks=[])):
            self.assert_denied(fixture(), mutate)

    def test_authorization_unknown_duplicate_json_update_old_sha_and_bot_denied(self):
        fx = fixture(request=True)
        key = "contents/" + m.PREFIX + TAG + ".json?ref=" + HEAD
        raw = base64.b64decode(fx[2][key]["content"])
        request = json.loads(raw)
        for field, value in (("extra", True), ("confirmRelease", "UPDATE"), ("packagingMainSha", SHA),
                             ("candidateRunId", True), ("decisionRunId", 0), ("candidateHeadSha", "old"),
                             ("operatorLogin", "github-actions[bot]")):
            env, event, data = deepcopy(fx)
            changed = dict(request)
            changed[field] = value
            set_request(data, changed)
            with self.subTest(field=field), self.assertRaises((m.Denied, m.auth.Denied)):
                self.check((env, event, data))
        for payload in (raw.replace(b'"schemaVersion": 1', b'"schemaVersion":1,"schemaVersion":1'), b"{}", b"[1]"):
            env, event, data = deepcopy(fx)
            set_request(data, raw=payload)
            with self.assertRaises((m.Denied, m.auth.Denied)):
                self.check((env, event, data))
        for mutate in (
            lambda e,v,d:d["pulls/4"]["user"].update(type="Bot"),
            lambda e,v,d:d["pulls/4"]["head"]["repo"].update(full_name="pgextwin/evil"),
            lambda e,v,d:d["pulls/4/files?per_page=100"][0].update(status="modified"),
            lambda e,v,d:d[key].update(sha="f"*40),
            lambda e,v,d:d[key].update(size=20000),
            lambda e,v,d:d[key].update(content="%%%")):
            self.assert_denied(fx, mutate)

    def test_renamed_authorization_cannot_hide_as_no_authorization(self):
        fx = fixture()
        fx[2]["pulls/4/files?per_page=100"][0]["previous_filename"] = m.PREFIX + TAG + ".json"
        with self.assertRaises(m.Denied):
            self.check(fx)

    def test_two_reads_must_be_stable(self):
        env, event, data = fixture()
        class Racing(FakeReader):
            def get(self, path):
                r = super().get(path)
                if path == "branches/main" and self.calls.count(path) == 2:
                    r["commit"]["sha"] = HEAD
                return r
        with self.assertRaises(m.Denied):
            m.inspect(env, event, Racing(data))

    def test_reader_is_closed_get_only_no_redirect_or_pagination(self):
        for path in ("../outside", "https://evil.test/", "releases", "git/refs", "secrets",
                     "branches/main?token=x", "actions/runs/1/rerun", "contents/config/extension.json?ref=main"):
            with self.subTest(path=path), self.assertRaises(m.Denied):
                m.Reader.allowed(path)
        seen = []
        class Response:
            status = 200
            headers = {}
            body = b"{}"
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def read(self,n): return self.body[:n]
        def opener(request, **kwargs):
            seen.append(request)
            return Response()
        self.assertEqual(m.Reader(REPO,"test-only-token",opener).get("branches/main"), {})
        self.assertEqual(seen[0].method, "GET")
        for body, headers in ((b'{"a":1,"a":2}',{}),(b'{}',{"Link":'<next>; rel="next"'}),
                              (b'x'*(m.MAX_JSON+1),{})):
            Response.body, Response.headers = body, headers
            with self.assertRaises(m.Denied):
                m.Reader(REPO,"test-only-token",opener).get("branches/main")
        def denied(request, **kwargs):
            raise HTTPError(request.full_url,403,"sensitive-test-token",{},io.BytesIO(b"private"))
        with self.assertRaises(m.Denied) as error:
            m.Reader(REPO,"test-only-token",denied).get("branches/main")
        self.assertNotIn("sensitive", str(error.exception))
        with self.assertRaises(m.Denied):
            m.NoRedirect().redirect_request(None,None,302,"",{},"https://evil.test")

    def test_shared_workflow_has_no_writer_signer_secret_or_caller_execution(self):
        text = (ROOT / ".github/workflows/chat-publication-readonly.yml").read_text()
        for forbidden in ("write", "secrets.", "secrets: inherit", "workflow_dispatch:",
                          "pull_request_target", "actions/create-github-app-token", "promote.yml", "artifact@"):
            self.assertNotIn(forbidden, text)
        for required in ("permissions: {}", "persist-credentials: false", "${{ job.workflow_sha }}",
                         "${{ job.workflow_repository }}", "python -I", "checks: read", "pull-requests: read"):
            self.assertIn(required, text)


if __name__ == "__main__":
    main()
