#!/usr/bin/env python3
"""Adversarial local checks for distinct genuine owner main-signing source."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "chat_signed_main_auth", ROOT / "scripts/chat-signed-main-auth.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
REPO = "pgextwin/plpgsql_check"
SHA = "a" * 40
USER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}


def env():
    return {
        "GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "8888",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "issue_comment",
        "GITHUB_ACTOR": "ShutenOishi", "GITHUB_ACTOR_ID": "27071164",
        "GITHUB_TRIGGERING_ACTOR": "ShutenOishi",
    }


def event():
    return {
        "action": "created", "repository": {"full_name": REPO},
        "sender": dict(USER), "issue": {"number": 78},
        "comment": {
            "id": 123456, "issue_url": "https://api.github.com/repos/" + REPO + "/issues/78",
            "body": "/pgextwin sign-main", "user": dict(USER),
            "created_at": "2026-11-03T00:00:00Z",
            "updated_at": "2026-11-03T00:00:00Z",
        },
    }


def live():
    return dict(event()["comment"])


def branch():
    return {"name": "main", "protected": True, "commit": {"sha": SHA}}


def run():
    return {"id": 8888, "run_attempt": 1, "event": "issue_comment",
            "path": ".github/workflows/chat-signed-main.yml",
            "head_branch": "main", "head_sha": SHA,
            "repository": {"full_name": REPO}}


def fleet():
    return {"schemaVersion": 1, "entries": [
        {"repository": REPO}, {"repository": "pgextwin/orafce"}]}


def check(**overrides):
    x = {"event": event(), "live": live(), "branch": branch(),
         "run": run(), "fleet": fleet(), "env": env(), "issue_number": 78}
    x.update(overrides)
    return auth.check(**x)


class MainSigningSourceTests(TestCase):
    def test_genuine_and_nonpublishing(self):
        r = check()
        self.assertEqual(r["sourceKind"], "OWNER_ISSUE_COMMENT_MAIN_SIGNING")
        self.assertEqual(r["sourceEvent"], "issue_comment")
        self.assertFalse(r["publisherEligible"])
        self.assertFalse(r["publicationAuthorized"])
        self.assertEqual(r["PUBLISH"], "DENY")

    def test_sql_passengers_resolve_identity_from_original_context(self):
        registered = json.loads((ROOT / "metadata/automation-fleet.json").read_text())
        for repo in ("pgextwin/pg_permissions", "pgextwin/pg_track_settings", "pgextwin/pg_show_plans", "pgextwin/pg_profile", "pgextwin/pldebugger", "pgextwin/pg_wait_sampling", "pgextwin/pg_failover_slots", "pgextwin/pg_squeeze", "pgextwin/odbc_fdw"):
            with self.subTest(repository=repo):
                e, runtime, r = event(), env(), run()
                runtime["GITHUB_REPOSITORY"] = repo
                e["repository"]["full_name"] = repo
                e["issue"]["number"] = 1
                e["comment"]["issue_url"] = f"https://api.github.com/repos/{repo}/issues/1"
                r["repository"]["full_name"] = repo
                result = check(event=e, live=dict(e["comment"]), run=r,
                               env=runtime, fleet=registered, issue_number=1)
                self.assertEqual(result["repository"], repo)
                self.assertEqual(result["PUBLISH"], "DENY")
                # The same shared verifier rejects a foreign event identity.
                e["repository"]["full_name"] = "pgextwin/other"
                with self.assertRaises(auth.Denied):
                    check(event=e, live=dict(e["comment"]), run=r,
                          env=runtime, fleet=registered, issue_number=1)

    def test_replay_foreign_actor_ref_and_source_kind(self):
        for key, replacement in (
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REF", "refs/heads/fake"), ("GITHUB_SHA", "b" * 40),
            ("GITHUB_ACTOR", "attacker"), ("GITHUB_TRIGGERING_ACTOR", "attacker"),
            ("GITHUB_ACTOR_ID", "1"), ("GITHUB_REPOSITORY", "pgextwin/other"),
        ):
            with self.subTest(key=key):
                bad = env()
                bad[key] = replacement
                with self.assertRaises(auth.Denied):
                    check(env=bad)

    def test_edited_comment_wrong_issue_and_forged_sender(self):
        for key, value in (
            ("action", "edited"), ("sender", {"login": "ShutenOishi", "id": 1}),
            ("issue", {"number": 78, "pull_request": {}}),
            ("issue", {"number": 311}),
            ("comment", {**event()["comment"], "body": "/pgextwin publish pgextwin/plpgsql_check"}),
            ("comment", {**event()["comment"], "updated_at": "2026-11-03T00:01:00Z"}),
        ):
            with self.subTest(key=key):
                v = event()
                v[key] = value
                with self.assertRaises(auth.Denied):
                    check(event=v)
        for k, v in (
            ("body", "/pgextwin scan"), ("id", 123457),
            ("updated_at", "2026-11-03T00:01:00Z"),
        ):
            x = live()
            x[k] = v
            with self.assertRaises(auth.Denied):
                check(live=x)

    def test_drift_nonprotected_incorrect_run_and_unregistered(self):
        for bad in ({"name": "main", "protected": False, "commit": {"sha": SHA}},
                    {"name": "main", "protected": True, "commit": {"sha": "b" * 40}}):
            with self.assertRaises(auth.Denied):
                check(branch=bad)
        for key, value in (("event", "push"), ("run_attempt", 2),
                           ("path", ".github/workflows/update-watch.yml"),
                           ("head_sha", "b" * 40)):
            r = run()
            r[key] = value
            with self.assertRaises(auth.Denied):
                check(run=r)
        with self.assertRaises(auth.Denied):
            check(fleet={"schemaVersion": 1, "entries": [{"repository": "pgextwin/orafce"}]})
        with self.assertRaises(auth.Denied):
            check(fleet={"schemaVersion": 1, "entries": [{"repository": REPO}, {"repository": REPO}]})

    def test_reusable_workflow_has_no_publish_credentials(self):
        workflow = (ROOT / ".github/workflows/chat-signed-main-source.yml").read_text("utf-8")
        self.assertIn("workflow_call:", workflow)
        self.assertIn("scripts/chat-signed-main-auth.py", workflow)
        self.assertIn("build-extension-attested.yml@", workflow)
        self.assertIn("chat-signed-main-audit.py", workflow)
        self.assertIn("chat-owner-sigstore-nonpublishing", workflow)
        self.assertNotIn("matrix.auditor", workflow)
        self.assertNotIn("dual_audit_join", workflow)
        for forbidden in ("schedule:", "workflow_dispatch:", "contents: write",
                          "pull-requests: write", "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",
                          "gh release create", "environment: publisher"):
            self.assertNotIn(forbidden, workflow)


class FinalizerAdmissionTests(TestCase):
    """The finalizer independently repeats fresh GET checks before ZIP metadata."""

    def verifier(self):
        spec = importlib.util.spec_from_file_location(
            "finalizer_owner_source", ROOT / "scripts/finalize-owner-source.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def api(self, override=None):
        original = {
            "issues/comments/123456": live(),
            "branches/main": branch(),
            "actions/runs/8888": run(),
        }
        if override:
            original.update(override)
        def get(repository, resource):
            return original[resource]
        return get

    def test_original_owner_source_accepts_only_nonpublishing(self):
        proof = self.verifier().authenticate(event(), fleet(), env(), self.api())
        self.assertEqual(proof["sourceKind"], "OWNER_ISSUE_COMMENT_MAIN_SIGNING")
        self.assertEqual(proof["sourceEvent"], "issue_comment")
        self.assertEqual(proof["PUBLISH"], "DENY")
        self.assertFalse(proof["publicationAuthorized"])

    def test_hostile_source_and_missing_live_get_fail_closed(self):
        v = self.verifier()
        for key, bad_value in (
            ("GITHUB_ACTOR", "attacker"), ("GITHUB_ACTOR_ID", "1"),
            ("GITHUB_TRIGGERING_ACTOR", "attacker"),
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", "refs/heads/evil"),
            ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REPOSITORY", "pgextwin/evil"),
            ("GITHUB_SHA", "b" * 40),
        ):
            with self.subTest(runtime=key):
                altered = env()
                altered[key] = bad_value
                with self.assertRaises((v.auth.Denied, KeyError)):
                    v.authenticate(event(), fleet(), altered, self.api())
        for field, value in (
            ("action", "edited"),
            ("issue", {"number": 78, "pull_request": {}}),
            ("comment", {**event()["comment"], "body": "/pgextwin publish-owner-source"}),
            ("sender", {"login": "ShutenOishi", "id": 1}),
        ):
            altered = event()
            altered[field] = value
            with self.subTest(event=field):
                with self.assertRaises(v.auth.Denied):
                    v.authenticate(altered, fleet(), env(), self.api())
        cases = [
            {"issues/comments/123456": {**live(), "updated_at": "2026-11-03T00:05:00Z"}},
            {"issues/comments/123456": {**live(), "id": 7}},
            {"branches/main": {**branch(), "protected": False}},
            {"actions/runs/8888": {**run(), "event": "push"}},
            {"actions/runs/8888": {**run(), "run_attempt": 2}},
        ]
        for i, case in enumerate(cases):
            with self.subTest(live_case=i):
                with self.assertRaises(v.auth.Denied):
                    v.authenticate(event(), fleet(), env(), self.api(case))
        def missing_get(_repo, _resource):
            raise OSError("GitHub GET unavailable")
        with self.assertRaises(OSError):
            v.authenticate(event(), fleet(), env(), missing_get)

    def test_source_verifier_is_wired_to_actual_finalizer_only(self):
        finalizer = (ROOT / "scripts/finalize-package.ps1").read_text("utf-8")
        builder = (ROOT / ".github/workflows/build-extension-attested.yml").read_text("utf-8")
        source = (ROOT / ".github/workflows/chat-signed-main-source.yml").read_text("utf-8")
        guard = (ROOT / "scripts/finalize-owner-source.py").read_text("utf-8")
        self.assertIn('$WorkflowEvent -eq "issue_comment"', finalizer)
        self.assertIn('scripts/finalize-owner-source.py', finalizer)
        self.assertIn('if ($LASTEXITCODE -ne 0)', finalizer)
        self.assertIn('"workflow_dispatch", "push"', finalizer)
        self.assertIn('GH_TOKEN: ${{ github.token }}', builder)
        self.assertIn('issues: read', builder)
        self.assertIn('actions: read', builder)
        self.assertIn('issues: read', source)
        self.assertIn('actions: read', source)
        self.assertIn('auth.check(event, live, branch, run, fleet, env, issue_number)', guard)
        self.assertIn('method="GET"', guard)
        self.assertNotIn('gh release create', guard)
        self.assertNotIn('contents: write', source)
        self.assertNotIn('schedule:', source)


class OwnerSignerPinTests(TestCase):
    """Keep the genuine owner's exact reviewed builder separate from old manual pins."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "owner_signer_audit_pin", ROOT / "scripts/chat-signed-main-audit.py")
        self.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.audit)
        self.workflow = (ROOT / self.audit.SOURCE_WORKFLOW).read_text("utf-8")
        self.signer_sha = self.audit.signer_sha_from_workflow(self.workflow)

    def test_approved_owner_builder_stays_separate_from_legacy_pin(self):
        self.assertNotEqual(self.signer_sha, self.audit.pin.SIGNER_SHA)
        self.assertEqual(self.audit.pin.SIGNER_SHA,
                         "5756b3c5136a8bf4db710016cfe97555f0a71c6d")

    def test_only_reads_exact_builder_uses_in_signed_windows_job(self):
        builder = f"pgextwin/build/{self.audit.pin.offline.SIGNER_PATH}@{SHA}"
        workflow = (
            "jobs:\n  decoy:\n"
            f"    uses: {builder.replace(SHA, 'b' * 40)}\n"
            "  signed_windows:\n"
            f"    uses: {builder}\n"
        )
        self.assertEqual(self.audit.signer_sha_from_workflow(workflow), SHA)
        for invalid in (
                workflow.replace("signed_windows:", "other:"),
                workflow.replace(builder, builder.replace(SHA, "main")),
                workflow.replace(builder, builder.replace("pgextwin/build", "fork/build")),
                workflow + f"    uses: {builder}\n",
                workflow + f"  signed_windows:\n    uses: {builder}\n"):
            with self.subTest(workflow=invalid), self.assertRaises(self.audit.Denied):
                self.audit.signer_sha_from_workflow(invalid)

    def test_signer_is_read_from_the_trusted_commit(self):
        with TemporaryDirectory() as tmp, patch.object(self.audit, "ROOT", Path(tmp) / "scripts"):
            def git(*args):
                return subprocess.check_output(["git", "-C", tmp, *args], text=True).strip()

            workflow = Path(tmp) / self.audit.SOURCE_WORKFLOW
            workflow.parent.mkdir(parents=True)
            workflow.write_text(self.workflow, "utf-8")
            git("init", "--quiet")
            git("add", self.audit.SOURCE_WORKFLOW)
            git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Test pin")
            commit = git("rev-parse", "HEAD")
            workflow.write_text(self.workflow.replace(self.signer_sha, SHA), "utf-8")
            self.assertEqual(self.audit.signer_sha_at(commit), self.signer_sha)
            for invalid in ("main", "0" * 40):
                with self.subTest(commit=invalid), self.assertRaises(self.audit.Denied):
                    self.audit.signer_sha_at(invalid)

    def test_pg19_opt_in_follows_protected_policy_for_a_fixed_signer(self):
        policy = json.loads((ROOT / self.audit.ident.ADMISSION_PATH).read_text("utf-8"))
        extension = next(name for name in self.audit.ident.UPSTREAMS
                         if name not in policy["pg19OptIn"])
        central_sha = SHA

        def get(route):
            if route == "branches/main":
                return dict(branch(), commit={"sha": central_sha})
            self.assertEqual(route, f"contents/{self.audit.ident.ADMISSION_PATH}?ref={central_sha}")
            return {"type": "file", "encoding": "base64",
                    "content": base64.b64encode(json.dumps(policy).encode()).decode()}

        manifest = {"name": extension, "postgresql": {"majors": [19]}}
        with self.assertRaises(self.audit.ident.Denied):
            self.audit.ident.configured_majors(manifest, admission=self.audit.protected_admission(get))
        policy["pg19OptIn"].append(extension)
        central_sha = "c" * 40
        self.assertEqual(
            self.audit.ident.configured_majors(manifest, admission=self.audit.protected_admission(get)),
            [19])
        self.assertEqual(self.audit.signer_sha_from_workflow(self.workflow), self.signer_sha)
        with self.assertRaisesRegex(self.audit.Denied, "not from protected main"):
            self.audit.protected_admission(lambda route: dict(branch(), protected=False))

    def test_sigstore_requires_exact_new_owner_signer_digest(self):
        fake = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='[{"verificationResult":{"signed":"test"}}]', stderr="")
        with patch.object(self.audit.subprocess, "run", return_value=fake) as fake_run:
            result = self.audit.verify(ROOT / "fake-owner.zip",
                                       self.audit.pin.SLSA, REPO, SHA, self.signer_sha)
            args = fake_run.call_args.args[0]
        self.assertEqual(result["verificationResult"]["signed"], "test")
        self.assertEqual(args[args.index("--signer-digest") + 1],
                         self.signer_sha)
        self.assertNotEqual(args[args.index("--signer-digest") + 1],
                            self.audit.pin.SIGNER_SHA)


if __name__ == "__main__":
    main()
