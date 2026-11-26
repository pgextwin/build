#!/usr/bin/env python3
"""Fail-closed independent Publisher-side owner-signed source admission tests."""
import base64
import copy
import importlib.util
import json
import shutil
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "publisher_owner_source_admission",
    ROOT / "scripts/publisher-owner-source-admission.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SHA = "a" * 40
REPO = "pgextwin/plpgsql_check"
USER = {"login": "ShutenOishi", "id": 27071164, "type": "User"}
COMMAND = "/pgextwin admit-owner-source " + REPO + " 41486380278"

def env():
    return {"GITHUB_REPOSITORY": "pgextwin/build",
            "GITHUB_EVENT_NAME": "issue_comment", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": "ShutenOishi",
            "GITHUB_TRIGGERING_ACTOR": "ShutenOishi", "GITHUB_ACTOR_ID": "27071164",
            "GITHUB_RUN_ID": "5555", "GITHUB_SHA": SHA}

def event():
    return {"action": "created", "sender": dict(USER),
            "repository": {"full_name": "pgextwin/build"},
            "issue": {"number": 311},
            "comment": {"id": 3333, "body": COMMAND, "user": dict(USER),
                        "issue_url": "https://api.github.com/repos/pgextwin/build/issues/311",
                        "created_at": "2026-11-03T00:00:00Z",
                        "updated_at": "2026-11-03T00:00:00Z"}}

def run():
    return {"id": 5555, "run_attempt": 1, "event": "issue_comment",
            "path": mod.CENTRAL_WORKFLOW, "head_branch": "main", "head_sha": SHA,
            "status": "in_progress", "repository": {"full_name": "pgextwin/build"},
            "actor": dict(USER), "triggering_actor": dict(USER)}

def branch():
    return {"name": "main", "protected": True, "commit": {"sha": SHA}}

def intent(repo=REPO, issue=78):
    return {"schemaVersion": 1, "sourceKind": mod.SOURCE_KIND,
            "sourceEvent": "issue_comment", "repository": repo, "mainSha": SHA,
            "runId": 41486380278, "runAttempt": 1, "issueNumber": issue,
            "commentId": 4444, "signingEligible": True,
            "publisherEligible": False, "publicationAuthorized": False,
            "PUBLISH": "DENY"}

def signed_run(repo=REPO):
    r = run()
    r.update(id=41486380278, status="completed", conclusion="success",
             path=mod.SOURCE_WORKFLOW,
             repository={"full_name": repo})
    return r

def original_jobs(majors=(14,15,16,17,18), *, legacy=False):
    audit_jobs = [
        "Independent original Sigstore/ZIP/SPDX/Grype audit (first)",
        "Independent original Sigstore/ZIP/SPDX/Grype audit (second)",
        "Require exact independent real-signature byte agreement (NO PUBLISH)",
    ] if legacy else [mod.audit.AUDIT_JOB]
    names = ["Original authenticated owner/main/comment source (DENY Publisher)",
             "Resolve extension and PostgreSQL matrix", *audit_jobs,
             *(f"PostgreSQL {m} / Windows x64" for m in majors)]
    return {"total_count": len(names), "jobs": [
        {"name": n, "id": 100+i, "run_id": 41486380278, "run_attempt": 1,
         "head_sha": SHA, "status": "completed", "conclusion": "success"}
        for i, n in enumerate(names)]}

def source_artifacts(*, legacy=False):
    names = ["chat-main-source-intent-nonpublishing"]
    if legacy:
        names.extend(("chat-owner-sigstore-first-nonpublishing",
                      "chat-owner-sigstore-second-nonpublishing",
                      "chat-owner-dual-sigstore-nonpublishing"))
    else:
        names.append(mod.audit.AUDIT_ARTIFACT)
    return {"total_count": len(names), "artifacts": [
        {"name": n, "id": i+1, "size_in_bytes": 40, "expired": False}
        for i, n in enumerate(names)]}

def live_signing(repo=REPO, issue=78):
    return {"id": 4444, "body": "/pgextwin sign-main",
            "issue_url": f"https://api.github.com/repos/{repo}/issues/{issue}",
            "created_at": "2026-11-03T00:00:00Z",
            "updated_at": "2026-11-03T00:00:00Z", "user": dict(USER)}

def source_check(**overrides):
    x = {"repo": REPO, "sha": SHA, "run_id": 41486380278,
         "run": signed_run(), "jobs": original_jobs(),
         "artifacts": source_artifacts(), "intent": intent(),
         "live": live_signing(), "majors": [14,15,16,17,18]}
    x.update(overrides)
    return mod.source_metadata(**x)

class AdmissionTests(TestCase):
    def test_genuine_original_owner_source_and_no_publication(self):
        self.assertEqual(mod.authenticate_request(
            event(), event()["comment"], run(), branch(), env()),
            (REPO, 41486380278))
        self.assertFalse(source_check())
        self.assertTrue(source_check(jobs=original_jobs(legacy=True),
                                     artifacts=source_artifacts(legacy=True)))
        self.assertEqual(mod.SOURCE_KIND, "OWNER_ISSUE_COMMENT_MAIN_SIGNING")

    def test_wrong_central_run_actor_replay_and_ref_denied(self):
        for field, value in (("GITHUB_RUN_ATTEMPT", "2"),
                             ("GITHUB_REF", "refs/heads/fake"),
                             ("GITHUB_EVENT_NAME", "push"),
                             ("GITHUB_ACTOR", "other"),
                             ("GITHUB_TRIGGERING_ACTOR", "other"),
                             ("GITHUB_SHA", "b"*40)):
            with self.subTest(field=field):
                e=env();e[field]=value
                with self.assertRaises(mod.Denied):
                    mod.authenticate_request(event(),event()["comment"],
                                             run(),branch(),e)
        for field,value in (("event","schedule"), ("path",mod.SOURCE_WORKFLOW),
                            ("run_attempt",2), ("status","completed")):
            r=run();r[field]=value
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(event(),event()["comment"],
                                         r,branch(),env())

    def test_wrong_owner_command_or_edited_comment_denied(self):
        for bad in ("/pgextwin publish "+REPO,
                    "/pgextwin admit-owner-source "+REPO+" 0",
                    COMMAND+"\\n", COMMAND+" extra", COMMAND.replace(REPO,"pgextwin/fake;rm")):
            e=event();e["comment"]["body"]=bad
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(e,e["comment"],run(),branch(),env())
        for field,value in (("updated_at","2026-11-03T01:00:00Z"),
                            ("user",{"login":"attacker","id":1}),
                            ("issue_url","https://evil.invalid")):
            e=event();e["comment"][field]=value
            with self.assertRaises(mod.Denied):
                mod.authenticate_request(e,e["comment"],run(),branch(),env())

    def test_source_run_wrong_kind_edited_or_replayed_denied(self):
        for key, value in (("event","push"), ("path",".github/workflows/update-watch.yml"),
                           ("run_attempt",2), ("status","in_progress"),
                           ("head_sha","b"*40),("conclusion","failure")):
            with self.subTest(key=key):
                r=signed_run();r[key]=value
                with self.assertRaises(mod.Denied):
                    source_check(run=r)
        for key,value in (("sourceKind","PUSH"),("publisherEligible",True),
                          ("publicationAuthorized",True),("PUBLISH","ALLOW"),
                          ("runAttempt",2),("mainSha","b"*40)):
            with self.subTest(key=key):
                i=intent();i[key]=value
                with self.assertRaises(mod.Denied):
                    source_check(intent=i)

    def test_failed_audit_or_missing_artifact_denied(self):
        jobs=original_jobs(legacy=True)
        artifacts=source_artifacts(legacy=True)
        for n in (2,3):
            altered=copy.deepcopy(jobs)
            altered["jobs"][n]["conclusion"]="failure"
            with self.assertRaises(mod.Denied):
                source_check(jobs=altered, artifacts=artifacts)
        for name in ("chat-owner-sigstore-second-nonpublishing",
                     "chat-owner-dual-sigstore-nonpublishing"):
            a=copy.deepcopy(artifacts)
            a["artifacts"]=[x for x in a["artifacts"] if x["name"]!=name]
            a["total_count"]=len(a["artifacts"])
            with self.assertRaises(mod.Denied):
                source_check(jobs=jobs, artifacts=a)
        for bad in ({"jobs": jobs}, {"artifacts": artifacts},
                    {"artifacts": {"total_count": 1, "artifacts": source_artifacts()["artifacts"][:1]}}):
            with self.assertRaises(mod.Denied):
                source_check(**bad)
        x=live_signing();x["body"]="/pgextwin publish "+REPO
        with self.assertRaises(mod.Denied):
            source_check(live=x)

    def test_source_must_not_enable_formal_publisher(self):
        path=(ROOT/".github/workflows/publisher-candidate-intake.yml").read_text("utf-8")
        self.assertIn("independent_owner_source_admission:",path)
        job=path.split("  independent_owner_source_admission:",1)[1].split(
            "  independent_real_signed_source:",1)[0]
        self.assertIn("publisher-owner-source-admission.py",job)
        self.assertIn("github.event_name == 'issue_comment'",job)
        self.assertIn("admit-owner-source",job)
        for denied in ("environment: publisher","contents: write",
                       "PGEXTWIN_PUBLISHER_APP_PRIVATE_KEY",
                       "gh release create","secrets.","schedule:"):
            self.assertNotIn(denied,job)
        self.assertIn("PUBLISH_DENY",job)

    def test_original_and_publisher_each_verify_two_predicates_per_major_offline(self):
        # Stub GitHub transport and Sigstore responses at the command boundary.
        # Exercise the real audit, proof_statement, and receipt comparison.
        # These synthetic fixtures grant no signing or publication authority.
        def load(label, name):
            spec = importlib.util.spec_from_file_location(label, ROOT / "tests" / name)
            value = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(value)
            return value
        assets = load("owner_passenger_assets", "test-fleet-publish-release.py")
        proofs = load("owner_passenger_proofs", "test-automatic-signed-candidate-audit.py")
        fleet = json.loads((ROOT / "metadata/automation-fleet.json").read_text())
        lifecycle = assets.fixture()[1]
        lifecycle["postgresql"].append({"major": 19, "eol": "2031-12-31"})
        workflow = (ROOT / mod.audit.SOURCE_WORKFLOW).read_text("utf-8")
        canonical_signer = mod.audit.signer_sha_from_workflow(workflow)
        routes = mod.audit.routes
        policy_raw = (ROOT / routes.POLICY).read_bytes()
        policy = routes.read_policy(policy_raw)
        central_sha = "c" * 40
        for name, ref, version, legacy, majors in (
                ("pg_hint_plan", "REL19_1_0", "1.0", False, [15, 16, 17, 18, 19]),
                ("pg_ivm", "v1.17", "1.17", False, [15, 16, 17, 18, 19]),
                ("pg_permissions", "REL_1_4_1", "1.4.1", True, [15, 16, 17, 18]),
                ("pg_permissions", "REL_1_6", "1.6", False, [15, 16, 17, 18, 19]),
                ("pgtap", "v1.3.4", "1.3.4", False, [15, 16, 17, 18, 19]),
                ("pg_track_settings", "2.1.2", "2.1.2", False, [15, 16, 17, 18])):
            repo = "pgextwin/" + name
            group = routes.repository_policy(policy, repo) if repo in routes.PACKAGE_REPOSITORIES else None
            wrapper = routes.owner_wrapper_pins(policy, repo)[0] if group else None
            signer_sha = group["candidateSigner"] if group else canonical_signer
            if legacy and repo in routes.WAVE2_LEGACY_WRAPPERS:
                wrapper = routes.WAVE2_LEGACY_WRAPPERS[repo]
                signer_sha = canonical_signer
            manifest = {"schemaVersion": 1, "name": name,
                        "upstream": {"repository": mod.ident.UPSTREAMS[name],
                                     "ref": ref, "version": version, "commit": "b"*40},
                        "postgresql": {"majors": majors}}
            source_intent = intent(repo, 1)
            run_id = source_intent["runId"]
            uri = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/1"
            signer = ("https://github.com/pgextwin/build/" +
                      mod.audit.pin.offline.SIGNER_PATH + "@" + signer_sha)

            def verify_command(args, **kwargs):
                self.assertEqual(args[:3], ["gh", "attestation", "verify"])
                path = Path(args[3])
                kind = args[args.index("--predicate-type") + 1]
                self.assertEqual(args[args.index("--repo") + 1], repo)
                self.assertEqual(args[args.index("--source-digest") + 1], SHA)
                self.assertEqual(args[args.index("--signer-digest") + 1], signer_sha)
                entry = proofs.signed_result(path, kind, repo, SHA)[0]
                cert = entry["verificationResult"]["signature"]["certificate"]
                cert.update(runInvocationURI=uri, buildSignerURI=signer,
                            subjectAlternativeName=signer,
                            buildSignerDigest=signer_sha,
                            buildConfigURI=f"https://github.com/{repo}/{mod.SOURCE_WORKFLOW}@refs/heads/main",
                            buildTrigger="issue_comment")
                if kind == mod.audit.pin.SLSA:
                    entry["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = uri
                return CompletedProcess(args, 0, stdout=json.dumps([entry]), stderr="")

            with self.subTest(repository=repo), TemporaryDirectory() as td:
                root = Path(td)
                original = root / "assets"
                original.mkdir()
                assets.make_assets(original, manifest, run=run_id, workflow_event="issue_comment")
                for path in original.glob("*.zip"):
                    with ZipFile(path) as z:
                        package = json.loads(z.read("PACKAGE-INFO.json"))
                    package["package"].update(name=name, platform="windows", architecture="x64")
                    package["source"]["packagingRepository"] = repo
                    package["workflowRun"]["url"] = uri.removesuffix("/attempts/1")
                    package["buildInfrastructure"]["commit"] = signer_sha
                    with ZipFile(path, "w") as z:
                        z.writestr("PACKAGE-INFO.json", json.dumps(package))

                with patch.object(mod.audit.subprocess, "run", side_effect=verify_command) as calls:
                    receipt, blocking = mod.audit.audit(
                        original, source_intent, manifest, lifecycle, repo=repo, sha=SHA,
                        run_id=run_id, signer_sha=signer_sha)
                    self.assertEqual(blocking, 0)
                    self.assertEqual(calls.call_count, 2 * len(majors))
                    calls.reset_mock()
                    with self.assertRaisesRegex(mod.audit.Denied, "signer mismatch"):
                        mod.audit.audit(original, source_intent, manifest, lifecycle, repo=repo,
                                        sha=SHA, run_id=run_id, signer_sha=mod.audit.pin.SIGNER_SHA)
                    calls.assert_not_called()
                    artifact = mod.audit.AUDIT_ARTIFACT
                    filename = mod.audit.AUDIT_FILE
                    if legacy:
                        receipt.update(schemaVersion=1, auditors=["first", "second"],
                                       status="DUAL_VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING")
                        artifact = "chat-owner-dual-sigstore-nonpublishing"
                        filename = "chat-owner-dual-sigstore.json"

                    def fetch(repository, source_run, artifact_name, folder, *, pattern=False):
                        self.assertEqual((repository, source_run), (repo, run_id))
                        folder.mkdir()
                        if pattern:
                            for path in original.iterdir():
                                shutil.copyfile(path, folder / path.name)
                        else:
                            label = {
                                "chat-main-source-intent-nonpublishing": ("owner-main-intent.json", source_intent),
                                artifact: (filename, receipt),
                            }[artifact_name]
                            (folder / label[0]).write_text(json.dumps(label[1]))

                    def blob(path, raw):
                        return {"type": "file", "path": path, "encoding": "base64",
                                "content": base64.b64encode(raw.encode()).decode()}

                    def get(repository, route):
                        if wrapper and repository == routes.CENTRAL:
                            self.assertEqual(route, f"contents/{routes.OWNER_WRAPPER}?ref={wrapper}")
                            return blob(routes.OWNER_WRAPPER, workflow.replace(canonical_signer, signer_sha))
                        self.assertEqual(repository, repo)
                        current_run = signed_run(repo)
                        caller = {}
                        if wrapper:
                            current_run["referenced_workflows"] = [
                                {"path": routes.workflow_ref(path, pin), "sha": pin}
                                for path, pin in ((routes.OWNER_WRAPPER, wrapper), (routes.SIGNER, signer_sha))
                            ]
                            caller[f"contents/{routes.OWNER_CALLER}?ref={SHA}"] = blob(
                                routes.OWNER_CALLER,
                                f"jobs:\n  signed_main_source:\n    uses: {routes.workflow_ref(routes.OWNER_WRAPPER, wrapper)}\n")
                        return {
                            **caller,
                            "branches/main": branch(),
                            f"contents/config/extension.json?ref={SHA}": {
                                "encoding": "base64", "content": base64.b64encode(json.dumps(manifest).encode()).decode()},
                            f"actions/runs/{run_id}": current_run,
                            f"actions/runs/{run_id}/attempts/1/jobs?per_page=100": original_jobs(majors, legacy=legacy),
                            f"actions/runs/{run_id}/artifacts?per_page=100": source_artifacts(legacy=legacy),
                            "issues/comments/4444": live_signing(repo, 1),
                        }[route]

                    with patch.object(mod.audit, "protected_blob", return_value=policy_raw) as protected, \
                         patch.object(mod.audit, "signer_sha_at", return_value=canonical_signer) as resolve, \
                            patch.object(mod, "get", side_effect=get), patch.object(
                                mod, "fetch_artifact", side_effect=fetch) as downloads:
                        result, admitted_manifest, admitted_intent = mod.admit(
                            repo, run_id, scratch=root, fleet=fleet, lifecycle=lifecycle,
                            central_sha=central_sha)
                        if wrapper:
                            protected.assert_called_once_with(central_sha, routes.POLICY)
                            resolve.assert_not_called()
                        else:
                            resolve.assert_called_once_with(central_sha)
                        self.assertEqual(admitted_manifest, manifest)
                        self.assertEqual(admitted_intent, source_intent)
                        self.assertEqual(downloads.call_count, 3)
                        self.assertEqual(calls.call_count, 2 * len(majors))
                        self.assertEqual(result["repository"], repo)
                        self.assertEqual(result["maintainedMajors"], majors)
                        self.assertEqual(len(result["SHA256"]), 3 * len(majors))
                        self.assertTrue(result["originalAndFreshSigstoreAgree"])
                        self.assertEqual(result["PUBLISH"], "DENY")
                        for field in ("publisherEligible", "publicationAuthorized", "publishableReceipt", "publisherWriteAuthorized"):
                            self.assertIs(result[field], False)
                        # A stale original receipt cannot pass a fresh byte audit.
                        receipt["SHA256"] = {"foreign.zip": "0"*64}
                        retry = root / "retry"
                        retry.mkdir()
                        with self.assertRaisesRegex(mod.Denied, "independent Publisher Sigstore/byte receipts differ"):
                            mod.admit(repo, run_id, scratch=retry, fleet=fleet, lifecycle=lifecycle,
                                      central_sha=central_sha)

class ReceiptComparableTests(TestCase):
    def fresh(self):
        return {"schemaVersion": 2,
                "status": "VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING",
                "SHA256": {"x.zip": "0"*64},
                "grypePolicyByMajor": {"15": {"status": "NO_BLOCKING_FINDINGS"}}}

    def test_new_format_compares_the_full_dictionary(self):
        original = self.fresh()
        self.assertEqual(mod.receipt_comparable(original, self.fresh(), legacy=False),
                         original)
        altered = self.fresh()
        altered["grypePolicyByMajor"]["15"]["status"] = "BLOCKING_FINDINGS"
        self.assertNotEqual(mod.receipt_comparable(altered, self.fresh(), legacy=False),
                            altered)
        altered = self.fresh()
        altered["SHA256"] = {"x.zip": "1"*64}
        self.assertNotEqual(mod.receipt_comparable(altered, self.fresh(), legacy=False),
                            altered)

    def test_old_format_excludes_exactly_the_missing_field(self):
        original = self.fresh()
        del original["grypePolicyByMajor"]
        comparable = mod.receipt_comparable(original, self.fresh(), legacy=False)
        self.assertEqual(comparable, original)
        self.assertNotIn("grypePolicyByMajor", comparable)
        # Every other field is still compared exactly.
        for field, value in (("SHA256", {"x.zip": "1"*64}),
                             ("status", "DUAL_VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING"),
                             ("schemaVersion", 1)):
            altered = copy.deepcopy(original)
            altered[field] = value
            self.assertNotEqual(
                mod.receipt_comparable(altered, self.fresh(), legacy=False), altered)
        # An extra field in the old receipt is not silently dropped either.
        altered = copy.deepcopy(original)
        altered["unexpected"] = True
        self.assertNotEqual(
            mod.receipt_comparable(altered, self.fresh(), legacy=False), altered)

    def test_legacy_shape_combines_with_both_formats(self):
        legacy_shape = {**self.fresh(), "schemaVersion": 1,
                        "auditors": ["first", "second"],
                        "status": "DUAL_VERIFIED_OWNER_MAIN_SIGNED_NONPUBLISHING"}
        self.assertEqual(mod.receipt_comparable(legacy_shape, self.fresh(), legacy=True),
                         legacy_shape)
        old = copy.deepcopy(legacy_shape)
        del old["grypePolicyByMajor"]
        self.assertEqual(mod.receipt_comparable(old, self.fresh(), legacy=True), old)


class OldFormatReceiptAdmissionTests(TestCase):
    def test_old_and_new_format_receipts_admit_only_with_full_reverification(self):
        # Same offline harness style as the end-to-end admission test above:
        # stub GitHub transport and Sigstore at the command boundary and run
        # the real audit plus admit() against served original receipts.
        def load(label, name):
            spec = importlib.util.spec_from_file_location(label, ROOT / "tests" / name)
            value = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(value)
            return value
        assets = load("pr6_assets", "test-fleet-publish-release.py")
        proofs = load("pr6_proofs", "test-automatic-signed-candidate-audit.py")
        fleet = json.loads((ROOT / "metadata/automation-fleet.json").read_text())
        lifecycle = assets.fixture()[1]
        lifecycle["postgresql"].append({"major": 19, "eol": "2031-12-31"})
        workflow = (ROOT / mod.audit.SOURCE_WORKFLOW).read_text("utf-8")
        canonical_signer = mod.audit.signer_sha_from_workflow(workflow)
        routes = mod.audit.routes
        policy_raw = (ROOT / routes.POLICY).read_bytes()
        policy = routes.read_policy(policy_raw)
        central_sha = "c" * 40
        name, majors = "pg_ivm", [15, 16, 17, 18, 19]
        repo = "pgextwin/" + name
        group = routes.repository_policy(policy, repo)
        wrapper = routes.owner_wrapper_pins(policy, repo)[0]
        signer_sha = group["candidateSigner"]
        manifest = {"schemaVersion": 1, "name": name,
                    "upstream": {"repository": mod.ident.UPSTREAMS[name],
                                 "ref": "v1.17", "version": "1.17", "commit": "b"*40},
                    "postgresql": {"majors": majors}}
        source_intent = intent(repo, 1)
        run_id = source_intent["runId"]
        uri = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/1"
        signer = ("https://github.com/pgextwin/build/" +
                  mod.audit.pin.offline.SIGNER_PATH + "@" + signer_sha)
        served = {"receipt": None, "bad_signer": False}

        def verify_command(args, **kwargs):
            self.assertEqual(args[:3], ["gh", "attestation", "verify"])
            path = Path(args[3])
            kind = args[args.index("--predicate-type") + 1]
            entry = proofs.signed_result(path, kind, repo, SHA)[0]
            cert = entry["verificationResult"]["signature"]["certificate"]
            cert.update(runInvocationURI=uri, buildSignerURI=signer,
                        subjectAlternativeName=signer,
                        buildSignerDigest="d"*40 if served["bad_signer"] else signer_sha,
                        buildConfigURI=f"https://github.com/{repo}/{mod.SOURCE_WORKFLOW}@refs/heads/main",
                        buildTrigger="issue_comment")
            if kind == mod.audit.pin.SLSA:
                entry["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = uri
            return CompletedProcess(args, 0, stdout=json.dumps([entry]), stderr="")

        with TemporaryDirectory() as td:
            root = Path(td)
            original = root / "assets"
            original.mkdir()
            assets.make_assets(original, manifest, run=run_id, workflow_event="issue_comment")
            for path in original.glob("*.zip"):
                with ZipFile(path) as z:
                    package = json.loads(z.read("PACKAGE-INFO.json"))
                package["package"].update(name=name, platform="windows", architecture="x64")
                package["source"]["packagingRepository"] = repo
                package["workflowRun"]["url"] = uri.removesuffix("/attempts/1")
                package["buildInfrastructure"]["commit"] = signer_sha
                with ZipFile(path, "w") as z:
                    z.writestr("PACKAGE-INFO.json", json.dumps(package))

            def fetch(repository, source_run, artifact_name, folder, *, pattern=False):
                self.assertEqual((repository, source_run), (repo, run_id))
                folder.mkdir()
                if pattern:
                    for path in original.iterdir():
                        shutil.copyfile(path, folder / path.name)
                else:
                    label = {
                        "chat-main-source-intent-nonpublishing": ("owner-main-intent.json", source_intent),
                        mod.audit.AUDIT_ARTIFACT: (mod.audit.AUDIT_FILE, served["receipt"]),
                    }[artifact_name]
                    (folder / label[0]).write_text(json.dumps(label[1]))

            def blob(path, raw):
                return {"type": "file", "path": path, "encoding": "base64",
                        "content": base64.b64encode(raw.encode()).decode()}

            def get(repository, route):
                if repository == routes.CENTRAL:
                    self.assertEqual(route, f"contents/{routes.OWNER_WRAPPER}?ref={wrapper}")
                    return blob(routes.OWNER_WRAPPER, workflow.replace(canonical_signer, signer_sha))
                self.assertEqual(repository, repo)
                current_run = signed_run(repo)
                current_run["referenced_workflows"] = [
                    {"path": routes.workflow_ref(path, pin), "sha": pin}
                    for path, pin in ((routes.OWNER_WRAPPER, wrapper), (routes.SIGNER, signer_sha))
                ]
                caller = {f"contents/{routes.OWNER_CALLER}?ref={SHA}": blob(
                    routes.OWNER_CALLER,
                    f"jobs:\n  signed_main_source:\n    uses: {routes.workflow_ref(routes.OWNER_WRAPPER, wrapper)}\n")}
                return {
                    **caller,
                    "branches/main": branch(),
                    f"contents/config/extension.json?ref={SHA}": {
                        "encoding": "base64", "content": base64.b64encode(json.dumps(manifest).encode()).decode()},
                    f"actions/runs/{run_id}": current_run,
                    f"actions/runs/{run_id}/attempts/1/jobs?per_page=100": original_jobs(majors),
                    f"actions/runs/{run_id}/artifacts?per_page=100": source_artifacts(),
                    "issues/comments/4444": live_signing(repo, 1),
                }[route]

            with patch.object(mod.audit.subprocess, "run", side_effect=verify_command) as calls, \
                 patch.object(mod.audit, "protected_blob", return_value=policy_raw), \
                 patch.object(mod.audit, "signer_sha_at", return_value=canonical_signer), \
                 patch.object(mod, "get", side_effect=get), \
                 patch.object(mod, "fetch_artifact", side_effect=fetch):
                genuine, blocking = mod.audit.audit(
                    original, source_intent, manifest, lifecycle, repo=repo, sha=SHA,
                    run_id=run_id, signer_sha=signer_sha)
                self.assertEqual(blocking, 0)
                self.assertIn("grypePolicyByMajor", genuine)
                old_format = {k: v for k, v in genuine.items()
                              if k != "grypePolicyByMajor"}
                attempts = 0

                def attempt():
                    nonlocal attempts
                    attempts += 1
                    scratch = root / f"attempt{attempts}"
                    scratch.mkdir()
                    return mod.admit(repo, run_id, scratch=scratch, fleet=fleet,
                                     lifecycle=lifecycle, central_sha=central_sha)

                # New format, genuine: admitted (also covered for six
                # repositories by the end-to-end test above).
                served["receipt"] = copy.deepcopy(genuine)
                result, _, _ = attempt()
                self.assertTrue(result["originalAndFreshSigstoreAgree"])

                # Old format, genuine: admitted, and the fresh audit still
                # re-verified both Sigstore predicates for every major from
                # the original bytes -- the format reading relaxes nothing.
                served["receipt"] = copy.deepcopy(old_format)
                calls.reset_mock()
                result, _, _ = attempt()
                self.assertTrue(result["originalAndFreshSigstoreAgree"])
                self.assertEqual(calls.call_count, 2 * len(majors))

                # Old format with a tampered digest: denied by comparison.
                tampered = copy.deepcopy(old_format)
                key = sorted(tampered["SHA256"])[0]
                tampered["SHA256"][key] = "0"*64 if tampered["SHA256"][key] != "0"*64 else "1"*64
                served["receipt"] = tampered
                with self.assertRaisesRegex(mod.Denied, "receipts differ"):
                    attempt()

                # New format with a Grype verdict mismatch: denied.
                forged = copy.deepcopy(genuine)
                forged["grypePolicyByMajor"]["15"] = {
                    **forged["grypePolicyByMajor"]["15"], "status": "BLOCKING_FINDINGS"}
                served["receipt"] = forged
                with self.assertRaisesRegex(mod.Denied, "receipts differ"):
                    attempt()

                # Old format served, but the original bytes fail Sigstore
                # signer verification: denied by the fresh audit itself.
                served["receipt"] = copy.deepcopy(old_format)
                served["bad_signer"] = True
                with self.assertRaises(mod.audit.pin.Deny):
                    attempt()


if __name__ == "__main__":
    main()
