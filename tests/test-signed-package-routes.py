"""Offline trust checks for the exact pilot signer and the protected wrapper policy."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("package_owner_audit", ROOT / "scripts/chat-signed-main-audit.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
routes = owner.routes
POLICY = routes.read_policy()
SIGNER = POLICY["candidateSigner"]
WRAPPER = POLICY["ownerWrappers"]["pgextwin/pg_profile"]
VERIFIER = POLICY["candidateAudit"]
REPO = "pgextwin/pg_profile"
HEAD = "d" * 40


def git_blob(commit, path):
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "--no-replace-objects", "show", f"{commit}:{path}"])


class SignedPackageRoutes(unittest.TestCase):
    def test_fixed_workflow_chain_in_git_objects(self):
        for repository, wrapper in sorted(POLICY["ownerWrappers"].items()):
            self.assertEqual(owner.signer_sha_from_workflow(git_blob(wrapper, routes.OWNER_WRAPPER)), SIGNER)
            print(f"{repository} wrapper={wrapper} signer={SIGNER} candidate-audit={VERIFIER}")
        signer_workflow = git_blob(SIGNER, routes.SIGNER)
        self.assertIn(b"-BuildMode release-attested", signer_workflow)
        self.assertIn(b"scripts/invoke-windows-package.ps1", signer_workflow)
        self.assertIn(b"Require a pilot signing repository", signer_workflow)
        verifier_workflow = git_blob(VERIFIER, routes.CANDIDATE_AUDIT)
        self.assertEqual(verifier_workflow.count(b'--package-verifier-sha "$VERIFIER_SHA"'), 2)
        self.assertEqual(routes.read_policy(git_blob(VERIFIER, routes.POLICY))["candidateSigner"], SIGNER)
        canonical = (ROOT / routes.OWNER_WRAPPER).read_bytes()
        self.assertEqual(owner.signer_sha_from_workflow(canonical),
                         "4558c82c28b0814e60f35c6e5e5f8ee1025a5754")

    def test_owner_signer_requires_protected_caller_and_matching_run(self):
        wrapper_ref = routes.workflow_ref(routes.OWNER_WRAPPER, WRAPPER)
        signer_ref = routes.workflow_ref(routes.SIGNER, SIGNER)
        caller = f"jobs:\n  signed_main_source:\n    uses: {wrapper_ref}\n".encode()

        def get(repo, resource):
            if repo == REPO and resource == f"contents/{routes.OWNER_CALLER}?ref={HEAD}":
                path, raw = routes.OWNER_CALLER, caller
            elif repo == routes.CENTRAL and resource == f"contents/{routes.OWNER_WRAPPER}?ref={WRAPPER}":
                path, raw = routes.OWNER_WRAPPER, git_blob(WRAPPER, routes.OWNER_WRAPPER)
            else:
                self.fail(f"unexpected GET {repo} {resource}")
            return {"type": "file", "path": path, "encoding": "base64", "content": base64.b64encode(raw).decode()}

        run = {"referenced_workflows": [{"path": wrapper_ref, "sha": WRAPPER}, {"path": signer_ref, "sha": SIGNER}]}

        def resolve(repository=REPO):
            return routes.owner_signer(get, repository, HEAD, run, WRAPPER, owner.signer_sha_from_workflow)

        self.assertEqual(resolve(), SIGNER)
        with self.assertRaisesRegex(routes.Denied, "outside"):
            resolve("pgextwin/unregistered_fixture")
        run["referenced_workflows"][0]["sha"] = "e" * 40
        with self.assertRaisesRegex(routes.Denied, "approved workflow"):
            resolve()
        run["referenced_workflows"][0]["sha"] = WRAPPER
        caller = caller.replace(WRAPPER.encode(), b"e" * 40)
        with self.assertRaisesRegex(routes.Denied, "protected owner-source caller"):
            resolve()

    def test_wave2_immutable_routes_bind_both_readers_and_exclude_other_repositories(self):
        group = POLICY["wave2"]
        signer = group["candidateSigner"]
        verifier = group["candidateAudit"]
        workflow = git_blob(signer, routes.SIGNER)
        self.assertIn(b"pgextwin/pg_permissions|pgextwin/pgtap)", workflow)
        self.assertNotIn(b"pgextwin/pg_profile|pgextwin/pg_track_settings)", workflow)
        self.assertIn(b"scripts/invoke-windows-package.ps1", workflow)
        self.assertIn(b"Copyright (c)", git_blob(signer, "scripts/resolve-matrix.ps1"))
        self.assertEqual(git_blob(verifier, routes.CANDIDATE_AUDIT).count(
            b'--package-verifier-sha "$VERIFIER_SHA"'), 2)
        self.assertEqual(routes.read_policy(git_blob(verifier, routes.POLICY))["wave2"]["candidateSigner"], signer)

        for repo, wrapper in group["ownerWrappers"].items():
            with self.subTest(repo=repo):
                legacy_wrapper = routes.WAVE2_LEGACY_WRAPPERS[repo]
                legacy_owner = owner.signer_sha_from_workflow(git_blob(legacy_wrapper, routes.OWNER_WRAPPER))
                self.assertEqual(legacy_owner, "4558c82c28b0814e60f35c6e5e5f8ee1025a5754")
                self.assertEqual(owner.signer_sha_from_workflow(git_blob(wrapper, routes.OWNER_WRAPPER)), signer)
                self.assertIn(repo.encode(), git_blob(wrapper, routes.OWNER_WRAPPER))
                print(f"{repo} legacy-wrapper={legacy_wrapper} legacy-owner-signer={legacy_owner} "
                      f"wrapper={wrapper} signer={signer} candidate-audit={verifier}")

                def refs(*pins):
                    return {"referenced_workflows": [
                        {"path": routes.workflow_ref(path, sha), "sha": sha} for path, sha in pins
                    ]}

                def get(repository, resource):
                    path = resource.removeprefix("contents/").split("?")[0]
                    if repository == routes.CENTRAL:
                        raw = git_blob(resource.split("=")[-1], path)
                    elif path == routes.CANDIDATE_CALLER:
                        raw = (f"jobs:\n  candidate_attested_build:\n    uses: {candidate_run['referenced_workflows'][0]['path']}\n"
                               f"  candidate_signed_audit:\n    uses: {audit_ref}\n").encode()
                    else:
                        raw = f"jobs:\n  signed_main_source:\n    uses: {routes.workflow_ref(routes.OWNER_WRAPPER, owner_wrapper)}\n".encode()
                    return {"type": "file", "path": path, "encoding": "base64",
                            "content": base64.b64encode(raw).decode()}

                owner_wrapper = wrapper
                owner_run = refs((routes.OWNER_WRAPPER, wrapper), (routes.SIGNER, signer))
                self.assertEqual(routes.owner_signer(get, repo, HEAD, owner_run, wrapper,
                                                     owner.signer_sha_from_workflow), signer)
                owner_wrapper = legacy_wrapper
                owner_run = refs((routes.OWNER_WRAPPER, legacy_wrapper), (routes.SIGNER, legacy_owner))
                self.assertEqual(routes.owner_signer(get, repo, HEAD, owner_run, wrapper,
                                                     owner.signer_sha_from_workflow, legacy_wrapper_sha=legacy_wrapper),
                                 legacy_owner)
                legacy_candidate = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
                candidate_run = refs((routes.SIGNER, signer), (routes.CANDIDATE_AUDIT, verifier))
                audit_ref = routes.workflow_ref(routes.CANDIDATE_AUDIT, verifier)
                self.assertEqual(routes.candidate_signer(get, repo, HEAD, candidate_run, POLICY, legacy_candidate), signer)
                self.assertEqual(routes.candidate_signer(get, "pgextwin/unregistered_fixture", HEAD, candidate_run, POLICY,
                                                         legacy_candidate), legacy_candidate)
                with self.assertRaisesRegex(routes.Denied, "approved signer and audit pair"):
                    routes.candidate_signer(get, REPO, HEAD, candidate_run, POLICY, legacy_candidate)
                candidate_run["referenced_workflows"][0]["sha"] = legacy_candidate
                with self.assertRaisesRegex(routes.Denied, "approved workflow"):
                    routes.candidate_signer(get, repo, HEAD, candidate_run, POLICY, legacy_candidate)
                audit_ref = routes.workflow_ref(routes.CANDIDATE_AUDIT, routes.LEGACY_AUDIT)
                candidate_run = refs((routes.SIGNER, legacy_candidate), (routes.CANDIDATE_AUDIT, routes.LEGACY_AUDIT))
                self.assertEqual(routes.candidate_signer(get, repo, HEAD, candidate_run, POLICY, legacy_candidate),
                                 legacy_candidate)

    def test_extension_routes_bind_fixed_workflows_and_readers(self):
        for repo, route in POLICY["extensions"].items():
            with self.subTest(repository=repo):
                signer, verifier = route["candidateSigner"], route["candidateAudit"]
                wrapper, legacy_wrapper = routes.owner_wrapper_pins(POLICY, repo)
                schedule = route["scheduledRequalification"]
                legacy_owner = owner.signer_sha_from_workflow(git_blob(legacy_wrapper, routes.OWNER_WRAPPER))
                legacy_signer = "5756b3c5136a8bf4db710016cfe97555f0a71c6d"
                print(f"{repo} signer={signer} candidate-audit={verifier} owner-wrapper={wrapper} "
                      f"requalification={schedule} legacy-wrapper={legacy_wrapper} legacy-owner-signer={legacy_owner}")
                self.assertIn(b"scripts/invoke-windows-package.ps1", git_blob(signer, routes.SIGNER))
                scope = json.loads(git_blob(signer, "metadata/windows-package-signing-scope.json"))
                self.assertEqual(set(scope), {name for name, value in POLICY["extensions"].items()
                                              if value["candidateSigner"] == signer})
                self.assertIn(b"metadata/windows-package-signing-scope.json", git_blob(signer, routes.SIGNER))
                self.assertEqual(owner.signer_sha_from_workflow(git_blob(wrapper, routes.OWNER_WRAPPER)), signer)
                self.assertEqual(git_blob(verifier, routes.CANDIDATE_AUDIT).count(
                    b'--package-verifier-sha "$VERIFIER_SHA"'), 2)
                for revision in filter(None, (verifier, schedule)):
                    self.assertEqual(routes.repository_policy(routes.read_policy(git_blob(revision, routes.POLICY)),
                                                              repo)["candidateSigner"], signer)

                def refs(*pins):
                    return {"referenced_workflows": [
                        {"path": routes.workflow_ref(path, sha), "sha": sha} for path, sha in pins
                    ]}

                def get(repository, resource):
                    path, revision = resource.removeprefix("contents/").split("?ref=")
                    if repository == routes.CENTRAL:
                        raw = git_blob(revision, path)
                    else:
                        self.assertEqual((repository, revision), (repo, HEAD))
                        raw = ("jobs:\n" + "".join(
                            f"  {job}:\n    uses: {routes.workflow_ref(workflow, pin)}\n"
                            for job, (workflow, pin) in caller.items())).encode()
                    return {"type": "file", "path": path, "encoding": "base64",
                            "content": base64.b64encode(raw).decode()}

                for approved, expected in ((wrapper, signer), (legacy_wrapper, legacy_owner)):
                    caller = {"signed_main_source": (routes.OWNER_WRAPPER, approved)}
                    run = refs((routes.OWNER_WRAPPER, approved), (routes.SIGNER, expected))
                    self.assertEqual(routes.owner_signer(get, repo, HEAD, run, wrapper, owner.signer_sha_from_workflow,
                                                        legacy_wrapper_sha=legacy_wrapper), expected)
                    run["referenced_workflows"][1]["sha"] = "e" * 40
                    with self.assertRaisesRegex(routes.Denied, "approved workflow"):
                        routes.owner_signer(get, repo, HEAD, run, wrapper, owner.signer_sha_from_workflow,
                                            legacy_wrapper_sha=legacy_wrapper)
                for approved, audit_sha in ((signer, verifier), (legacy_signer, routes.LEGACY_AUDIT)):
                    caller = {"candidate_attested_build": (routes.SIGNER, approved),
                              "candidate_signed_audit": (routes.CANDIDATE_AUDIT, audit_sha)}
                    run = refs(*caller.values())
                    self.assertEqual(routes.candidate_signer(get, repo, HEAD, run, POLICY, legacy_signer), approved)
                    self.assertEqual(routes.candidate_signer(get, "pgextwin/unregistered_fixture", HEAD, run, POLICY, legacy_signer),
                                     legacy_signer)
                    run["referenced_workflows"][0]["sha"] = "e" * 40
                    with self.assertRaisesRegex(routes.Denied, "approved workflow"):
                        routes.candidate_signer(get, repo, HEAD, run, POLICY, legacy_signer)
                if schedule is None:
                    continue
                scheduled_workflow = git_blob(schedule, routes.SCHEDULED_REQUALIFICATION)
                self.assertEqual(routes.workflow_uses(scheduled_workflow, ["signed_windows"]),
                                 [routes.workflow_ref(routes.SIGNER, signer)])
                self.assertEqual(scheduled_workflow.count(b'--package-requalification-sha "$REQUALIFICATION_SHA"'), 2)
                caller = {"merged_candidate_scheduled_oidc": (routes.SCHEDULED_REQUALIFICATION, schedule)}
                run = refs(*caller.values(), (routes.SIGNER, signer))
                self.assertEqual(routes.requalification_signer(get, repo, HEAD, run, POLICY, schedule), signer)
                with self.assertRaisesRegex(routes.Denied, "outside"):
                    routes.requalification_signer(get, "pgextwin/unregistered_fixture", HEAD, run, POLICY, schedule)
                run["referenced_workflows"][1]["sha"] = legacy_signer
                with self.assertRaisesRegex(routes.Denied, "approved workflow"):
                    routes.requalification_signer(get, repo, HEAD, run, POLICY, schedule)
                caller["merged_candidate_scheduled_oidc"] = (routes.SCHEDULED_REQUALIFICATION, "e" * 40)
                with self.assertRaisesRegex(routes.Denied, "protected scheduled caller"):
                    routes.requalification_signer(get, repo, HEAD, run, POLICY, schedule)


if __name__ == "__main__":
    unittest.main()
