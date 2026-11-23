"""Offline trust checks for the exact pilot signer and the protected wrapper policy."""

import base64
import importlib.util
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
            resolve("pgextwin/pg_ivm")
        run["referenced_workflows"][0]["sha"] = "e" * 40
        with self.assertRaisesRegex(routes.Denied, "approved workflow"):
            resolve()
        run["referenced_workflows"][0]["sha"] = WRAPPER
        caller = caller.replace(WRAPPER.encode(), b"e" * 40)
        with self.assertRaisesRegex(routes.Denied, "protected owner-source caller"):
            resolve()


if __name__ == "__main__":
    unittest.main()
