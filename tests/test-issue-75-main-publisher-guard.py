#!/usr/bin/env python3
"""PRE-G4 active manual Publisher guard: hostile offline tests ONLY.

Mocked gh verification results are structural fixtures, NOT cryptographic proof.
Never call Publisher.main(), GitHub network, POST, PATCH, Dispatch or Release.
"""
import copy
import importlib.util
import json
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def load(path, label):
    spec = importlib.util.spec_from_file_location(label, ROOT / path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


p = load("scripts/fleet-publish-release.py", "issue75_guard_current")
oldtests = load("tests/test-fleet-publish-release.py", "issue75_existing_fixtures")
REPO, COMMIT = oldtests.REPO, oldtests.COMMIT
RUN = 123
ENV = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/main",
       "GITHUB_EVENT_NAME": "workflow_dispatch",
       "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1"}


def job(name, number, *, status="completed", conclusion="success", attempt=1):
    return {"id": number, "name": name, "run_id": RUN, "run_attempt": attempt,
            "head_sha": COMMIT, "status": status, "conclusion": conclusion}


def evidence(majors, *, attempt=1):
    g = p.guard
    run = {"id": RUN, "run_attempt": attempt, "repository": {"full_name": REPO},
           "head_sha": COMMIT, "head_branch": "main",
           "event": "workflow_dispatch", "path": g.PROMOTE_PATH,
           "status": "in_progress", "conclusion": None}
    jobs = [job(g.AUTHORIZE, 1), job(g.RESOLVE, 2)] + [
        job(g.BUILD + f" / PostgreSQL {major} / Windows x64", major + 10)
        for major in majors] + [
        job(g.PUBLISH, 999, status="in_progress", conclusion=None)]
    return run, {"total_count": len(jobs), "jobs": jobs}


def certificate(kind, zip_path, attempt=1, mutate=None):
    g = p.guard
    uri = f"https://github.com/{REPO}/actions/runs/{RUN}/attempts/{attempt}"
    signer = ("https://github.com/pgextwin/build/" + g.SIGNER_PATH
              + "@" + g.SIGNER_SHA)
    cert = {
        "issuer": "https://token.actions.githubusercontent.com",
        "runInvocationURI": uri,
        "buildSignerURI": signer, "subjectAlternativeName": signer,
        "buildSignerDigest": g.SIGNER_SHA,
        "sourceRepositoryURI": "https://github.com/" + REPO,
        "sourceRepositoryDigest": COMMIT,
        "sourceRepositoryRef": "refs/heads/main",
        "buildConfigURI": ("https://github.com/" + REPO + "/" +
                           g.PROMOTE_PATH + "@refs/heads/main"),
        "buildConfigDigest": COMMIT,
        "githubWorkflowSHA": COMMIT,
        "githubWorkflowRef": "refs/heads/main",
        "buildTrigger": "workflow_dispatch",
    }
    if mutate:
        field, value = mutate
        if value is None:
            cert.pop(field, None)
        else:
            cert[field] = value
    sbom = {"spdxVersion": "SPDX-2.3"}
    signed_pred = (
        sbom if kind == g.SPDX else
        {"buildDefinition": {"buildType": "offline-fixture"},
         "runDetails": {"metadata": {"invocationId": uri},
                        "builder": {"id": "fixture-only"}}}
    )
    stmt = {"predicateType": kind, "subject": [{
        "name": zip_path.name, "digest": {"sha256": p.digest(zip_path)}}],
        "predicate": signed_pred}
    return json.dumps([{"verificationResult": {
        "statement": stmt, "signature": {"certificate": cert},
        "verifiedTimestamps": [{"timestamp": "mock-not-proof"}]}}])


def replace_pkg(folder, major, transform):
    zip_path = next(x for x in folder.glob("*.zip") if f"-pg{major}-" in x.name)
    with ZipFile(zip_path) as z:
        pkg = json.loads(z.read("PACKAGE-INFO.json"))
    transform(pkg)
    with ZipFile(zip_path, "w") as z:
        z.writestr("PACKAGE-INFO.json", json.dumps(pkg))


def valid_gh(*args):
    if args[:3] != ("gh", "attestation", "verify"):
        raise AssertionError("unexpected process/write command")
    required = {
        "--repo": REPO, "--signer-workflow": p.SIGNER,
        "--signer-digest": p.guard.SIGNER_SHA,
        "--source-digest": COMMIT, "--source-ref": "refs/heads/main",
        "--format": "json"}
    for flag, expected in required.items():
        if flag not in args or args[args.index(flag) + 1] != expected:
            raise AssertionError("missing/wrong strict gh policy: " + flag)
    kind = args[args.index("--predicate-type") + 1]
    if kind not in (p.guard.PROVENANCE, p.guard.SPDX):
        raise AssertionError("unexpected attestation type")
    return certificate(kind, Path(args[3]))


class MainGuardOffline(TestCase):
    def invoke(self, *, distort=None, signed=None, mutate_pkg=None, env=None,
               api_failure=None):
        ext, lifecycle, receipt = oldtests.fixture()
        majors = receipt["majors"]
        active, page = evidence(majors)
        if distort:
            distort(active, page)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            oldtests.make_assets(folder, ext)
            if mutate_pkg:
                mutate_pkg(folder)
            def fake_get(path):
                if api_failure is not None:
                    raise p.Denied("GitHub API HTTP " + str(api_failure))
                if path == f"actions/runs/{RUN}":
                    return copy.deepcopy(active)
                if (path.startswith(f"actions/runs/{RUN}/attempts/")
                        and path.endswith("/jobs?per_page=100")):
                    # Simulate a valid GET page for the requested attempt; the
                    # independent run/job metadata must still reject mismatch.
                    return copy.deepcopy(page)
                raise AssertionError("unexpected or write API endpoint: " + path)
            with patch.object(p, "REPO", REPO), patch.dict(p.os.environ,
                    ENV if env is None else {**ENV, **env}), patch.object(
                    p, "get", side_effect=fake_get) as api, patch.object(
                    p, "run", side_effect=signed or valid_gh) as gh:
                result = p.check_assets(folder, ext, receipt, COMMIT, RUN, lifecycle)
                return result, api.call_count, gh.call_args_list

    def test_real_gh_envelope_projects_verified_result_only_fail_closed(self):
        # Verified GitHub CLI current JSON has both attestation bundle and
        # verificationResult; this is offline mocked SHAPE, not Sigstore.
        with tempfile.TemporaryDirectory() as directory:
            z = Path(directory) / "plpgsql_check-pg18-windows-x64.zip"
            z.write_bytes(b"synthetic untrusted ZIP, not a signed release")
            digest = p.digest(z)
            sbom = {"spdxVersion": "SPDX-2.3"}
            for kind in (p.guard.PROVENANCE, p.guard.SPDX):
                item = json.loads(certificate(kind, z))[0]
                real_shape = copy.deepcopy(item)
                real_shape["attestation"] = {"bundle": {"synthetic": True}}
                kwargs = dict(predicate=kind, repo=REPO, packaging_sha=COMMIT,
                              run_id=RUN, attempt=1, zip_name=z.name,
                              zip_digest=digest, sbom=sbom)
                # Projection retains the exact original certificate and
                # signature claims; cannot turn mocks into authority.
                p.guard.verified_claims(json.dumps([real_shape]), **kwargs)
                p.guard.verified_claims(json.dumps([item]), **kwargs)
                for bad in (
                    {**real_shape, "extraField": "untrusted"},
                    {**real_shape, "attestation": None},
                    {**real_shape, "attestation": {}},
                    {**real_shape, "attestation": []},
                    {**real_shape, "verificationResult": "forged"},
                ):
                    with self.subTest(kind=kind, bad=str(bad)[:40]):
                        with self.assertRaises(p.guard.Deny):
                            p.guard.verified_claims(json.dumps([bad]), **kwargs)
                duplicate = json.dumps([real_shape, copy.deepcopy(real_shape)])
                with self.assertRaises(p.guard.Deny):
                    p.guard.verified_claims(duplicate, **kwargs)
                crossed = copy.deepcopy(real_shape)
                crossed["verificationResult"]["signature"]["certificate"]["githubWorkflowSHA"] = "f"*40
                with self.assertRaises(p.guard.Deny):
                    p.guard.verified_claims(json.dumps([crossed]), **kwargs)

    def test_active_manual_root_in_progress_and_all_pg_signatures_mock_positive(self):
        got, api, signed = self.invoke()
        self.assertEqual(len(got), 15)
        self.assertEqual(api, 4)  # two authenticated root + attempt job GET pairs
        self.assertEqual(len(signed), 10)  # 5 PG x SLSA/SPDX strict gh calls
        self.assertEqual(sum("--predicate-type" in c.args for c in signed), 10)

    def test_environment_attempt_missing_wrong_noncanonical_and_event_deny(self):
        for bad in ("0", "02", "false", "1.0", "", "2"):
            with self.subTest(attempt=bad), self.assertRaises(p.guard.Deny):
                self.invoke(env={"GITHUB_RUN_ATTEMPT": bad})
        for changed in ({"GITHUB_EVENT_NAME": "push"},
                        {"GITHUB_RUN_ID": "124"},
                        {"GITHUB_REF": "refs/heads/other"}):
            with self.subTest(changed=changed), self.assertRaises(p.guard.Deny):
                self.invoke(env=changed)

    def test_attempt1_2_missing_null_bool_string_or_mixed_pg_deny(self):
        for value in (2, False, None, 0, "1", "2"):
            def alter(folder, v=value):
                replace_pkg(folder, 15, lambda obj: obj["workflowRun"].__setitem__("attempt", v))
            with self.subTest(value=value), self.assertRaises((p.Denied, p.guard.Deny)):
                self.invoke(mutate_pkg=alter)
        with self.assertRaises((p.Denied, p.guard.Deny)):
            self.invoke(mutate_pkg=lambda folder: replace_pkg(
                folder, 14, lambda obj: obj["workflowRun"].pop("attempt")))
        with self.assertRaises((p.Denied, p.guard.Deny)):
            self.invoke(mutate_pkg=lambda folder: replace_pkg(
                folder, 16, lambda obj: obj["buildInfrastructure"].__setitem__(
                    "commit", "f"*40)))

    def test_attempt_scoped_api_failed_skipped_partial_duplicate_wrong_run_deny(self):
        for what in ("wrong-attempt", "wrong-head", "wrong-run", "wrong-path",
                     "wrong-branch", "completed-root", "failed-signer",
                     "skipped-authorize", "missing-pg", "duplicate-pg",
                     "incomplete-page", "completed-publisher", "new-job"):
            def distort(run, page, what=what):
                jobs = page["jobs"]
                if what == "wrong-attempt": run["run_attempt"] = 2
                if what == "wrong-head": run["head_sha"] = "f"*40
                if what == "wrong-run": jobs[0]["run_id"] = RUN + 1
                if what == "wrong-path": run["path"] = "wrong.yml"
                if what == "wrong-branch": run["head_branch"] = "branch"
                if what == "completed-root":
                    run["status"], run["conclusion"] = "completed", "success"
                if what == "failed-signer":
                    jobs[3]["conclusion"] = "failure"
                if what == "skipped-authorize":
                    jobs[0]["conclusion"] = "skipped"
                if what == "missing-pg":
                    jobs.pop(3); page["total_count"] -= 1
                if what == "duplicate-pg":
                    jobs[4]["name"] = jobs[3]["name"]
                if what == "incomplete-page": page["total_count"] += 1
                if what == "completed-publisher":
                    jobs[-1]["status"], jobs[-1]["conclusion"] = "completed", "success"
                if what == "new-job":
                    jobs.append(job("Untrusted publisher", 777)); page["total_count"] += 1
            with self.subTest(what=what), self.assertRaises((p.Denied, p.guard.Deny)):
                self.invoke(distort=distort)

    def test_api_denies_null_and_http_failures_and_missing_page(self):
        self.assertRaises(p.guard.Deny, p.guard.validate_snapshot, None, {},
                          repo=REPO, sha=COMMIT, run_id=RUN, attempt=1,
                          majors=[14,15,16,17,18])
        for status in (401, 403, 404, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(p.Denied):
                self.invoke(api_failure=status)
        # Direct pure contract rejects incomplete, missing, oversized or stale pages.
        run, page = evidence([14,15,16,17,18])
        page["total_count"] = 100
        with self.assertRaises(p.guard.Deny):
            p.guard.validate_snapshot(run, page, repo=REPO, sha=COMMIT,
                                      run_id=RUN, attempt=1, majors=[14,15,16,17,18])

    def test_signed_certificate_wrong_source_signer_run_oidc_or_missing_deny(self):
        changes = (
            ("runInvocationURI", f"https://github.com/{REPO}/actions/runs/{RUN}/attempts/2"),
            ("runInvocationURI", None),
            ("buildSignerURI", "https://github.com/pgextwin/build/.github/workflows/build-extension-attested.yml@refs/heads/main"),
            ("buildSignerDigest", "e"*40),
            ("sourceRepositoryDigest", "c"*40),
            ("sourceRepositoryRef", "refs/heads/fake"),
            ("issuer", "https://evil.example"),
            ("verifiedTimestamps", None))
        for field, value in changes:
            def mock(*args, field=field, value=value):
                if field == "verifiedTimestamps":
                    x = json.loads(valid_gh(*args))
                    x[0]["verificationResult"].pop("verifiedTimestamps")
                    return json.dumps(x)
                return certificate(args[args.index("--predicate-type")+1],
                                   Path(args[3]), mutate=(field, value))
            with self.subTest(field=field), self.assertRaises(p.guard.Deny):
                self.invoke(signed=mock)
        with self.assertRaises(p.guard.Deny):
            self.invoke(signed=lambda *_: "[]")
        with self.assertRaises(p.guard.Deny):
            self.invoke(signed=lambda *_: '{"verificationResult":"forged"}')

    def test_run_metadata_toctou_after_signature_deny(self):
        ext, lc, receipt = oldtests.fixture()
        run, jobs = evidence(receipt["majors"])
        calls = [0]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp); oldtests.make_assets(folder, ext)
            def changing_get(path):
                calls[0] += 1
                if "/jobs?" in path:
                    return copy.deepcopy(jobs)
                value = copy.deepcopy(run)
                if calls[0] >= 3:
                    value["run_attempt"] = 2
                return value
            with patch.object(p, "REPO", REPO), patch.dict(p.os.environ, ENV), patch.object(
                    p, "get", side_effect=changing_get), patch.object(
                    p, "run", side_effect=valid_gh):
                with self.assertRaises(p.guard.Deny):
                    p.check_assets(folder, ext, receipt, COMMIT, RUN, lc)


    def test_observed_v21015_unsigned_dispatch_is_not_a_signed_publisher(self):
        """Fixed authenticated GET identities; purely synthetic denial, no network.

        The successful one-shot candidate is eligible *unsigned* evidence only.
        Even with its real job names and clean result, it has no attested
        main/authorize/publish topology or verified certificates. This test
        NEVER calls the Publisher writer or promotes historical GO A.
        """
        candidate_sha = "4899b5c1da8e2fb681381fff4fa2ab41882cb0bc"
        candidate_run_id = 39021934569
        candidate_run = {
            "id": candidate_run_id, "run_attempt": 1,
            "repository": {"full_name": REPO}, "head_sha": candidate_sha,
            "head_branch": "auto-candidate/29d1c1984a1b44a55107",
            "event": "workflow_dispatch",
            "path": ".github/workflows/windows.yml",
            "status": "completed", "conclusion": "success"}
        candidate_names = [
            "Regression-test immutable Release preflight",
            "windows / Resolve extension and PostgreSQL matrix",
            *[f"windows / PostgreSQL {pg} / Windows x64"
              for pg in range(14, 19)],
            "Windows required summary",
            "Verify PG-major candidate artifacts and annotate owned PR / report",
        ]
        self.assertEqual(len(candidate_names), 9)
        candidate_page = {
            "total_count": 9,
            "jobs": [{"id": 117365321417 + i, "name": name,
                      "run_id": candidate_run_id, "run_attempt": 1,
                      "head_sha": candidate_sha, "status": "completed",
                      "conclusion": "success"}
                     for i, name in enumerate(candidate_names)]
        }
        attempts = [("actual successful unsigned candidate", candidate_run,
                     candidate_page)]
        claimed_main = copy.deepcopy(candidate_run)
        claimed_main.update(head_branch="main",
                            path=p.guard.PROMOTE_PATH,
                            status="in_progress", conclusion=None)
        attempts.append(("forged promotion root, unsigned jobs", claimed_main,
                         candidate_page))
        # Even inventing the signed job names cannot turn a fully completed
        # candidate run into an active, write-isolated prepublish Publisher.
        forged_names = [p.guard.AUTHORIZE, p.guard.RESOLVE, *[
            p.guard.BUILD + f" / PostgreSQL {pg} / Windows x64"
            for pg in range(14, 19)], p.guard.PUBLISH]
        forged_page = {
            "total_count": len(forged_names),
            "jobs": [{"id": 999100 + i, "name": name,
                      "run_id": candidate_run_id, "run_attempt": 1,
                      "head_sha": candidate_sha, "status": "completed",
                      "conclusion": "success"}
                     for i, name in enumerate(forged_names)]
        }
        attempts.append(("forged completed Publisher job", claimed_main,
                         forged_page))
        for label, observed_run, observed_jobs in attempts:
            with self.subTest(case=label), self.assertRaises(p.guard.Deny):
                p.guard.validate_snapshot(
                    copy.deepcopy(observed_run),
                    copy.deepcopy(observed_jobs), repo=REPO,
                    sha=candidate_sha, run_id=candidate_run_id,
                    attempt=1, majors=[14, 15, 16, 17, 18])
        # An unsigned candidate-audit's self-declared VERIFIED status is NOT
        # real zero-exit gh attestation verification, SLSA or signed SPDX.
        fake_audit = json.dumps({"schemaVersion": 1, "status": "VERIFIED",
                                 "matrixResult": "success",
                                 "runId": candidate_run_id})
        with self.assertRaises(p.guard.Deny):
            p.guard.verified_claims(
                fake_audit, predicate=p.guard.PROVENANCE, repo=REPO,
                packaging_sha=candidate_sha, run_id=candidate_run_id,
                attempt=1, zip_name="plpgsql_check-pg14-windows-x64.zip",
                zip_digest="c17fc1a68474452979233a540e704ea376feda3451ce976935b08f01c5a54819",
                sbom={"spdxVersion": "SPDX-2.3"})



if __name__ == "__main__":
    main()
