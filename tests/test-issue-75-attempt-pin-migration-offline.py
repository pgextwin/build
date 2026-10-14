#!/usr/bin/env python3
"""Issue #75 PRE-G4: synthetic hostile future attempt/pin cutover tests only."""
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import importlib.util
import json
from pathlib import Path
from unittest import TestCase, main, mock
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pin_migration", ROOT / "scripts/issue-75-attempt-pin-migration-offline.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

REPO = "pgextwin/plpgsql_check"
PACKAGING = "37cb5ee00f556fd6b57e439a5e19cd210125a571"
UPSTREAM = "ccdbcce9de51f01e1138c270aeb9fe4e26c6e911"
MAJORS = [14, 15, 16, 17, 18]
RUN = 90000000001


def zip_with(pkg):
    io = BytesIO()
    with ZipFile(io, "w") as z:
        z.writestr("PACKAGE-INFO.json", json.dumps(pkg))
    return io.getvalue()


def sample(attempt=1):
    uri = f"https://github.com/{REPO}/actions/runs/{RUN}/attempts/{attempt}"
    signer_uri = ("https://github.com/pgextwin/build/"
                  + m.offline.SIGNER_PATH + "@" + m.SIGNER_SHA)
    cert = {"issuer": m.offline.ISSUER, "runInvocationURI": uri,
            "buildSignerURI": signer_uri, "subjectAlternativeName": signer_uri,
            "buildSignerDigest": m.SIGNER_SHA,
            "sourceRepositoryURI": "https://github.com/" + REPO,
            "sourceRepositoryDigest": PACKAGING,
            "sourceRepositoryRef": "refs/heads/main",
            "buildConfigURI": ("https://github.com/" + REPO + "/"
                               + m.offline.PROMOTE_PATH + "@refs/heads/main"),
            "buildConfigDigest": PACKAGING, "githubWorkflowSHA": PACKAGING,
            "githubWorkflowRef": "refs/heads/main",
            "buildTrigger": "workflow_dispatch"}
    run = {"id": RUN, "run_attempt": attempt, "head_sha": PACKAGING,
           "head_branch": "main", "event": "workflow_dispatch",
           "path": m.offline.PROMOTE_PATH, "repository": {"full_name": REPO},
           "status": "completed", "conclusion": "success"}
    e = {"repo": REPO, "releaseTag": "v2.10.15-windows.1",
         "packagingSha": PACKAGING, "signerSha": m.SIGNER_SHA,
         "legacyPublisherPin": m.MANUAL_PIN, "proposedPublisherPin": None,
         "upstreamByMajor": {pg: UPSTREAM for pg in MAJORS},
         "majors": MAJORS[:], "byMajor": {},
         "runSnapshots": [{"status": 200, "data": deepcopy(run)} for _ in range(2)],
         "tagSnapshots": [{"status": 404} for _ in range(2)],
         "releaseSnapshots": [{"status": 404} for _ in range(2)],
         "writerState": "NOT_STARTED"}
    for pg in MAJORS:
        pkg = {"buildMode": "release-attested", "package": {"name": "plpgsql_check"},
               "postgresql": {"major": pg},
               "source": {"packagingRepository": REPO, "packagingCommit": PACKAGING},
               "upstream": {"commit": UPSTREAM},
               "buildInfrastructure": {"repository": "pgextwin/build",
                   "workflow": m.offline.SIGNER_PATH, "commit": m.SIGNER_SHA},
               "workflowRun": {"id": RUN, "attempt": attempt,
                   "url": f"https://github.com/{REPO}/actions/runs/{RUN}",
                   "event": "workflow_dispatch", "ref": "refs/heads/main"}}
        data = zip_with(pkg)
        sbom = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}
        slsa = {"buildDefinition": {"buildType": "synthetic"},
                "runDetails": {"builder": {"id": "https://github.com/actions/runner"},
                               "metadata": {"invocationId": uri}}}
        proofs = {}
        for kind, predicate in ((m.SLSA, slsa), (m.SPDX, sbom)):
            proofs[kind] = [{"verificationResult": {
                "statement": {"predicateType": kind,
                    "subject": [{"name": f"plpgsql_check-pg{pg}-windows-x64.zip",
                                 "digest": {"sha256": sha256(data).hexdigest()}}],
                    "predicate": deepcopy(predicate)},
                "signature": {"certificate": deepcopy(cert)},
                "verifiedTimestamps": [{"synthetic": True}]}}]
        e["byMajor"][pg] = {"zip": data, "sbom": sbom, "proofs": proofs}
    return e


class InertContract(TestCase):
    def test_nominal_all_pg_mock_stays_blocked(self):
        e = sample()
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("NO GET")), \
             mock.patch("subprocess.run", side_effect=AssertionError("NO COMMAND")):
            got = m.inspect_inert(e)
        self.assertEqual(got["decision"], "BLOCKED")
        self.assertEqual(got["offlineContract"], "PASS")
        self.assertEqual(got["cryptographicVerification"], "NOT_PERFORMED")
        self.assertEqual(got["pinCutover"], "NOT_AUTHORIZED")
        self.assertEqual(got["g4"], "NO_GO")
        self.assertEqual(got["g5"], "NO_GO")
        self.assertIs(got["publishableReceipt"], False)
        self.assertIs(got["mutationsEnabled"], False)
        self.assertEqual(got["publication"], "DENY")
        self.assertEqual(len(got["zipSha256ByMajor"]), 5)

    def test_exact_attempt2_even_consistent_fake_signatures_never_grant_publish(self):
        got = m.inspect_inert(sample(attempt=2))
        self.assertEqual(got["runAttempt"], 2)
        self.assertEqual(got["decision"], "BLOCKED")

    def test_run_api_cross_attempt_boolean_missing_zero_string_and_downstream_failure(self):
        for field, bad in (("run_attempt", 2), ("run_attempt", False),
                           ("run_attempt", None), ("run_attempt", 0),
                           ("run_attempt", "1"), ("run_attempt", "ABSENT"),
                           ("id", RUN + 1), ("conclusion", "failure"),
                           ("conclusion", "neutral"), ("status", "in_progress"),
                           ("event", "push"), ("path", "evil.yml"),
                           ("head_branch", "fork"), ("head_sha", "f"*40),
                           ("repository", {"full_name": "evil/repo"})):
            with self.subTest(field=field, bad=bad):
                e = sample()
                for s in e["runSnapshots"]:
                    if bad == "ABSENT":
                        s["data"].pop(field, None)
                    else:
                        s["data"][field] = bad
                with self.assertRaises(m.Deny):
                    m.inspect_inert(e)

    def test_mixed_attempt_or_id_and_pg_partial_fail_closed(self):
        for field, bad in (("attempt", 2), ("attempt", False),
                           ("attempt", None), ("attempt", 0),
                           ("attempt", "1"), ("attempt", "ABSENT"),
                           ("id", RUN + 1)):
            with self.subTest(field=field, bad=bad):
                e = sample()
                pkg = m.offline.package_from_zip(e["byMajor"][18]["zip"])
                if bad == "ABSENT":
                    del pkg["workflowRun"][field]
                else:
                    pkg["workflowRun"][field] = bad
                e["byMajor"][18]["zip"] = zip_with(pkg)
                with self.assertRaises(m.Deny):
                    m.inspect_inert(e)
        for mutate in (lambda e: e["byMajor"].pop(17),
                       lambda e: e["byMajor"].update({19: e["byMajor"][18]}),
                       lambda e: e["upstreamByMajor"].pop(17),
                       lambda e: e["majors"].append(17),
                       lambda e: e["majors"].append(False)):
            e = sample()
            mutate(e)
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)

    def test_signed_claim_run_attempt_signer_oidc_source_and_caller_are_exact(self):
        cert_fields = {
            "issuer": "https://evil.example",
            "runInvocationURI": f"https://github.com/{REPO}/actions/runs/{RUN}/attempts/2",
            "buildSignerURI": "https://github.com/pgextwin/build/" + m.offline.SIGNER_PATH + "@refs/heads/main",
            "buildSignerDigest": "a"*40, "subjectAlternativeName": "bad",
            "sourceRepositoryURI": "https://github.com/evil/repo",
            "sourceRepositoryDigest": "b"*40, "sourceRepositoryRef": "refs/heads/topic",
            "buildConfigURI": "https://github.com/evil/other.yml@main",
            "buildConfigDigest": "c"*40, "githubWorkflowSHA": "c"*40,
            "githubWorkflowRef": "refs/heads/topic", "buildTrigger": "push"}
        for kind in (m.SLSA, m.SPDX):
            for field, bad in cert_fields.items():
                with self.subTest(kind=kind, field=field):
                    e = sample()
                    e["byMajor"][14]["proofs"][kind][0]["verificationResult"]["signature"]["certificate"][field] = bad
                    with self.assertRaises(m.Deny):
                        m.inspect_inert(e)
            e = sample()
            e["byMajor"][14]["proofs"][kind][0]["verificationResult"]["signature"]["certificate"]["runnerInvocationURI"] = "forged"
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)

    def test_missing_invalid_or_partial_crypto_claims_are_denied(self):
        for kind, field in ((m.SLSA, "signature"), (m.SPDX, "verifiedTimestamps")):
            e = sample()
            del e["byMajor"][15]["proofs"][kind][0]["verificationResult"][field]
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)
        for stamps in ([], None, [None], [{}], "synthetic"):
            e = sample()
            e["byMajor"][15]["proofs"][m.SLSA][0]["verificationResult"]["verifiedTimestamps"] = stamps
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)
        for mutate in (
            lambda p: p.pop(m.SLSA),
            lambda p: p.pop(m.SPDX),
            lambda p: p[m.SLSA].append(deepcopy(p[m.SLSA][0])),
            lambda p: p.update({"unknown": []})):
            e = sample()
            mutate(e["byMajor"][15]["proofs"])
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)

    def test_unsigned_self_claims_do_not_override_signed_identity(self):
        for change in (
            lambda e: e["byMajor"][14]["proofs"][m.SLSA][0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"].update(invocationId="forged"),
            lambda e: e["byMajor"][14]["proofs"][m.SPDX][0]["verificationResult"]["statement"].update(predicate={"spdxVersion": "SPDX-2.3"}),
            lambda e: e["byMajor"][14]["proofs"][m.SLSA][0]["verificationResult"]["statement"]["subject"][0]["digest"].update(sha256="0"*64),
            lambda e: e["byMajor"][14].update(zip=e["byMajor"][14]["zip"]+b"tampered"),
            lambda e: e["byMajor"][14].update(sbom={"spdxVersion": "SPDX-2.3"}),
        ):
            e = sample()
            change(e)
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)

    def test_package_source_event_singer_repo_and_pg_mismatch(self):
        cases = (("workflowRun", "event", "push"),
                 ("workflowRun", "ref", "refs/heads/topic"),
                 ("workflowRun", "url", "wrong"),
                 ("upstream", "commit", "a"*40),
                 ("source", "packagingCommit", "a"*40),
                 ("buildInfrastructure", "commit", "a"*40),
                 ("buildInfrastructure", "workflow", "other.yml"),
                 ("postgresql", "major", True))
        for section, field, bad in cases:
            with self.subTest(section=section, field=field):
                e = sample()
                pkg = m.offline.package_from_zip(e["byMajor"][16]["zip"])
                pkg[section][field] = bad
                e["byMajor"][16]["zip"] = zip_with(pkg)
                with self.assertRaises(m.Deny):
                    m.inspect_inert(e)

    def test_two_get_api_failures_and_stale_tag_release_replay(self):
        for endpoint in ("runSnapshots", "tagSnapshots", "releaseSnapshots"):
            for code in (401, 403, 429, 500, 503):
                with self.subTest(endpoint=endpoint, status=code):
                    e = sample()
                    e[endpoint] = [{"status": code}] * 2
                    with self.assertRaises(m.Deny):
                        m.inspect_inert(e)
            for malformed in (None, [], [None], [{"status": 404}], "timeout"):
                e = sample()
                e[endpoint] = malformed
                with self.assertRaises(m.Deny):
                    m.inspect_inert(e)
            e = sample()
            e[endpoint][1] = {"status": 200, "data": {"changed": True}}
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)
        for endpoint in ("tagSnapshots", "releaseSnapshots"):
            e = sample()
            e[endpoint] = [{"status": 200, "data": {"existing": True}}] * 2
            with self.assertRaises(m.Deny):
                m.inspect_inert(e)

    def test_wrong_pin_policy_and_ambiguous_write_quarantine(self):
        for key, bad in (("legacyPublisherPin", "0"*40),
                         ("signerSha", "a"*40),
                         ("proposedPublisherPin", "main"),
                         ("packagingSha", "short"),
                         ("releaseTag", "v1.0.0-windows.0"),
                         ("repo", "evil/repo")):
            e = sample()
            e[key] = bad
            with self.subTest(key=key), self.assertRaises(m.Deny):
                m.inspect_inert(e)
        e = sample()
        e["proposedPublisherPin"] = "b"*40
        self.assertEqual(m.inspect_inert(e)["pinCutover"], "NOT_AUTHORIZED")
        for state in ("WRITE_ATTEMPTED", "LOST_RESPONSE", "PARTIAL_DRAFT",
                      "UNKNOWN", None):
            e = sample()
            e["writerState"] = state
            with self.subTest(state=state), self.assertRaises(m.UnknownQuarantine):
                m.inspect_inert(e)


if __name__ == "__main__":
    main()
