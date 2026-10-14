#!/usr/bin/env python3
"""Synthetic hostile tests ONLY: no test fixture is a cryptographic proof."""
from copy import deepcopy
import importlib.util
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "issue75_live_certificate",
    ROOT / "scripts/issue-75-historical-certificate-readonly.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

URI = f"https://github.com/{m.public.REPO}/actions/runs/{m.RUN_ID}/attempts/1"
NAME = m.public.STEM.format(14) + ".zip"
DIGEST = "a" * 64
SBOM = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}
RUN = {"id": m.RUN_ID, "run_attempt": 1, "head_sha": m.public.TAG_SHA,
       "head_branch": "main", "event": "workflow_dispatch",
       "path": ".github/workflows/promote.yml", "status": "completed",
       "conclusion": "failure", "repository": {"full_name": m.public.REPO}}
CERT = {"issuer": m.offline.ISSUER, "runnerInvocationURI": URI,
        "sourceRepositoryURI": "https://github.com/" + m.public.REPO,
        "sourceRepositoryDigest": m.public.TAG_SHA,
        "sourceRepositoryRef": "refs/heads/main",
        "buildSignerURI": "https://github.com/pgextwin/build/" +
            m.offline.SIGNER_PATH + "@refs/heads/main",
        "buildSignerDigest": m.offline.SIGNER_SHA,
        "buildTrigger": "workflow_dispatch"}


def sample(kind=m.public.SPDX):
    predicate = SBOM if kind == m.public.SPDX else {
        "runDetails": {"builder": {"id": "https://github.com/actions/runner"},
                       "metadata": {"invocationId": URI}},
        "buildDefinition": {"buildType": "synthetic"}}
    return {"verificationResult": {
        "statement": {"predicateType": kind,
                      "subject": [{"name": NAME, "digest": {"sha256": DIGEST}}],
                      "predicate": deepcopy(predicate)},
        "signature": {"certificate": deepcopy(CERT)},
        "verifiedTimestamps": [{"fixture": "NOT REAL SIGNED TIMESTAMP"}]}}


class HistoricalCertificateContract(TestCase):
    def test_only_protected_main_exact_event_sha_attempt(self):
        env = {"GITHUB_REPOSITORY": "pgextwin/build", "GITHUB_EVENT_NAME": "push",
               "GITHUB_REF": "refs/heads/main",
               "GITHUB_WORKFLOW_REF": m.EXPECTED_WORKFLOW,
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
               "GITHUB_ACTOR": "human"}
        branch = {"protected": True, "commit": {"sha": "a" * 40}}
        m.preflight(env, "a" * 40, branch)
        for key, bad in (
            ("GITHUB_REPOSITORY", "pgextwin/evil"), ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF", "refs/heads/topic"),
            ("GITHUB_WORKFLOW_REF", "pgextwin/build/.github/workflows/evil.yml@refs/heads/main"),
            ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_SHA", "b" * 40),
            ("GITHUB_ACTOR", "")):
            with self.subTest(key=key), self.assertRaises(m.public.Deny):
                m.preflight({**env, key: bad}, "a" * 40, branch)
        for bad in ({"protected": False, "commit": {"sha": "a" * 40}},
                    {"protected": True, "commit": {"sha": "b" * 40}}):
            with self.assertRaises(m.public.Deny):
                m.preflight(env, "a" * 40, bad)

    def test_exact_predicate_subject_and_ambiguity(self):
        entry = sample()
        self.assertEqual(m.matching_evidence([entry], m.public.SPDX,
                                              NAME, DIGEST), entry)
        for entries, kind, name, digest in (
            ([], m.public.SPDX, NAME, DIGEST),
            ([entry, entry], m.public.SPDX, NAME, DIGEST),
            ([entry], m.public.PROVENANCE, NAME, DIGEST),
            ([entry], m.public.SPDX, "evil.zip", DIGEST),
            ([entry], m.public.SPDX, NAME, "0" * 64)):
            with self.assertRaises(m.public.Deny):
                m.matching_evidence(entries, kind, name, digest)

    def test_fixture_certificate_fields_are_structurally_checked_not_verified(self):
        for kind in (m.public.PROVENANCE, m.public.SPDX):
            claims = m.certified_claims(sample(kind), predicate=kind,
                                       name=NAME, digest=DIGEST,
                                       sbom=SBOM, run=RUN)
            self.assertEqual(claims["runnerInvocationURI"], URI)
            self.assertEqual(claims["buildSignerDigest"], m.offline.SIGNER_SHA)
        # The pure parser is NOT exposed as live verification, nor a receipt.
        self.assertFalse(hasattr(m, "publish"))
        self.assertFalse(hasattr(m, "authorize"))

    def test_missing_certificate_timestamp_and_uri_fail_closed(self):
        for label in ("no-signature", "no-certificate", "no-timestamps",
                      "no-attempt", "unknown-schema"):
            item = sample()
            v = item["verificationResult"]
            if label == "no-signature":
                v.pop("signature")
            elif label == "no-certificate":
                v["signature"].pop("certificate")
            elif label == "no-timestamps":
                v["verifiedTimestamps"] = []
            elif label == "no-attempt":
                v["signature"]["certificate"]["runnerInvocationURI"] = URI.split("/attempts/")[0]
            else:
                v["signature"]["certificate"].pop("sourceRepositoryDigest")
            with self.subTest(label=label), self.assertRaises(m.Blocked):
                m.certified_claims(item, predicate=m.public.SPDX, name=NAME,
                                   digest=DIGEST, sbom=SBOM, run=RUN)

    def test_wrong_oidc_source_signer_sha_run_attempt_and_spdx_deny(self):
        cases = (
            ("issuer", "https://evil.example"),
            ("sourceRepositoryDigest", "b" * 40),
            ("sourceRepositoryRef", "refs/heads/evil"),
            ("sourceRepositoryURI", "https://github.com/evil/repo"),
            ("buildSignerURI", "https://github.com/evil/forged.yml"),
            ("buildSignerDigest", "c" * 40),
            ("buildTrigger", "push"),
            ("runnerInvocationURI", URI[:-1] + "2"))
        for field, wrong in cases:
            item = sample()
            item["verificationResult"]["signature"]["certificate"][field] = wrong
            with self.subTest(field=field), self.assertRaises(
                    (m.public.Deny, m.offline.Deny)):
                m.certified_claims(item, predicate=m.public.SPDX, name=NAME,
                                   digest=DIGEST, sbom=SBOM, run=RUN)
        for field, bad in (("run_attempt", 2), ("head_sha", "d" * 40),
                           ("path", "wrong"), ("repository", {"full_name": "evil/repo"})):
            with self.assertRaises((m.public.Deny, m.offline.Deny)):
                m.certified_claims(sample(), predicate=m.public.SPDX, name=NAME,
                                   digest=DIGEST, sbom=SBOM, run={**RUN, field: bad})
        with self.assertRaises(m.offline.Deny):
            m.certified_claims(sample(), predicate=m.public.SPDX, name=NAME,
                               digest=DIGEST, sbom={"spdxVersion": "SPDX-2.2"}, run=RUN)

    def test_restrict_cli_to_read_only_introspection(self):
        for args in (("api", "repos/pgextwin/build/issues/75/comments"),
                     ("workflow", "run", "promote.yml"), ("release", "create"),
                     ("api", "-X", "POST"), ("auth", "login")):
            with self.assertRaises(m.public.Deny):
                m.read_only_gh(*args)
        with mock.patch.object(m.subprocess, "run", side_effect=OSError("offline")):
            with self.assertRaises(m.Blocked):
                m.read_only_gh("--version")

    def test_release_metadata_rejects_asset_digest_or_id_change(self):
        rel = {"id": 409572202, "tag_name": m.public.TAG,
               "target_commitish": m.public.TAG_SHA, "draft": False,
               "prerelease": False, "updated_at": "2026-10-11",
               "assets": [{"id": 1, "name": "a.zip", "size": 1,
                           "digest": "sha256:" + DIGEST,
                           "state": "uploaded", "updated_at": "2026-10-11"}]}
        self.assertEqual(m.release_identity(rel), m.release_identity(deepcopy(rel)))
        altered = deepcopy(rel)
        altered["assets"][0]["digest"] = "sha256:" + "0" * 64
        self.assertNotEqual(m.release_identity(rel), m.release_identity(altered))


if __name__ == "__main__":
    main()
