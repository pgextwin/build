#!/usr/bin/env python3
"""Issue #75 Phase D: inert real-GitHub read-only evidence adapter.

No CLI entrypoint, workflow trigger, release, tag write, or publication receipt.
A future trusted protected-main runner must supply the *actual* GitHub push
event and a ONE-repository short-lived App token. Missing real authorization
or unsigned candidate artifacts fail closed; fixtures never imply acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler
from zipfile import ZipFile, BadZipFile

ROOT = Path(__file__).resolve().parent
REPO = "pgextwin/plpgsql_check"
BASE = "repos/" + REPO + "/"
MAX_JSON = 2 * 1024 * 1024
MAX_PACKAGE = 256 * 1024
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"


class Blocked(ValueError):
    """Missing, ambiguous or unverifiable GitHub evidence."""


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    require(spec is not None and spec.loader is not None, "trusted verifier missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


approval_lib = load("phase_d_live_approval", "chat-pr-authorization.py")
fleet_lib = load("phase_d_live_fleet", "fleet-promotion-gate.py")
classic_lib = load("phase_d_live_classic", "classic-composite-protection.py")
phase_d = load("phase_d_live_jit", "chat-pr-phase-d-prepublish.py")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate GitHub JSON field")
        result[key] = value
    return result


class PilotReadOnly:
    """No arbitrary URL, mutation, redirect, write verb or unbounded JSON."""

    def __init__(self, token):
        require(type(token) is str and bool(token), "short-lived scoped token missing")
        self.token = token
        self._open = build_opener(NoRedirect()).open

    @staticmethod
    def allowed(path, allow_404):
        require(type(path) is str and len(path) < 300, "invalid read path")
        scope = path == "installation/repositories?per_page=100"
        base = re.escape(BASE)
        suffix = path[len(BASE):] if path.startswith(BASE) else ""
        patterns = (
            r"branches/main(?:/protection)?",
            r"commits/[0-9a-f]{40}(?:/pulls)?",
            r"commits/[0-9a-f]{40}/check-runs\?per_page=100",
            r"pulls/[1-9][0-9]*(?:/files\?per_page=100)?",
            r"actions/runs/[1-9][0-9]*",
            r"contents/(?:config/extension\.json|config/release-promotion\.json|\.github/release-authorizations/v[A-Za-z0-9._-]+-windows\.[1-9][0-9]*\.json)\?ref=[0-9a-f]{40}",
            r"git/ref/tags/v[A-Za-z0-9._%-]+",
            r"releases/tags/v[A-Za-z0-9._%-]+",
        )
        valid = scope or (path.startswith(BASE) and any(re.fullmatch(p, suffix) for p in patterns))
        require(valid, "GitHub path not on read-only pilot allowlist")
        if allow_404:
            require(path.startswith(BASE + "git/ref/tags/") or
                    path.startswith(BASE + "releases/tags/"),
                    "404 cannot silently prove missing evidence")

    def get(self, path, *, allow_404=False):
        self.allowed(path, allow_404)
        request = Request(
            "https://api.github.com/" + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
            method="GET",
        )
        try:
            with self._open(request, timeout=20) as response:
                require(response.status == 200, "GitHub read not HTTP 200")
                require('rel="next"' not in response.headers.get("Link", ""),
                        "paginated GitHub response incomplete")
                data = response.read(MAX_JSON + 1)
        except HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            raise Blocked("GitHub REST evidence unavailable") from None
        except (URLError, OSError, TimeoutError):
            raise Blocked("GitHub REST evidence unavailable") from None
        require(len(data) <= MAX_JSON, "oversized GitHub JSON response")
        try:
            return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
        except (UnicodeDecodeError, ValueError, TypeError):
            raise Blocked("invalid GitHub JSON evidence") from None


def trusted_json_file(api, path, ref):
    """Fetch and bind a committed content blob to its independently fetched SHA."""
    require(approval_lib.full_sha(ref), "source commit SHA invalid")
    obj = api.get(BASE + "contents/" + path + "?ref=" + ref)
    require(type(obj) is dict and obj.get("encoding") == "base64"
            and type(obj.get("content")) is str and type(obj.get("sha")) is str,
            "committed file is missing or invalid")
    try:
        raw = base64.b64decode(obj["content"], validate=False)
        require(len(raw) <= MAX_JSON, "committed file too large")
        require(approval_lib.git_blob_sha(raw) == obj["sha"],
                "committed bytes not bound to Git blob SHA")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise Blocked("committed JSON invalid or mismatched") from None


def gh_read(*arguments):
    """Only GH download/attestation verification; never workflow/tag/Release writes."""
    allowed = (arguments[:2] == ("run", "download")
               or arguments[:2] == ("attestation", "verify"))
    require(allowed, "GitHub CLI operation not read-only")
    try:
        result = subprocess.run(
            ("gh",) + arguments, check=False, capture_output=True, timeout=120,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("read-only GitHub artifact operation unavailable") from None
    require(result.returncode == 0, "artifact download/attestation denied")
    # stdout/stderr can include untrusted data: never surface or use as proof.


def one_json(folder):
    files = list(Path(folder).rglob("*.json"))
    require(len(files) == 1 and files[0].is_file(), "missing/duplicate decision JSON")
    require(files[0].stat().st_size <= MAX_JSON, "evidence JSON oversized")
    try:
        return json.loads(files[0].read_text(encoding="utf-8-sig"),
                          object_pairs_hook=unique_object)
    except ValueError:
        raise Blocked("invalid decision JSON") from None


def verified_artifacts(run_id, decision_id, majors, ext, sources, candidate_head, candidate_branch):
    """Download actual candidate evidence; check ZIP bytes and Sigstore signatures.

    A routine green Windows CI with *unsigned* candidate ZIPs will DENY.
    This does not produce a valid release authorization or publisher receipt.
    """
    require(type(run_id) is int and run_id > 0 and
            type(decision_id) is int and decision_id > 0,
            "invalid signed artifact run identities")
    require(type(majors) is list and majors and all(type(x) is int for x in majors),
            "untrusted artifact PG matrix")
    require(type(sources) is dict, "SHA-pinned extension sources missing")
    require(approval_lib.full_sha(candidate_head)
            and type(candidate_branch) is str
            and re.fullmatch(r"auto-candidate/[0-9a-f]{20}", candidate_branch),
            "artifact branch/head not trustworthy")
    digests = {}
    with tempfile.TemporaryDirectory(prefix="pgextwin-issue75-readonly-") as temp:
        folder = Path(temp)
        gh_read("run", "download", str(run_id), "--repo", REPO, "--dir", str(folder / "candidate"))
        gh_read("run", "download", str(decision_id), "--repo", REPO,
                "--name", "candidate-decision", "--dir", str(folder / "decision"))
        gh_read("run", "download", str(run_id), "--repo", REPO,
                "--name", "candidate-audit", "--dir", str(folder / "audit"))
        # The workflow's metadata still needs independent fleet.verify().
        decision = one_json(folder / "decision")
        actual_audit = one_json(folder / "audit")
        require(type(actual_audit) is dict
                and type(actual_audit.get("majors")) is list
                and len(actual_audit["majors"]) == len(majors),
                "candidate-audit matrix missing")
        entries = {x.get("major"): x for x in actual_audit["majors"]
                   if type(x) is dict and type(x.get("major")) is int}
        require(set(entries) == set(majors), "duplicate or unexpected PG majors")
        for major in majors:
            item = entries[major]
            stem = fleet_lib.ident.asset_stem(ext, major)
            expected = (stem + ".zip", stem + ".spdx.json",
                        stem + ".vulnerabilities.json")
            found = []
            for name in expected:
                matches = [p for p in (folder / "candidate").rglob(name) if p.is_file()]
                require(len(matches) == 1, "candidate ZIP/SBOM/Grype absent or duplicated")
                found.append(matches[0])
            zip_path, sbom_path, grype_path = found
            require(item.get("zip") == expected[0]
                    and item.get("sbom") == expected[1]
                    and item.get("grype") == expected[2],
                    "candidate audit filename mismatch")
            with zip_path.open("rb") as asset_stream:
                sha = hashlib.file_digest(asset_stream, "sha256").hexdigest()
            require(item.get("zipSha256") == sha, "candidate ZIP SHA256 mismatch")
            with ZipFile(zip_path, "r") as archive:
                members = [m for m in archive.infolist() if m.filename == "PACKAGE-INFO.json"]
                require(len(members) == 1 and members[0].file_size <= MAX_PACKAGE,
                        "PACKAGE-INFO missing, duplicated or oversized")
                pkg = json.loads(archive.read(members[0]).decode("utf-8-sig"),
                                 object_pairs_hook=unique_object)
            source = sources[major]
            require(type(pkg) is dict and pkg.get("package", {}).get("name") == ext["name"]
                    and pkg.get("postgresql", {}).get("major") == major
                    and pkg.get("upstream", {}).get("commit") == source["commit"]
                    and pkg.get("upstream", {}).get("ref") == source["ref"]
                    and pkg.get("upstream", {}).get("version") == source["version"]
                    and pkg.get("upstream", {}).get("repository") == ext["upstream"]["repository"]
                    and pkg.get("workflowRun", {}).get("id") == run_id
                    and pkg.get("workflowRun", {}).get("event") == "workflow_dispatch"
                    and pkg.get("workflowRun", {}).get("ref") == "refs/heads/" + candidate_branch
                    and pkg.get("source", {}).get("packagingRepository") == REPO
                    and pkg.get("source", {}).get("packagingCommit") == candidate_head,
                    "ZIP PACKAGE-INFO candidate/run/source mismatch")
            require(json.loads(sbom_path.read_text(encoding="utf-8-sig")).get("spdxVersion") == "SPDX-2.3",
                    "invalid SPDX")
            require(type(json.loads(grype_path.read_text(encoding="utf-8-sig")).get("matches")) is list,
                    "invalid Grype report")
            gh_read("attestation", "verify", str(zip_path), "--repo", REPO,
                    "--signer-workflow", SIGNER)
            gh_read("attestation", "verify", str(zip_path), "--repo", REPO,
                    "--signer-workflow", SIGNER, "--predicate-type", SPDX_PREDICATE)
            digests[str(major)] = sha
    return decision, actual_audit, digests


class PhaseDGitHubAdapter:
    """Trusted-runner-only pilot adapter. No __main__; cannot publish.

    event must be read directly from GitHub's authenticated main push event,
    not constructed from PR, chat text, or downloaded candidate data.
    """

    def __init__(self, admin_token, evidence_token, *, event, main_sha, actor, allowed_operators):
        require(type(event) is dict and type(allowed_operators) in (set, frozenset)
                and actor in allowed_operators and approval_lib.human(actor)
                and approval_lib.full_sha(main_sha), "invalid runtime identity")
        self.admin_api = PilotReadOnly(admin_token)
        self.api = PilotReadOnly(evidence_token)
        self.admin_token = admin_token
        self.event = event
        self.sha = main_sha
        self.actor = actor
        self.allowed_operators = allowed_operators
        self.signed_digests = []

    def capture(self):
        base = BASE
        scope = self.admin_api.get("installation/repositories?per_page=100")
        require(type(scope) is dict and type(scope.get("total_count")) is int
                and scope["total_count"] == 1
                and type(scope.get("repositories")) is list
                and len(scope["repositories"]) == 1
                and scope["repositories"][0].get("full_name") == REPO,
                "dedicated token must be scoped to only one repository")
        branch = self.api.get(base + "branches/main")
        require(branch.get("protected") is True and
                branch.get("commit", {}).get("sha") == self.sha, "main advanced/unprotected")
        classic = classic_lib.collect_verified_composite(
            classic_lib.CompositeReader(self.admin_token), expected_main_sha=self.sha)
        require(classic.get("status") == "VERIFIED_CLASSIC_COMPOSITE_READ_ONLY"
                and classic.get("publishableReceipt") is False,
                "fresh same-token Classic policy denied")

        commit = self.api.get(base + "commits/" + self.sha)
        linked = self.api.get(base + "commits/" + self.sha + "/pulls")
        require(type(linked) is list and len(linked) == 1
                and type(linked[0].get("number")) is int,
                "authorization squash PR linkage absent/ambiguous")
        auth_number = linked[0]["number"]
        pr = self.api.get(base + "pulls/" + str(auth_number))
        pr_files = self.api.get(base + "pulls/" + str(auth_number) + "/files?per_page=100")
        path = commit.get("files", [{}])[0].get("filename", "")
        require(type(commit.get("files")) is list and len(commit["files"]) == 1
                and path.startswith(".github/release-authorizations/")
                and path.endswith(".json"), "no unique real authorization file")
        raw_request = self.api.get(base + "contents/" + path + "?ref=" + self.sha)
        require(type(raw_request) is dict and raw_request.get("encoding") == "base64",
                "missing committed authorization blob")
        try:
            raw = base64.b64decode(raw_request["content"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError, TypeError):
            raise Blocked("invalid authorization blob") from None
        require(approval_lib.git_blob_sha(raw.encode("utf-8")) == raw_request.get("sha"),
                "authorization blob mismatch")
        request = json.loads(raw, object_pairs_hook=unique_object)
        require(type(request) is dict, "authorization must be object")
        tag = request.get("releaseTag")
        require(type(tag) is str and approval_lib.TAG.fullmatch(tag),
                "authorization tag invalid")
        # Only a genuine 404 from both APIs can mean that the tag is free.
        q = quote(tag, safe="")
        require(self.api.get(base + "git/ref/tags/" + q, allow_404=True) is None
                and self.api.get(base + "releases/tags/" + q, allow_404=True) is None,
                "tag or Release exists")
        parent = commit.get("parents", [{}])[0].get("sha")
        require(approval_lib.full_sha(parent), "authorization parent unknown")
        ext = trusted_json_file(self.api, "config/extension.json", parent)
        local = trusted_json_file(self.api, "config/release-promotion.json", parent)
        # Only the verified same-token Classic proof can establish effective
        # required checks; no REST optional-field omission is assumed safe.
        protection = self.api.get(base + "branches/main/protection")
        rules = protection.get("required_status_checks", {})
        required = rules.get("checks", [])
        checks = self.api.get(base + "commits/" + pr["head"]["sha"]
                              + "/check-runs?per_page=100")
        require(type(checks) is dict
                and checks.get("total_count") == len(checks.get("check_runs", [])),
                "paginated/ambiguous exact-head required checks")
        names = set(classic_lib.rest.REQUIRED_CONTEXTS)
        require(type(required) is list and len(required) == 8
                and {r.get("context") for r in required} == names
                and all(r.get("app_id") == 15368 for r in required),
                "Classic App-bound required CI changed")
        for rule in required:
            matches = [c for c in checks["check_runs"] if
                       c.get("name") == rule["context"] and
                       c.get("app", {}).get("id") == 15368]
            require(len(matches) == 1
                    and matches[0].get("head_sha") == pr["head"]["sha"]
                    and matches[0].get("conclusion") == "success"
                    and matches[0].get("status") == "completed",
                    "required authorization exact-head CI denied")
        approval = approval_lib.verify_approval(
            raw, repository=REPO, event=self.event, pr=pr, pr_files=pr_files,
            commit=commit, ci={
                "headSha": pr["head"]["sha"],
                "requiredChecks": sorted(names),
                "allRequiredChecksPassed": True,
            },
            effective_rules={
                "protectedMain": True,
                "requiredChecksEnforced": True,
                "restrictDirectPush": True,
            }, allowed_operators=self.allowed_operators)
        pr_number = approval["candidatePr"]
        candidate = self.api.get(base + "pulls/" + str(pr_number))
        candidate_files = self.api.get(base + "pulls/" + str(pr_number)
                                       + "/files?per_page=100")
        run_id, decision_id = approval["candidateRunId"], approval["decisionRunId"]
        windows = self.api.get(base + "actions/runs/" + str(run_id))
        watch = self.api.get(base + "actions/runs/" + str(decision_id))
        policy = json.loads((ROOT.parent / "metadata/release-promotion.json").read_text())
        fleet = json.loads((ROOT.parent / "metadata/automation-fleet.json").read_text())
        lifecycle = json.loads((ROOT.parent / "metadata/postgresql.json").read_text())
        # Live production policies remain manual-dispatch, therefore DENY.
        # Never synthesize a chat-pr opt-in to pass this gate.
        require(policy.get("releasePolicy") == "chat-pr-authorization"
                and local.get("releasePolicy") == "chat-pr-authorization",
                "central/local real chat publication mode disabled")
        majors = fleet_lib.ident.maintained_majors(ext, lifecycle)
        sources = fleet_lib.ident.sources(ext)
        decision, audit, digests = verified_artifacts(
            run_id, decision_id, majors, ext, sources,
            candidate["head"]["sha"], candidate["head"]["ref"])
        receipt = fleet_lib.verify(
            REPO, self.sha, approval["releaseTag"], "PUBLISH", self.actor,
            policy, fleet, local, ext, lifecycle, candidate, candidate_files,
            windows, watch, decision, audit, authorization_mode="chat-pr-authorization")
        self.signed_digests.append(digests)
        # Even independently checked bytes here cannot activate a live
        # publisher: Phase D's synthetic-or-real binding remains INERT.
        return {
            "mainSha": self.sha, "tagRef": "ABSENT", "release": "ABSENT",
            "candidateReceipt": receipt, "approval": approval,
            "classicComposite": classic,
            "artifactSignatures": "NOT_INDEPENDENTLY_VERIFIED",
        }

    def validate(self):
        result = phase_d.verify_inert_prepublication_recheck(
            self, expected_main_sha=self.sha, expected_operator=self.actor)
        require(len(self.signed_digests) == 2
                and self.signed_digests[0] == self.signed_digests[1],
                "candidate ZIP byte digests changed between prepublish reads")
        require(result.get("status") == "DRY_RUN_PHASE_D_RECHECK_ONLY"
                and result.get("publishableReceipt") is False,
                "inert Phase D verification denied")
        return result
