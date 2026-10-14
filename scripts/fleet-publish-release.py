#!/usr/bin/env python3
"""All 14 extensions: create-only, manual-PUBLISH attested Release publisher.

A reserved tag or partial draft is quarantined; reruns MUST fail closed.
Release state and every GitHub asset digest are independently verified before and
after publishing by immutable Release ID. This script NEVER schedules itself.
"""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from zipfile import ZipFile

REPO = os.environ.get("GITHUB_REPOSITORY", "")
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"
ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("fleet_identity", ROOT / "fleet-release-identity.py")
ident = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ident)
_guard_spec = importlib.util.spec_from_file_location(
    "pre_g4_publisher_guard", ROOT / "issue-75-publisher-preflight.py")
guard = importlib.util.module_from_spec(_guard_spec)
_guard_spec.loader.exec_module(guard)
_auth_spec = importlib.util.spec_from_file_location("typed_release_auth", ROOT / "release-authorization.py")
auth = importlib.util.module_from_spec(_auth_spec)
_auth_spec.loader.exec_module(auth)

class Denied(ValueError): pass

def check(x, message):
    if not x: raise Denied(message)

def run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        raise Denied("command failed: " + " ".join(args[:3]) + " " + p.stderr[:250])
    return p.stdout

def digest(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda: f.read(1024 * 1024), b""): h.update(c)
    return h.hexdigest()

def get(path):
    req = Request("https://api.github.com/repos/" + REPO + "/" + path,
                  headers={"Authorization":"Bearer " + os.environ["GH_TOKEN"],
                           "Accept":"application/vnd.github+json"})
    try:
        with urlopen(req, timeout=25) as resp:
            check(resp.status == 200, "ambiguous GitHub response")
            # A partial Release inventory can hide an existing tag or Draft;
            # deny rather than trusting the first page of mutable GitHub data.
            link = resp.headers.get("Link", "")
            check(not re.search(r'\brel\s*=\s*"?next"?', link, re.I),
                  "paginated GitHub Release/asset history is not authoritative")
            return json.load(resp)
    except HTTPError as e:
        if e.code == 404: return None
        raise Denied("GitHub API failed HTTP " + str(e.code)) from e

def absent(tag):
    for path in ("releases/tags/","git/ref/tags/"):
        check(get(path+quote(tag,safe="")) is None, "existing tag/release forbidden")

def check_assets(folder, ext, receipt, commit, run_id, lifecycle, verify_signatures=True,
                 workflow_event="workflow_dispatch"):
    # Do not trust the authorization receipt without independently matching all
    # immutable source identities, lifecycle, package metadata and zip digests.
    try:
        auth.validate_receipt(receipt, repository=REPO, commit=commit,
                              actor=receipt.get("operator"), event=workflow_event)
    except auth.Denied as e:
        raise Denied("invalid typed authorization: " + str(e)) from e
    # A Chat PR receipt must never turn run-metadata SUCCESS into artifact
    # attestation success by calling this verifier in a test/bypass mode.
    if receipt.get("authorizationMode") == "chat-pr-authorization":
        check(verify_signatures is True,
              "Chat PR publication requires independent ZIP/SPDX attestations")
    check(receipt.get("schemaVersion") == 1
          and isinstance(receipt.get("operator"), str)
          and bool(receipt["operator"])
          and receipt.get("repository") == REPO
          and receipt.get("trustedCommit") == commit
          and ext.get("name") == receipt.get("extension")
          and isinstance(receipt.get("majors"), list)
          and receipt["majors"] == sorted(set(receipt["majors"]))
          and bool(receipt["majors"]), "invalid authorization receipt")
    try:
        ident.validate_release_tag(ext, receipt["releaseTag"])
        configured = ident.sources(ext)
        maintained = ident.maintained_majors(ext, lifecycle)
        expected_sources = [configured[n] for n in maintained]
        expected_files = ident.expected_assets(ext, maintained) - {"SHA256SUMS.txt"}
    except (ident.Denied, KeyError, ValueError, TypeError) as e:
        raise Denied("untrusted source identity: " + str(e)) from e
    check(receipt["majors"] == maintained and receipt.get("sources") == expected_sources,
          "receipt source pins or maintained PostgreSQL matrix mismatch")
    check({p.name for p in folder.iterdir() if p.is_file()} == expected_files,
          "partial/extra major release files")
    # Existing manual Publisher runs *while* root Actions status is in_progress.
    # Authenticated attempt-scoped jobs, not root completion, are the prewrite gate.
    attempt = None
    initial_snapshot = None
    if verify_signatures:
        attempt = guard.attempt_from_env(os.environ, run_id, REPO)
        initial_snapshot = guard.validate_snapshot(
            get("actions/runs/" + str(run_id)),
            get("actions/runs/" + str(run_id) + "/attempts/" +
                str(attempt) + "/jobs?per_page=100"),
            repo=REPO, sha=commit, run_id=run_id, attempt=attempt,
            majors=maintained)
    before_hashes = {name: digest(folder / name) for name in expected_files}
    package_attempt = None
    for major in maintained:
        source = configured[major]
        stem = ident.asset_stem(ext, major)
        zip_path = folder / (stem + ".zip")
        spdx_path = folder / (stem + ".spdx.json")
        grype_path = folder / (stem + ".vulnerabilities.json")
        with ZipFile(zip_path) as z:
            check(z.namelist().count("PACKAGE-INFO.json") == 1,
                  "missing/duplicate package identity")
            pkg = json.loads(z.read("PACKAGE-INFO.json").decode("utf-8-sig"),
                             object_pairs_hook=guard._unique)
        wf = pkg.get("workflowRun") if type(pkg) is dict else None
        check(type(wf) is dict and guard.positive(wf.get("attempt")),
              "missing/bool/string/zero PACKAGE-INFO.workflowRun.attempt")
        if package_attempt is None:
            package_attempt = wf["attempt"]
        check(package_attempt == wf["attempt"], "mixed PG run attempts")
        if verify_signatures:
            check(wf["attempt"] == attempt, "package vs authenticated run attempt")
        guard.validate_pkg(pkg, major=major, repo=REPO,
                           packaging_sha=commit, upstream_sha=source["commit"],
                           run_id=run_id, attempt=package_attempt)
        check(pkg.get("buildMode") == "release-attested"
              and pkg["package"]["name"] == ext["name"]
              and pkg["postgresql"]["major"] == major
              and pkg["upstream"]["repository"] == ext["upstream"]["repository"]
              and pkg["upstream"]["commit"] == source["commit"]
              and pkg["upstream"]["ref"] == source["ref"]
              and pkg["upstream"]["version"] == source["version"]
              and pkg["source"]["packagingRepository"] == REPO
              and pkg["source"]["packagingCommit"] == commit
              and pkg["workflowRun"]["id"] == run_id
              and pkg["workflowRun"]["event"] == workflow_event
              and pkg["workflowRun"]["ref"] == "refs/heads/main",
              "package identity, source pin, run, or major mismatch")
        check(json.loads(spdx_path.read_text(encoding="utf-8-sig")).get("spdxVersion") == "SPDX-2.3",
              "invalid SPDX SBOM")
        check(isinstance(json.loads(grype_path.read_text(encoding="utf-8-sig")).get("matches"), list),
              "invalid Grype vulnerability report")
        if verify_signatures:
            sbom = json.loads(spdx_path.read_text(encoding="utf-8-sig"),
                              object_pairs_hook=guard._unique)
            zip_hash = before_hashes[zip_path.name]
            # Only zero-exit actual gh CLI verification supplies trust. Parsing
            # forged verificationResult JSON alone NEVER authenticates bytes.
            for kind in (guard.PROVENANCE, guard.SPDX):
                verified = run(
                    "gh", "attestation", "verify", str(zip_path),
                    "--repo", REPO, "--signer-workflow", SIGNER,
                    "--signer-digest", guard.SIGNER_SHA,
                    "--source-digest", commit, "--source-ref", "refs/heads/main",
                    "--predicate-type", kind, "--format", "json")
                guard.verified_claims(
                    verified, predicate=kind, repo=REPO, packaging_sha=commit,
                    run_id=run_id, attempt=attempt, zip_name=zip_path.name,
                    zip_digest=zip_hash, sbom=sbom)
                check(digest(zip_path) == zip_hash and
                      digest(spdx_path) == before_hashes[spdx_path.name],
                      "local ZIP/SPDX modified during signed verification")
    check({name: digest(folder / name) for name in expected_files} == before_hashes,
          "local release assets changed during preflight")
    if verify_signatures:
        final_snapshot = guard.validate_snapshot(
            get("actions/runs/" + str(run_id)),
            get("actions/runs/" + str(run_id) + "/attempts/" +
                str(attempt) + "/jobs?per_page=100"),
            repo=REPO, sha=commit, run_id=run_id, attempt=attempt,
            majors=maintained)
        check(initial_snapshot == final_snapshot,
              "Actions run/job attempt changed during signature verification")
    return before_hashes

def staged_release_id(tag, commit):
    # GitHub's releases/tags/{tag} endpoint can return HTTP 404 for an
    # authenticated DRAFT even when the tag, draft and assets exist. A newly
    # reserved tag must resolve to exactly one draft; never infer a release by
    # display title or treat a tag lookup 404 as evidence of draft absence.
    releases = get("releases?per_page=100")
    check(isinstance(releases, list), "cannot enumerate staged Releases")
    check(len(releases) < 100,
          "potentially incomplete first page of staged Release history")
    matches = [r for r in releases if r.get("tag_name") == tag]
    check(len(matches) == 1, "missing or ambiguous freshly staged Release")
    release = matches[0]
    check(release.get("draft") is True
          and release.get("target_commitish") == commit
          and isinstance(release.get("id"), int)
          and release["id"] > 0, "staged Release identity does not match this run")
    return release["id"]


def check_remote(tag, expected, draft, release_id):
    # Use the immutable release ID, not tag lookup, to validate a draft.
    # A public Release must ALSO resolve by its tag.
    check(isinstance(release_id, int) and release_id > 0, "invalid staged Release ID")
    release = get("releases/" + str(release_id))
    check(release and release.get("id") == release_id
          and release.get("draft") is draft and release.get("tag_name") == tag,
          "release state mismatch")
    if not draft:
        by_tag = get("releases/tags/" + quote(tag, safe=""))
        check(by_tag and by_tag.get("id") == release_id
              and by_tag.get("draft") is False,
              "published Release is not discoverable by its immutable tag")
    check(isinstance(release.get("assets"), list)
          and all(isinstance(a, dict) and isinstance(a.get("name"), str)
                  for a in release["assets"]),
          "invalid GitHub Release assets")
    assets = {a["name"]: a for a in release["assets"]}
    check(len(assets) == len(release["assets"]),
          "duplicate GitHub Release asset names")
    check(set(assets) == set(expected)
          and all(a.get("state") == "uploaded" for a in assets.values()),
          "partial or unexpected published assets")
    for name, expected_sha in expected.items():
        a = assets[name]
        # GitHub reports SHA-256 of the actual uploaded asset, including drafts.
        # This avoids tag-name download APIs that cannot resolve draft releases.
        check(a.get("digest") == "sha256:" + expected_sha,
              "GitHub-hosted asset SHA mismatch: " + name)
        if not draft:
            with tempfile.TemporaryDirectory() as d:
                run("gh","release","download",tag,"--repo",REPO,
                    "--pattern",name,"--dir",d)
                check(digest(Path(d)/name) == expected_sha,
                      "remote SHA mismatch: " + name)

def main():
    p=argparse.ArgumentParser()
    for n in ("receipt","manifest","tag","dist","recovery","lifecycle"):
        p.add_argument("--"+n,required=True)
    a=p.parse_args()
    stage="STARTED"
    try:
        check(REPO in {"pgextwin/" + name for name in ident.UPSTREAMS}
              and os.environ.get("GITHUB_REPOSITORY")==REPO
              and os.environ.get("GITHUB_REF")=="refs/heads/main", "untrusted publishing origin")
        receipt=json.loads(Path(a.receipt).read_text())
        ext=json.loads(Path(a.manifest).read_text())
        check(a.tag==receipt["releaseTag"],"tag does not match authorization receipt")
        commit=os.environ["GITHUB_SHA"]
        try:
            auth.validate_receipt(receipt, repository=REPO, commit=commit,
                                  actor=os.environ.get("GITHUB_ACTOR", ""),
                                  event=os.environ.get("GITHUB_EVENT_NAME", ""))
        except auth.Denied as e:
            raise Denied("untrusted publisher origin: " + str(e)) from e
        folder=Path(a.dist)
        lifecycle=json.loads(Path(a.lifecycle).read_text(encoding="utf-8"))
        expected=check_assets(folder,ext,receipt,commit,int(os.environ["GITHUB_RUN_ID"]),lifecycle,
                              workflow_event=os.environ.get("GITHUB_EVENT_NAME",""))
        absent(a.tag)
        (folder/"SHA256SUMS.txt").write_text("".join(
            value+"  "+name+"\n" for name,value in sorted(expected.items())),encoding="ascii")
        expected["SHA256SUMS.txt"]=digest(folder/"SHA256SUMS.txt")
        notes=Path(a.recovery).with_suffix(".md")
        notes.write_text("# "+ext["name"]+" Windows x64\n\n"
            +"Unofficial Windows x64 binaries built from per-PostgreSQL SHA-pinned upstream sources. "
            +"All maintained requested PG majors were smoke-tested; SPDX 2.3 SBOM, report-only Grype, "
            +"signed provenance, signed SBOM attestations and SHA256SUMS included.\n"
            +"非公式Windows x64バイナリです。対応するPG14〜18と検証可能な証明を含みます。\n",encoding="utf-8")
        def state(s):
            nonlocal stage
            stage=s
            Path(a.recovery).write_text(json.dumps(
                {"schemaVersion":1,"state":stage,"tag":a.tag,"runId":int(os.environ["GITHUB_RUN_ID"]),
                 "commit":commit},indent=2)+"\n")
        state("PREFLIGHT_OK")
        # Exclusive tag reservation: a second concurrent writer cannot create the same tag.
        run("gh","api","-X","POST","repos/"+REPO+"/git/refs",
            "-f","ref=refs/tags/"+a.tag,"-f","sha="+commit)
        state("TAG_RESERVED")
        run("gh","release","create",a.tag,
            *[str(folder/name) for name in sorted(expected)],
            "--repo",REPO,"--verify-tag","--draft","--target",commit,
            "--title",a.tag,"--notes-file",str(notes))
        state("DRAFT_STAGED")
        release_id = staged_release_id(a.tag, commit)
        check_remote(a.tag, expected, True, release_id)
        state("DRAFT_VERIFIED")
        # Publish exactly the release ID that this run created and verified.
        # Never resolve a draft by its tag or edit an unrelated Release.
        run("gh","api","-X","PATCH",
            "repos/"+REPO+"/releases/"+str(release_id),
            "-F","draft=false")
        state("PUBLISHED_AUDIT_PENDING")
        check_remote(a.tag, expected, False, release_id)
        state("PUBLISHED_VERIFIED")
        print("Formal Release verified: "+a.tag)
        return 0
    except (Denied,KeyError,ValueError,OSError,TypeError,IndexError,HTTPError) as e:
        print("RELEASE DENIED at "+stage+": "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__": sys.exit(main())
