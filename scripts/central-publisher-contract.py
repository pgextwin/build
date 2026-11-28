#!/usr/bin/env python3
"""Read-only admission and artifact binding for the central Release publisher."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
import zipfile

from jsonschema import Draft202012Validator

auth = import_module("central-signing-auth")
audit = import_module("central-signed-main-audit")
identity = import_module("fleet-release-identity")
k3 = import_module("verify-central-k3-admission")
package = import_module("central-package")
scope = import_module("publisher-scoped-token")
trigger = import_module("publisher-trigger-auth")
issuance = import_module("local-auth-issuance")

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = auth.REPOSITORY
REPO = f"repos/{REPOSITORY}"
PIN = "6ab938800d686240b5d18248bd73bf8deef31d23"
API = "https://api.github.com"
PREFIX = "/pgextwin publish-central "
MARKER = "PGEXTWIN_CENTRAL_SIGNED_PROVENANCE_V1 "
EXTENSION = r"[a-z][a-z0-9_-]{0,63}"
POSITIVE = r"[1-9][0-9]{0,18}"
MALFORMED = "CPUB_MALFORMED_TRIGGER"
EXT = "CPUB_EXTENSION_MISMATCH"
PG = "CPUB_PG_MAJOR_MISMATCH"
SHA = "CPUB_PROTECTED_SHA_MISMATCH"
RUN = "CPUB_SIGNING_RUN_MISMATCH"
ATTEMPT = "CPUB_ATTEMPT_MISMATCH"
TAG = "CPUB_INVALID_OD01_TAG"
LAYOUT = "CPUB_ARTIFACT_LAYOUT_INVALID"
K3 = "CPUB_K3_ADMISSION_DENIED"
POLICY = "CPUB_POLICY_NOT_ENABLED"
UNAUTHORIZED = "CPUB_UNAUTHORIZED_ACTOR"
READ = "CPUB_GITHUB_READ_FAILED"
PREWRITE = "DUPLICATE_PREWRITE_GET_DENIED"
WRITER = "DUPLICATE_WRITER_ABSENT_DENIED"
UNKNOWN = "WRITE_OUTCOME_UNKNOWN_QUARANTINED"
FIELDS = {
    "ext": (EXTENSION, EXT), "pg": (r"[1-9][0-9]{0,2}", PG),
    "sha": (auth.SHA, SHA), "run": (POSITIVE, RUN), "attempt": (POSITIVE, ATTEMPT),
    "tag": (r"[A-Za-z0-9_./-]{1,128}", TAG),
}


class Denied(ValueError):
    def __init__(self, code, detail=""):
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def require(condition, code, detail=""):
    if not condition:
        raise Denied(code, detail)


@contextmanager
def reject_as(code):
    try:
        yield
    except Denied:
        raise
    except (ValueError, KeyError, OSError, TypeError, RuntimeError, EOFError,
            zipfile.BadZipFile, subprocess.SubprocessError):
        raise Denied(code) from None


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Denied(MALFORMED, message)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def read_json(path, code):
    with reject_as(code):
        return auth.parse_json(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    k3.write_result(path, value)


def digest(value):
    return hashlib.sha256(json_bytes(value)).hexdigest()


def positive(value):
    return type(value) is int and value > 0


def parse_trigger(text):
    require(isinstance(text, str), MALFORMED)
    require(not any(ord(char) < 32 or ord(char) > 126 for char in text), MALFORMED)
    text = text.strip(" ")
    require(text != PREFIX.rstrip(), MALFORMED)
    require(text.startswith(PREFIX), "CPUB_LEGACY_CONTRACT_REJECTED")
    require(not re.search(r"[;|&<>`$(){}\\'\"!]", text), MALFORMED)
    result = {}
    for token in text[len(PREFIX):].split():
        key, sep, value = token.partition("=")
        require(sep and key in FIELDS and key not in result, MALFORMED)
        pattern, code = FIELDS[key]
        require(auth.matches(pattern, value), code)
        result[key] = int(value) if key in ("pg", "run", "attempt") else value
    require(result.keys() == FIELDS.keys(), MALFORMED)
    tag_suffix(result["ext"], result["tag"])
    return result


def tag_suffix(extension, tag):
    name, slash, suffix = tag.partition("/")
    require(name == extension and slash and identity.TAG_NAME.fullmatch(suffix), TAG)
    return suffix


def release_tag(declaration, number):
    require(positive(number), TAG)
    with reject_as(TAG):
        suffix = f"{identity.tag_stem(declaration)}-windows.{number}"
        identity.validate_release_tag(declaration, suffix)
    return f"{declaration['name']}/{suffix}"


def verify_tag(request, declaration):
    require(declaration.get("name") == request["ext"], EXT)
    suffix = tag_suffix(request["ext"], request["tag"])
    require(release_tag(declaration, int(suffix.rsplit(".", 1)[1])) == request["tag"], TAG)


class GitHub:
    """Bounded GETs. A 404 is a result only for optional resource probes."""

    def __init__(self, token, base=API):
        self.base = base.rstrip("/")
        self.token = token

    def get(self, path, *, missing=False):
        with reject_as(READ):
            request = Request(f"{self.base}/{path}", headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json", "User-Agent": "pgextwin-central-publisher",
            })
            try:
                with urlopen(request, timeout=30) as response:
                    raw = response.read(16 * 1024 * 1024 + 1)
                    require(response.status == 200 and len(raw) <= 16 * 1024 * 1024, READ)
                    value = auth.parse_json(raw.decode("utf-8"))
                    require(value is not None, READ)
                    return value
            except HTTPError as error:
                if missing and error.code == 404:
                    return None
                raise Denied(READ, f"HTTP {error.code}") from None

    def archive(self, endpoint, destination):
        # gh follows the GitHub artifact redirect. No destination comes from
        # the artifact or API response.
        with destination.open("wb") as out:
            env = dict(os.environ, GH_TOKEN=self.token, GH_PROMPT_DISABLED="1", GH_DEBUG="")
            result = subprocess.run(
                ["gh", "api", "--hostname", "github.com", "--method", "GET", endpoint],
                stdout=out, stderr=subprocess.DEVNULL, timeout=120, env=env)
        require(result.returncode == 0, LAYOUT, "artifact download failed")


def authorized_request(env, api, body):
    with reject_as(UNAUTHORIZED):
        comment = trigger.owner_issue_comment(env)
        event = trigger.payload(env)
        issue = event["issue"]
        require("pull_request" not in issue and issue.get("state") == "open"
                and auth.object_or_empty(event.get("repository")).get("full_name") == REPOSITORY
                and comment.get("body") == body and comment.get("author_association") == "OWNER"
                and isinstance(comment.get("created_at"), str)
                and comment["created_at"] == comment.get("updated_at")
                and env.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{trigger.WORKFLOW}@{auth.REF}"
                and env.get("GITHUB_WORKFLOW_SHA") == env.get("GITHUB_SHA"), UNAUTHORIZED)
        live = api.get(f"{REPO}/issues/comments/{comment['id']}")
        live_issue = api.get(f"{REPO}/issues/{trigger.ISSUE}")
        require(live_issue.get("state") == "open" and "pull_request" not in live_issue
                and live.get("id") == comment["id"] and trigger.owner(live.get("user"))
                and all(live.get(key) == comment.get(key) for key in (
                    "body", "issue_url", "created_at", "updated_at", "author_association")),
                UNAUTHORIZED)
    return parse_trigger(body)


def check_main(request, expected_sha, api):
    require(request["sha"] == expected_sha, SHA)
    with reject_as(SHA):
        branch = api.get(k3.MAIN_ENDPOINT)
        require(branch.get("protected") is True and branch.get("name") == "main"
                and branch.get("commit", {}).get("sha") == expected_sha, SHA)


def check_run(run, request, *, completed):
    require(type(run.get("id")) is int and run["id"] == request["run"], RUN)
    require(type(run.get("run_attempt")) is int and run["run_attempt"] == request["attempt"]
            and request["attempt"] == 1, ATTEMPT)
    require(run.get("head_sha") == request["sha"], SHA)
    if completed:
        require(run.get("status") == "completed" and run.get("conclusion") == "success", RUN)
    with reject_as(K3):
        require(run.get("path") in (auth.CALLER, f"{auth.CALLER}@{auth.REF}")
                and run.get("head_branch") == "main"
                and auth.object_or_empty(run.get("repository")).get("full_name") == REPOSITORY
                and run.get("event") in auth.CENTRAL_AUTHENTIC_EVENTS, K3)
        audit.referenced_workflow(run.get("referenced_workflows"), PIN)
    return run


def signing_run(api, request):
    endpoint = f"{REPO}/actions/runs/{request['run']}"
    latest = check_run(api.get(endpoint), request, completed=True)
    attempt = check_run(api.get(f"{endpoint}/attempts/{request['attempt']}"), request, completed=True)
    require(all(attempt.get(key) == latest.get(key) for key in ("event", "actor")), RUN)
    return attempt


def check_policy(path, extension):
    # The protected K3 registry has a closed schema. The central build row is
    # explicit about publication and the extension row explicitly opts in.
    with reject_as(POLICY):
        fleet = read_json(path, POLICY)
        rows = k3.fleet_policy.validate_registry(fleet)
        require(rows.get(REPOSITORY, {}).get("reason") == "Central Publisher enabled"
                and rows.get(f"pgextwin/{extension}", {}).get("reason") == "Central publication enabled",
                POLICY)
        scope.valid_fleet(fleet, REPOSITORY, release_policy=fleet["releasePolicy"])
        return fleet


def artifact_names(extension, major):
    suffix = f"{extension}-pg{major}"
    return tuple(f"central-{kind}-{suffix}" for kind in ("unsigned", "signed", "claims"))


def regular_files(folder, code=LAYOUT):
    folder = k3.safe_path(folder, code)
    require(folder.is_dir(), code)
    files = {item.name: item for item in folder.iterdir()}
    require(all(not item.is_symlink() and item.is_file() for item in files.values()), code)
    return files


def intent_root(directory):
    directory = Path(directory)
    # The production artifact uploads intent/ as its root. Also accept a
    # containing directory when loading an already unpacked workspace.
    wrapped = directory / "intent"
    return wrapped if wrapped.is_dir() else directory


def intent_series(directory, request):
    with reject_as(LAYOUT):
        root = k3.safe_path(intent_root(directory), LAYOUT)
        folder = root / request["ext"]
        require(folder.is_dir() and not folder.is_symlink(), EXT)
        require([p.name for p in root.iterdir() if p.name.casefold() == folder.name.casefold()]
                == [folder.name], EXT)
        result = {}
        for item in folder.iterdir():
            require(auth.matches(FIELDS["pg"][0], item.name), PG)
            files = regular_files(item)
            require(files.keys() == {auth.INTENT_NAME}, LAYOUT)
            value = read_json(files[auth.INTENT_NAME], LAYOUT)
            for key, expected, code in (
                ("extension_name", request["ext"], EXT), ("head_sha", request["sha"], SHA),
                ("run_id", request["run"], RUN), ("run_attempt", request["attempt"], ATTEMPT),
                ("reusable_pin_sha", PIN, K3),
            ):
                require(type(value.get(key)) is type(expected) and value[key] == expected, code)
            with reject_as(K3):
                result[int(item.name)] = auth.validate_intent(value)
        require(request["pg"] in result, PG)
        return result


def artifact_folder(root, name, *, single, extension):
    path = Path(root)
    if path.name == name:
        return path
    named = path / name
    if named.is_dir():
        return named
    require(not path.name.startswith("central-"), EXT)
    require(not any(p.is_dir() and p.name.startswith("central-") and
                    f"-{extension}-pg" not in p.name for p in path.iterdir()), EXT)
    require(single and not any(p.is_dir() for p in path.iterdir()), LAYOUT)
    return path


def check_artifact_roster(root, kind, extension, majors):
    pattern = re.compile(rf"central-{kind}-({EXTENSION})-pg([1-9][0-9]*)")
    entries = [match for path in Path(root).iterdir() if (match := pattern.fullmatch(path.name))]
    if entries:
        require(all(entry[1] == extension for entry in entries), EXT)
        require({entry[2] for entry in entries} == {str(major) for major in majors}, LAYOUT)


def artifact_row(api, repo, run_id, name):
    listing = api.get(f"{repo}/actions/runs/{run_id}/artifacts?" +
                      urlencode({"name": name, "per_page": 100}))
    rows = listing.get("artifacts")
    require(type(rows) is list and listing.get("total_count") == len(rows) == 1, LAYOUT, name)
    row = rows[0]
    require(row.get("name") == name and row.get("expired") is False
            and positive(row.get("id")) and positive(row.get("size_in_bytes"))
            and auth.matches(r"sha256:[0-9a-f]{64}", row.get("digest")), LAYOUT, name)
    binding = row.get("workflow_run")
    if binding is not None:
        require(binding.get("id") == run_id, RUN)
    return row


def unpack_artifact(api, repo, row, destination, *, limit):
    destination.mkdir()
    with TemporaryDirectory() as tmp:
        archive = Path(tmp) / "download.zip"
        require(row["size_in_bytes"] <= limit, LAYOUT)
        api.archive(f"{repo}/actions/artifacts/{row['id']}/zip", archive)
        require(archive.stat().st_size == row["size_in_bytes"]
                and "sha256:" + package.sha256_file(archive) == row["digest"], LAYOUT)
        with zipfile.ZipFile(archive) as zipped:
            seen = set()
            files = [item for item in zipped.infolist() if not item.is_dir()]
            require(0 < len(files) <= 2048 and sum(item.file_size for item in files) <= limit, LAYOUT)
            for item in files:
                names = item.filename.split("/")
                require(all(auth.matches(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", part) for part in names)
                        and len(names) <= 3 and item.filename.casefold() not in seen
                        and not stat.S_ISLNK(item.external_attr >> 16), LAYOUT)
                seen.add(item.filename.casefold())
                target = destination.joinpath(*names)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(item) as source, target.open("xb") as out:
                    shutil.copyfileobj(source, out)


def download_artifacts(api, request, scratch):
    with reject_as(LAYOUT):
        def download(name):
            row = artifact_row(api, REPO, request["run"], name)
            binding = row.get("workflow_run")
            if binding is not None:
                require(binding.get("head_sha") == request["sha"]
                        and binding.get("head_branch") == "main", SHA)
            path = scratch / name
            unpack_artifact(api, REPO, row, path, limit=512 * 1024 * 1024)
            return path

        intents = download(auth.ARTIFACT_NAME)
        for major in intent_series(intents, request):
            for name in artifact_names(request["ext"], major):
                download(name)
        return intents, scratch, scratch, scratch


def issuer_evidence(args, issuer_api, env, scratch):
    with reject_as(K3):
        paths = args.ticket, args.inputs, args.issuance_policy
        if all(paths):
            policy = read_json(args.issuance_policy, K3)
            ticket = k3.read_bytes(args.ticket, k3.ticket_verifier.MAX_TICKET_BYTES, K3)
            inputs = k3.read_bytes(args.inputs, k3.ticket_verifier.MAX_INPUTS_BYTES, K3)
        else:
            require(not any(paths) and env.get("CENTRAL_PUBLISHER_K3_ISSUANCE_POLICY")
                    and env.get("CENTRAL_PUBLISHER_ISSUER_READ_TOKEN"), K3,
                    "trusted issuer context required")
            policy = auth.parse_json(env["CENTRAL_PUBLISHER_K3_ISSUANCE_POLICY"])
            k3.live._validate_issuance_policy(policy)
            row = artifact_row(issuer_api, issuance.PREFIX, policy["runId"], issuance.ARTIFACT)
            folder = scratch / "issuer"
            unpack_artifact(issuer_api, issuance.PREFIX, row, folder, limit=issuance.MAX_ARTIFACT_BYTES)
            require(regular_files(folder).keys() == {"ticket.json", "inputs.json", "claim-result.json"}, K3)
            ticket = k3.read_bytes(folder / "ticket.json", k3.ticket_verifier.MAX_TICKET_BYTES, K3)
            inputs = k3.read_bytes(folder / "inputs.json", k3.ticket_verifier.MAX_INPUTS_BYTES, K3)
            claim = read_json(folder / "claim-result.json", K3)
            require(claim == {"status": "CLAIM_CREATED", "requestId": policy["requestId"],
                              "commit": policy["claimCommitSha"], "ticketSha256": policy["ticketSha256"]}, K3)
        return ticket.decode("utf-8"), inputs, policy


def verify_attestations(zip_path, sbom, signed, intent, major):
    with reject_as(K3):
        verification = audit.verify
        common = ["gh", "attestation", "verify", str(zip_path), "--repo", REPOSITORY,
                  "--signer-workflow", f"{REPOSITORY}/{auth.REUSABLE}", "--signer-digest", PIN,
                  "--source-digest", intent["head_sha"], "--source-ref", auth.REF,
                  "--deny-self-hosted-runners", "--format", "json"]
        results = []
        for kind, predicate in (("slsa", verification.SLSA), ("spdx", verification.SPDX)):
            result = subprocess.run(
                [*common, "--bundle", str(signed[f"{kind}.sigstore.json"]), "--predicate-type", predicate],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=180, check=True)
            results.append(auth.parse_json(result.stdout.decode("utf-8")))
        return verification.verify_claims(zip_path, sbom, *results, intent,
                                          intent["authentic_event"], major=major)


def verify_packages(request, live_run, roots, scratch, *, attestation_check):
    with reject_as(LAYOUT):
        intent_dir, unsigned_dir, signed_dir, claims_dir = roots
        intents = intent_series(intent_dir, request)
        for root, kind in ((unsigned_dir, "unsigned"), (signed_dir, "signed"), (claims_dir, "claims")):
            check_artifact_roster(root, kind, request["ext"], intents)
        dist = scratch / "dist"
        dist.mkdir()
        audit_dir = scratch / "audit"
        targets = []
        for major, intent in sorted(intents.items()):
            unsigned_name, signed_name, claims_name = artifact_names(request["ext"], major)
            unsigned = regular_files(artifact_folder(unsigned_dir, unsigned_name,
                                                     single=len(intents) == 1, extension=request["ext"]))
            signed = regular_files(artifact_folder(signed_dir, signed_name, single=len(intents) == 1,
                                                   extension=request["ext"]))
            evidence = regular_files(artifact_folder(claims_dir, claims_name, single=len(intents) == 1,
                                                     extension=request["ext"]))
            require(evidence.keys() == k3.AUDIT_FILES, LAYOUT)
            claims = read_json(evidence["claims.json"], LAYOUT)
            prior_run = check_run(read_json(evidence["run.json"], LAYOUT), request, completed=False)
            require(prior_run.get("event") == live_run["event"]
                    and prior_run.get("actor") == live_run.get("actor"), RUN)
            name = claims["subject"]["name"]
            require(isinstance(name, str) and name.startswith(f"{request['ext']}-"), EXT)
            require(name.endswith(f"-pg{major}-windows-x64.zip"), PG)
            with reject_as(K3):
                require(audit.audit(live_run, intent, claims) ==
                        read_json(evidence["audit.json"], K3), K3)
            sbom = name.removesuffix(".zip") + ".spdx.json"
            require(unsigned.keys() == {name, sbom} and signed.keys() ==
                    {name, sbom, "slsa.sigstore.json", "spdx.sigstore.json"}, LAYOUT)
            t0 = package.handoff_record("T0", request["ext"], major, unsigned[name])
            t1 = package.handoff_record("T1", request["ext"], major, signed[name], t0)
            require(t0["sha256"] == t1["sha256"] == claims["subject"]["digest"]["sha256"]
                    and t0["size"] == t1["size"]
                    and package.sha256_file(unsigned[sbom]) == package.sha256_file(signed[sbom]), LAYOUT)
            require(attestation_check(signed[name], signed[sbom], signed, intent, major) == claims, K3)
            for file_name, path in signed.items():
                target = dist / (file_name if file_name in (name, sbom) else
                                 name.removesuffix(".zip") + "." + file_name)
                shutil.copyfile(path, target)
            target_audit = audit_dir / request["ext"] / str(major)
            target_audit.mkdir(parents=True)
            for path in evidence.values():
                shutil.copyfile(path, target_audit / path.name)
            targets.append((t0, t1))
        return dist, audit_dir, targets


def rerun_k3(request, ticket, inputs, policy, intent_dir, audit_dir, dist, live_run, now,
             central_api, issuer_api):
    with reject_as(K3):
        base = k3.ticket_verifier.parse_ticket(ticket)["targetMainSha"]
        result = k3.verify_central_k3_admission(
            extension=request["ext"], central_main_sha=request["sha"], reusable_pin_sha=PIN,
            signing_run_id=request["run"], signing_run_attempt=request["attempt"],
            expected_event=live_run["event"], raw_ticket_text=ticket, raw_inputs_bytes=inputs,
            issuance_policy=policy, ticket_base_sha=base, dist_dir=dist,
            intent_dir=intent_root(intent_dir), audit_dir=audit_dir, now=now,
            central_api=central_api.get, issuer_api=issuer_api.get)
        schema = read_json(k3.RESULT_SCHEMA, K3)
        require(Draft202012Validator(schema).is_valid(result) and result.get("verified") is True
                and result.get("status") == k3.STATUS, K3)
        return result


def comparison_key(row):
    return row["extension"], row["pgMajor"], row["fileName"], row["sha256"], row["size"]


def admit(args, request, api, issuer_api, env, scratch, *, now, attestation_check=verify_attestations):
    check_main(request, args.expected_protected_sha, api)
    fleet = check_policy(args.fleet_config, request["ext"])
    live_run = signing_run(api, request)
    with reject_as(TAG):
        declaration = k3.fetch_central_protected_snapshot(
            api.get, request["sha"], f"extensions/{request['ext']}/extension.json", {}, "declaration", TAG)
        verify_tag(request, declaration)
    paths = args.intent_dir, args.unsigned_dir, args.signed_dir, args.claims_dir
    require(all(paths) or not any(paths), LAYOUT)
    roots = paths if all(paths) else download_artifacts(api, request, scratch)
    dist, audit_dir, chains = verify_packages(request, live_run, roots, scratch,
                                              attestation_check=attestation_check)
    ticket, inputs, policy = issuer_evidence(args, issuer_api, env, scratch)
    result = rerun_k3(request, ticket, inputs, policy, roots[0], audit_dir, dist, live_run, now, api, issuer_api)
    entries = []
    for t0, t1 in chains:
        t2 = package.handoff_record("T2", request["ext"], t1["pgMajor"], dist / t1["fileName"], t1)
        names = ("extension", "pgMajor", "fileName", "sha256", "size")
        entries.append({**{key: t2[key] for key in names}, "handoffs": {"T0": t0, "T1": t1, "T2": t2}})
    verified = {(row["extension"], row["postgresqlMajor"], row["zipName"], row["zipSha256"],
                 row["zipSizeBytes"]) for row in result["zipResults"]}
    require(len(verified) == len(entries) == len(result["zipResults"])
            and verified == {comparison_key(row) for row in entries}, K3)
    check_run(api.get(f"{REPO}/actions/runs/{request['run']}"), request, completed=True)
    return {"fleet": fleet, "entries": entries, "dist": dist}


def provenance(request, entries):
    return {
        "extension": request["ext"], "pgMajor": request["pg"], "protectedMainSha": request["sha"],
        "signingRunId": request["run"], "signingRunAttempt": request["attempt"],
        "od01Tag": request["tag"], "k3AdmissionVerified": True,
        "zipSha256": [row["sha256"] for row in entries],
    }


def release_matches(release, request, majors):
    require(isinstance(release, dict) and type(release.get("draft")) is bool
            and isinstance(release.get("tag_name"), str), READ)
    if release.get("tag_name") == request["tag"]:
        return True
    body = release.get("body") or ""
    require(isinstance(body, str), READ)
    if release.get("draft") is not False:
        return False
    for line in body.splitlines():
        if line.startswith(MARKER):
            with reject_as(READ):
                marker = auth.parse_json(line[len(MARKER):])
                require(isinstance(marker, dict), READ)
            if (marker.get("od01Tag") == request["tag"] or
                (marker.get("extension") == request["ext"] and marker.get("pgMajor") in majors
                 and marker.get("signingRunId") == request["run"])):
                return True
    return False


def release_identity(release):
    require(isinstance(release, dict) and positive(release.get("id"))
            and isinstance(release.get("tag_name"), str) and type(release.get("draft")) is bool, READ)
    return {key: release[key] for key in ("id", "tag_name", "draft")}


def snapshot(api, request, entries):
    encoded = quote(request["tag"], safe="")
    by_tag = api.get(f"{REPO}/releases/tags/{encoded}", missing=True)
    ref = api.get(f"{REPO}/git/ref/tags/{encoded}", missing=True)
    if by_tag is not None:
        by_tag = release_identity(by_tag)
        require(by_tag["tag_name"] == request["tag"], READ)
    if ref is not None:
        require(isinstance(ref, dict) and ref.get("ref") == f"refs/tags/{request['tag']}"
                and isinstance(ref.get("object"), dict)
                and auth.matches(auth.SHA, ref["object"].get("sha")), READ)
        ref = {key: ref[key] for key in ("ref", "object")}
    majors = {row["pgMajor"] for row in entries}
    with reject_as(READ):
        for page in range(1, 101):
            releases = api.get(f"{REPO}/releases?per_page=100&page={page}")
            require(type(releases) is list and len(releases) <= 100, READ)
            matches = [release_identity(row) for row in releases if release_matches(row, request, majors)]
            matches.sort(key=lambda row: row["id"])
            if matches or len(releases) < 100:
                return {"releaseByTag": by_tag, "gitRefTag": ref, "matchingReleases": matches}
        raise Denied(READ, "Release inventory exceeds read limit")


def observe(request, path, kind, before, after, now, recovery=None):
    normal = kind in (PREWRITE, WRITER)
    before_sha, after_sha = digest(before), digest(after) if after is not None else None
    require(not normal or before_sha == after_sha, READ, "remote state changed during denial observation")
    release, ref = before["releaseByTag"], before["gitRefTag"]
    matches = before["matchingReleases"]
    value = {
        "schemaVersion": 1, "observationKind": kind, "extension": request["ext"],
        "pgMajor": request["pg"], "od01Tag": request["tag"], "signingRunId": request["run"],
        "signingRunAttempt": request["attempt"], "protectedMainSha": request["sha"],
        "prewriteGetHits": {"releaseByTagStatus": 200 if release is not None else 404,
                            "gitRefTagStatus": 200 if ref is not None else 404,
                            "existingReleaseId": (release or (matches[0] if matches else {})).get("id")},
        "tokenMinted": kind != PREWRITE, "writeAttempted": kind == UNKNOWN,
        "writerAbsentDenied": kind == WRITER, "recoveryJsonGenerated": kind == UNKNOWN,
        "recoveryJsonPath": recovery.name if recovery else None,
        "beforeGet": before, "afterGet": after,
        "beforeGetSha256": before_sha, "afterGetSha256": after_sha,
        "unchangedAfterDenial": normal,
        "deniedReasonCode": "CPUB_DUPLICATE_TAG_ALREADY_EXISTS" if kind == PREWRITE else f"CPUB_{kind}",
        "observedAt": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    write_json(path, value)


def prewrite(api, request, entries, output, now):
    before = snapshot(api, request, entries)
    if before["releaseByTag"] is not None or before["gitRefTag"] is not None or before["matchingReleases"]:
        observe(request, output, PREWRITE, before, snapshot(api, request, entries), now)
        raise Denied(f"CPUB_{PREWRITE}")
    return before


def add_arguments(parser):
    parser.add_argument("--trigger-comment", default=os.environ.get("COMMENT_BODY"))
    parser.add_argument("--expected-protected-sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--github-api-base", default=API)
    parser.add_argument("--fleet-config", type=Path, default=ROOT / k3.FLEET_PATH)
    parser.add_argument("--out-duplicate-observation", type=Path, required=True)
    for arg in ("intent-dir", "unsigned-dir", "signed-dir", "claims-dir", "ticket", "inputs", "issuance-policy"):
        parser.add_argument(f"--{arg}", type=Path)


def runtime(args, env):
    # The real entry points execute exclusively from the event's main SHA.
    require(args.expected_protected_sha == env.get("GITHUB_SHA")
            and auth.git(ROOT, "rev-parse", "HEAD") == args.expected_protected_sha, SHA)
    # Mock HTTP reads never receive runner credentials.
    default_api = args.github_api_base == API
    api = GitHub(env.get("GH_TOKEN", "") if default_api else "", args.github_api_base)
    issuer = GitHub(env.get("CENTRAL_PUBLISHER_ISSUER_READ_TOKEN", "") if default_api else "",
                    args.github_api_base)
    return api, issuer


def output_extension(env, extension):
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"extension={extension}\n")


def cli(action):
    try:
        return action()
    except Denied as error:
        print(error, file=sys.stderr)
    except (ValueError, OSError, subprocess.SubprocessError, k3.Denied):
        print("CPUB_OPERATION_FAILED", file=sys.stderr)
    return 1


def utc_now():
    return datetime.now(timezone.utc)
