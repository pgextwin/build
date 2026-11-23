#!/usr/bin/env python3
"""Resolve the two fleet promotion evidence Run IDs using GitHub GETs only."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fleet_promotion_gate", ROOT / "fleet-promotion-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
Denied = gate.Denied
require = gate.require

LIFECYCLE = ROOT.parent / "metadata/postgresql.json"
MANIFEST = "config/extension.json"
FIRST_RELEASE = "config/initial-release-candidate.json"
RUN_FIELDS = "{id,event,status,conclusion,head_branch,head_sha}"
ARTIFACT_FIELDS = "{id,name,expired,workflow_run:(.workflow_run | {id,head_branch})}"
PR_FIELDS = """{number,merged,state,body,merge_commit_sha,
    base:{ref:.base.ref},head:(.head | {ref,sha}),user:{login:.user.login}}"""


def json_object(raw):
    def unique_pairs(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs), "duplicate JSON keys in evidence")
        return value

    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(type(value) is dict, "evidence must be a JSON object")
    return value


class GitHub:
    @staticmethod
    def get(path, *options):
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", path, *options],
            check=False, capture_output=True,
        )
        if result.returncode:
            reason = result.stderr.decode("utf-8", errors="replace").strip()
            raise Denied(f"GitHub GET failed for {path}: {reason[:350]}")
        return result.stdout

    def json(self, path, fields):
        return json.loads(self.get(path, "--jq", fields))

    def collection(self, path, key, fields, *, search_limit=None):
        raw = self.get(path, "--paginate", "--jq", f"{{total_count,{key}:[.{key}[] | {fields}]}}")
        pages = [json.loads(line) for line in raw.splitlines()]
        require(pages, f"missing GitHub {key} listing")
        total = pages[0]["total_count"]
        require(type(total) is int and total >= 0, f"invalid GitHub {key} count")
        require(search_limit is None or total < search_limit, f"GitHub {key} search limit reached")
        rows = [row for page in pages for row in page[key]]
        require(all(page["total_count"] == total for page in pages)
                and len(rows) == total and len({row["id"] for row in rows}) == total,
                f"incomplete or changing GitHub {key} listing")
        return rows

    def document(self, project, path, merge_sha):
        contents = self.json(f"{project}/contents/{path}?ref={merge_sha}", "{encoding,content}")
        require(contents.get("encoding") == "base64", f"missing merged {path}")
        encoded = "".join(contents["content"].split())
        return json_object(base64.b64decode(encoded, validate=True))

    def artifact(self, project, artifact_id, name):
        require(type(artifact_id) is int and artifact_id > 0, f"invalid {name} artifact ID")
        raw = self.get(f"{project}/actions/artifacts/{artifact_id}/zip")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            reports = [item for item in archive.infolist()
                       if not item.is_dir() and Path(item.filename).suffix == ".json"]
            require(len(reports) == 1, f"ambiguous or missing JSON in {name} artifact {artifact_id}")
            return json_object(archive.read(reports[0]).decode("utf-8-sig"))


def live_artifacts(github, endpoint, name):
    evidence = github.collection(f"{endpoint}?name={name}&per_page=100", "artifacts", ARTIFACT_FIELDS)
    for item in evidence:
        require(item.get("name") == name and type(item.get("expired")) is bool,
                f"invalid {name} artifact listing")
    return [item for item in evidence if not item["expired"]]


def unique_run(label, matches, rejected):
    if not matches:
        detail = "; ".join(sorted(set(rejected))) or "no eligible runs with available evidence"
        raise Denied(f"no matching {label} run: {detail}")
    require(len(matches) == 1, f"ambiguous {label} runs: {', '.join(map(str, sorted(matches)))}")
    return matches[0]


def resolve(repository, candidate_pr, *, github=None, lifecycle=None, release_tag=None):
    """Bind the runs to the merged PR SHA and gate evidence, returning their identity."""
    extension = repository.removeprefix("pgextwin/")
    require(extension in gate.ident.UPSTREAMS and repository == f"pgextwin/{extension}",
            "unsupported fleet repository")
    require(type(candidate_pr) is int and candidate_pr > 0, "invalid candidate PR number")
    github = GitHub() if github is None else github
    lifecycle = json_object(LIFECYCLE.read_bytes()) if lifecycle is None else lifecycle

    project = f"repos/{repository}"
    pull = f"{project}/pulls/{candidate_pr}"
    pr = github.json(pull, PR_FIELDS)
    require(pr.get("number") == candidate_pr, "candidate PR number mismatch")
    branch, candidate_id = gate.verify_candidate_pr(pr)
    head_sha = pr["head"]["sha"]
    merge_sha = pr["merge_commit_sha"]
    files = github.json(f"{pull}/files?per_page=2", "map({filename,status})")
    require(type(files) is list and len(files) == 1 and files[0].get("filename") in (MANIFEST, FIRST_RELEASE),
            "candidate PR must change exactly the manifest or add the first Release intent")
    ext = github.document(project, MANIFEST, merge_sha)
    require(ext.get("name") == extension, "merged manifest extension mismatch")
    first_release = files[0]["filename"] == FIRST_RELEASE
    intent = github.document(project, FIRST_RELEASE, merge_sha) if first_release else None
    gate.verify_candidate_files(repository, ext, files, candidate_id, first_release, intent)
    majors = gate.ident.maintained_majors(ext, lifecycle)
    sources = gate.ident.sources(ext)
    if release_tag is not None:
        gate.ident.validate_release_tag(ext, release_tag)

    actions = f"{project}/actions"
    candidates = github.collection(f"{actions}/runs?head_sha={head_sha}&per_page=100",
                                   "workflow_runs", RUN_FIELDS, search_limit=1000)
    matches, rejected = [], []
    for run in candidates:
        try:
            gate.verify_candidate_run(run, branch, head_sha)
        except Denied as error:
            rejected.append(str(error))
            continue
        run_id = run["id"]
        artifacts = live_artifacts(github, f"{actions}/runs/{run_id}/artifacts", "candidate-audit")
        if not artifacts:
            rejected.append("candidate-audit absent or expired")
            continue
        require(len(artifacts) == 1, f"ambiguous candidate-audit artifacts on run {run_id}")
        audit = github.artifact(project, artifacts[0]["id"], "candidate-audit")
        try:
            gate.verify_candidate_audit(audit, run_id, branch, head_sha, ext, majors, sources)
        except Denied as error:
            rejected.append(str(error))
            continue
        matches.append(run_id)
    candidate_run_id = unique_run("candidate", matches, rejected)

    # Look up runs through the exact artifact name. An arbitrary main-run time window
    # can hide a second valid decision, and a filtered run search is capped at 1,000.
    by_run = {}
    for item in live_artifacts(github, f"{actions}/artifacts", "candidate-decision"):
        workflow = item["workflow_run"]
        require(type(workflow.get("id")) is int and workflow["id"] > 0
                and isinstance(workflow.get("head_branch"), str), "unbound candidate-decision artifact")
        if workflow["head_branch"] == "main":
            by_run.setdefault(workflow["id"], []).append(item["id"])
    matches, rejected = [], []
    for run_id, artifact_ids in by_run.items():
        for artifact_id in artifact_ids:
            decision = github.artifact(project, artifact_id, "candidate-decision")
            try:
                gate.verify_decision(decision, branch, candidate_id, ext, majors, sources)
                require((decision.get("firstRelease") is True) == first_release,
                        "decision first Release flag differs from candidate PR")
            except Denied as error:
                rejected.append(str(error))
                continue
            run = github.json(f"{actions}/runs/{run_id}", RUN_FIELDS)
            require(run.get("id") == run_id, "decision run ID does not match its artifact")
            try:
                gate.verify_decision_run(run)
            except Denied as error:
                rejected.append(str(error))
                continue
            require(len(artifact_ids) == 1, f"ambiguous candidate-decision artifacts on run {run_id}")
            matches.append(run_id)
    decision_run_id = unique_run("decision", matches, rejected)
    return {
        "repository": repository,
        "candidatePr": candidate_pr,
        "candidateId": candidate_id,
        "candidateHeadSha": head_sha,
        "candidateMergeSha": merge_sha,
        "candidateRunId": candidate_run_id,
        "decisionRunId": decision_run_id,
    }


INPUT_ERRORS = (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, zipfile.BadZipFile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", help="extension repository, for example pgextwin/pgaudit")
    parser.add_argument("candidate_pr", type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(resolve(args.repository, args.candidate_pr), indent=2))
        return 0
    except INPUT_ERRORS as error:
        print(f"PROMOTION RUN RESOLUTION DENY: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
