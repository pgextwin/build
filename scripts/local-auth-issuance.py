"""Dispatch a private issuer run and verify its exact production artifact."""
import hashlib
import io
import json
import os
import subprocess
import time
from zipfile import BadZipFile, ZipFile

REPO = "pgextwin/local-auth-issuer"
WORKFLOW_ID = 421122469
WORKFLOW_PATH = ".github/workflows/issue-ticket.yml"
ARTIFACT = "local-auth-production-ticket"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
PREFIX = "repos/" + REPO


def request(endpoint, *, payload=None):
    command = ["gh", "api", "--hostname", "github.com", "--method",
               "GET" if payload is None else "POST",
               "-H", "X-GitHub-Api-Version: 2026-03-10", endpoint]
    body = None
    if payload is not None:
        command += ["--input", "-"]
        body = json.dumps(payload).encode()
    environment = dict(os.environ, GH_TOKEN=os.environ["LOCAL_AUTH_ISSUER_TOKEN"],
                       GH_PROMPT_DISABLED="1")
    environment.pop("GH_DEBUG", None)
    result = subprocess.run(command, input=body, capture_output=True, timeout=30,
                            env=environment, check=False)
    if result.returncode or not 0 < len(result.stdout) <= MAX_ARTIFACT_BYTES:
        raise ValueError("Private issuer GitHub request failed")
    return result.stdout


def get(endpoint):
    return json.loads(request(endpoint))


def receive(repository, target_sha, consumer_run_id, verifier):
    if not os.environ.get("LOCAL_AUTH_ISSUER_TOKEN"):
        raise ValueError("Missing repository-scoped local-auth issuer credential")
    workflow = get(f"{PREFIX}/actions/workflows/{WORKFLOW_ID}")
    if workflow.get("path") != WORKFLOW_PATH or workflow.get("state") != "active":
        raise ValueError("Private issuer workflow unavailable")
    issuer_main = get(PREFIX + "/git/ref/heads/main")["object"]["sha"]
    verifier._hex(issuer_main, 40, "ISSUER_MAIN_MISMATCH")
    result = json.loads(request(f"{PREFIX}/actions/workflows/{WORKFLOW_ID}/dispatches",
                               payload={"ref": "main", "inputs": {
                                   "operation": "candidate", "repository": repository,
                                   "target_main_sha": target_sha,
                                   "consumer_run_id": str(consumer_run_id),
                               }}))
    run_id = result["workflow_run_id"]
    verifier._positive_integer(run_id, "ISSUER_RUN_MISMATCH")
    run_endpoint = f"{PREFIX}/actions/runs/{run_id}"
    for _ in range(60):
        run = get(run_endpoint)
        if run.get("status") == "completed":
            break
        time.sleep(5)
    if (run.get("status"), run.get("conclusion")) != ("completed", "success"):
        raise ValueError("Private issuer run did not succeed")
    artifacts = get(run_endpoint + "/artifacts?per_page=100")
    entries = artifacts["artifacts"]
    if len(entries) != artifacts["total_count"] or len(entries) != 1:
        raise ValueError("Expected one private artifact from the exact issuer run")
    artifact = entries[0]
    artifact_id = artifact["id"]
    verifier._positive_integer(artifact_id, "INVALID_ISSUER_ARTIFACT")
    if (artifact.get("name") != ARTIFACT or artifact.get("expired") is not False
            or artifact.get("workflow_run", {}).get("id") != run_id
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= MAX_ARTIFACT_BYTES):
        raise ValueError("Invalid private issuer artifact identity")
    archive = request(f"{PREFIX}/actions/artifacts/{artifact_id}/zip")
    if (len(archive) != artifact["size_in_bytes"]
            or "sha256:" + hashlib.sha256(archive).hexdigest() != artifact.get("digest")):
        raise ValueError("Private issuer artifact bytes differ from GitHub digest")
    expected = {"ticket.json": verifier.MAX_TICKET_BYTES,
                "inputs.json": verifier.MAX_INPUTS_BYTES, "claim-result.json": 2048}
    try:
        with ZipFile(io.BytesIO(archive)) as data:
            names = data.infolist()
            if (len(names) != len(expected) or {item.filename for item in names} != set(expected)
                    or any(not 0 < item.file_size <= expected[item.filename] for item in names)):
                raise ValueError("Unexpected private issuer ZIP contents")
            ticket_raw, inputs, claim = (data.read(name) for name in expected)
    except BadZipFile as exc:
        raise ValueError("Invalid private issuer ZIP") from exc
    ticket = verifier.parse_ticket(ticket_raw.decode("utf-8"))
    claim = verifier._parse_json(claim.decode("utf-8"), expected["claim-result.json"])
    if (set(claim) != {"status", "requestId", "commit", "ticketSha256"}
            or claim["status"] != "CLAIM_CREATED"
            or claim["ticketSha256"] != hashlib.sha256(ticket_raw).hexdigest()):
        raise ValueError("Invalid private issuer claim receipt")
    issuance = {
        "repository": REPO, "mainSha": issuer_main, "workflowPath": WORKFLOW_PATH,
        "workflowId": WORKFLOW_ID, "runId": run_id, "claimCommitSha": claim["commit"],
        "requestId": claim["requestId"], "ticketSha256": claim["ticketSha256"],
    }
    return ticket, inputs, issuance
