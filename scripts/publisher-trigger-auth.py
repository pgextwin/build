#!/usr/bin/env python3
"""Authenticate a real central Publisher schedule or owner dispatch.

The dispatch path is distinct from schedule and requires the registered owner
as both original and triggering actor. This helper cannot issue a receipt,
request a token, waive signed-source verification or publish anything.
"""
import json
import re

OWNER = "ShutenOishi"
OWNER_ID = 27071164
WORKFLOW = ".github/workflows/publisher-candidate-intake.yml"
SHA = re.compile(r"^[a-f0-9]{40}$")
REPOSITORY = re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")

class Denied(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Denied(reason)

def context(env):
    event=env.get("GITHUB_EVENT_NAME")
    need(env.get("GITHUB_REPOSITORY")=="pgextwin/build"
         and event in ("schedule", "workflow_dispatch")
         and env.get("GITHUB_REF")=="refs/heads/main"
         and env.get("GITHUB_RUN_ATTEMPT")=="1",
         "untrusted central Publisher context")
    if event=="workflow_dispatch":
        need(env.get("GITHUB_ACTOR")==OWNER
             and env.get("GITHUB_TRIGGERING_ACTOR")==OWNER
             and env.get("GITHUB_ACTOR_ID")==str(OWNER_ID),
             "untrusted owner dispatch context")
    return event

def dispatch_request(env, *, repository=None):
    """Bind a manual invocation to the requested single repository and mode."""
    need(context(env)=="workflow_dispatch", "not an owner dispatch")
    target=env.get("PUBLISHER_TARGET")
    dry=env.get("PUBLISHER_DRY_RUN")
    need(type(target) is str and REPOSITORY.fullmatch(target)
         and dry in ("true", "false"), "invalid owner dispatch inputs")
    try:
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as file:
            payload=json.load(file)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise Denied("GitHub dispatch event inputs unavailable") from exc
    inputs=payload.get("inputs") if type(payload) is dict else None
    need(type(inputs) is dict and inputs.get("target_repository")==target
         and (inputs.get("dry_run")==dry
              or type(inputs.get("dry_run")) is bool
              and str(inputs["dry_run"]).lower()==dry)
         and (repository is None or target==repository),
         "target or dry-run does not match the GitHub dispatch request")
    return target, dry=="true"

def run(run, *, run_id, sha, event, actor):
    need(type(run_id) is int and run_id>0
         and type(sha) is str and SHA.fullmatch(sha)
         and event in ("schedule", "workflow_dispatch"),
         "invalid Publisher Run identity")
    need(type(run) is dict and type(run.get("id")) is int and run["id"]==run_id
         and type(run.get("run_attempt")) is int and run["run_attempt"]==1
         and run.get("event")==event and run.get("path")==WORKFLOW
         and run.get("head_sha")==sha and run.get("head_branch")=="main"
         and type(run.get("repository")) is dict
         and run["repository"].get("full_name")=="pgextwin/build"
         and run.get("status")=="in_progress" and run.get("conclusion") is None,
         "untrusted or replayed central Publisher Run")
    if event=="workflow_dispatch":
        need(actor==OWNER, "owner dispatch actor mismatch")
        for field in ("actor", "triggering_actor"):
            person=run.get(field)
            need(type(person) is dict and person.get("login")==OWNER
                 and type(person.get("id")) is int and person["id"]==OWNER_ID
                 and person.get("type")=="User",
                 "owner dispatch run identity mismatch")
    return event
