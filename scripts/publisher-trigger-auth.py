#!/usr/bin/env python3
"""Authenticate actual schedule, owner dispatch, or owner Issue #311 comment."""
import json
import re
OWNER="ShutenOishi"
OWNER_ID=27071164
WORKFLOW=".github/workflows/publisher-candidate-intake.yml"
SHA=re.compile(r"^[a-f0-9]{40}$")
REPOSITORY=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
COMMAND=re.compile(r"^/pgextwin publish (pgextwin/[a-z][a-z0-9_]*)$")
ISSUE=311
class Denied(ValueError):pass
def need(ok,msg):
    if not ok:raise Denied(msg)
def owner(person):
    return type(person) is dict and person.get("login")==OWNER and type(person.get("id")) is int and person["id"]==OWNER_ID and person.get("type")=="User"
def context(env):
    event=env.get("GITHUB_EVENT_NAME")
    need(env.get("GITHUB_REPOSITORY")=="pgextwin/build"
         and event in ("schedule","workflow_dispatch","issue_comment")
         and env.get("GITHUB_REF")=="refs/heads/main"
         and env.get("GITHUB_RUN_ATTEMPT")=="1","untrusted Publisher runtime")
    if event in ("workflow_dispatch","issue_comment"):
        need(env.get("GITHUB_ACTOR")==OWNER and env.get("GITHUB_TRIGGERING_ACTOR")==OWNER
             and env.get("GITHUB_ACTOR_ID")==str(OWNER_ID),"untrusted owner identity")
    return event
def payload(env):
    try:
        with open(env["GITHUB_EVENT_PATH"],encoding="utf-8") as f: obj=json.load(f)
    except (OSError,KeyError,TypeError,ValueError) as e:
        raise Denied("GitHub event payload unavailable") from e
    need(type(obj) is dict,"invalid event payload")
    return obj
def dispatch_request(env,*,repository=None):
    need(context(env)=="workflow_dispatch","not an owner dispatch")
    target=env.get("PUBLISHER_TARGET");dry=env.get("PUBLISHER_DRY_RUN")
    need(type(target) is str and REPOSITORY.fullmatch(target) and dry in ("true","false"),"invalid inputs")
    inputs=payload(env).get("inputs")
    need(type(inputs) is dict and inputs.get("target_repository")==target
         and (inputs.get("dry_run")==dry or
              type(inputs.get("dry_run")) is bool and str(inputs["dry_run"]).lower()==dry)
         and (repository is None or target==repository),"dispatch inputs mismatch")
    return target,dry=="true"
def issue_request(env,*,repository=None):
    need(context(env)=="issue_comment","not an issue comment")
    obj=payload(env);comment=obj.get("comment");issue=obj.get("issue")
    need(obj.get("action")=="created" and type(issue) is dict and issue.get("number")==ISSUE
         and not issue.get("pull_request") and type(comment) is dict
         and type(comment.get("id")) is int and comment["id"]>0
         and owner(comment.get("user")) and owner(obj.get("sender"))
         and comment.get("issue_url")=="https://api.github.com/repos/pgextwin/build/issues/311",
         "untrusted owner Issue #311 event")
    body=comment.get("body")
    m=COMMAND.fullmatch(body) if type(body) is str else None
    need(m is not None and (repository is None or repository==m.group(1)),
         "invalid single-target publish command")
    need(comment.get("created_at")==comment.get("updated_at"),"edited request rejected")
    return m.group(1),comment["id"]
def live_comment(env,api,*,repository=None):
    target,cid=issue_request(env,repository=repository)
    obj=api("pgextwin/build",f"issues/comments/{cid}")
    need(type(obj) is dict and obj.get("id")==cid and owner(obj.get("user"))
         and obj.get("body")==f"/pgextwin publish {target}"
         and obj.get("issue_url")=="https://api.github.com/repos/pgextwin/build/issues/311"
         and obj.get("created_at")==obj.get("updated_at"),"current owner request changed")
    return cid
def request(env,*,repository=None):
    event=context(env)
    if event=="workflow_dispatch":
        target,dry=dispatch_request(env,repository=repository)
        return target,dry,None
    if event=="issue_comment":
        target,cid=issue_request(env,repository=repository)
        return target,False,cid
    raise Denied("no authenticated owner request")
def run(run,*,run_id,sha,event,actor,comment_id=None):
    need(type(run_id) is int and run_id>0 and type(sha) is str and SHA.fullmatch(sha)
         and event in ("schedule","workflow_dispatch","issue_comment"),"invalid Publisher ID")
    need(type(run) is dict and type(run.get("id")) is int and run["id"]==run_id
         and type(run.get("run_attempt")) is int and run["run_attempt"]==1
         and run.get("event")==event and run.get("path")==WORKFLOW
         and run.get("head_sha")==sha and run.get("head_branch")=="main"
         and type(run.get("repository")) is dict
         and run["repository"].get("full_name")=="pgextwin/build"
         and run.get("status")=="in_progress" and run.get("conclusion") is None,
         "untrusted or replayed Publisher Run")
    if event in ("workflow_dispatch","issue_comment"):
        need(actor==OWNER and owner(run.get("actor")) and owner(run.get("triggering_actor")),
             "Publisher Run owner mismatch")
    if event=="issue_comment":
        need(type(comment_id) is int and comment_id>0
             and run.get("display_title")==f"Publisher-issue_comment-comment-{comment_id}",
             "comment ID not bound to Publisher Run")
    return event
