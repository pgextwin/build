#!/usr/bin/env python3
"""Step 19 stable candidate planning and once-only Windows CI dispatch; never publishes releases."""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

import candidate_branch
import local_auth_central
from update_watch_lib import (
    WatchError, detect_extension_update, github_get_json, load_watch, natural_key,
    resolve_watch, utc_now, validate_watch_semantics,
)

HEX_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MARKER_PREFIX = "pgextwin-candidate:v1"
DEFAULT_LOCAL_WRITER = ("github-actions[bot]", 41898282)
FIRST_RELEASE = frozenset({"pgextwin/pgtap", "pgextwin/pg_variables", "pgextwin/pg_store_plans"})
FIRST_FILE = "config/initial-release-candidate.json"
BUILD_ROOT = Path(__file__).resolve().parents[1]

_publication_spec = importlib.util.spec_from_file_location(
    "publication_policy", BUILD_ROOT / "scripts" / "publication-policy.py")
publication_policy = importlib.util.module_from_spec(_publication_spec)
_publication_spec.loader.exec_module(publication_policy)


def no_formal_release(repo, fetch):
    if repo not in FIRST_RELEASE:
        raise WatchError("initial candidate not allowed outside third wave")
    releases = fetch("https://api.github.com/repos/" + repo + "/releases?per_page=100")
    if type(releases) is not list:
        raise WatchError("formal Release absence cannot be established")
    return not releases


def initial_intent(extension, record):
    upstream = extension["upstream"]
    update = record["updates"]
    if (record.get("firstRelease") is not True or
            "pgextwin/" + extension["name"] not in FIRST_RELEASE or
            "perPostgresql" in upstream or len(update) != 1 or
            update[0].get("initialOnly") is not True or
            not HEX_SHA.fullmatch(str(upstream.get("commit", ""))) or
            any(upstream[k] != update[0][k] for k in ("ref", "version", "commit"))):
        raise WatchError("invalid initial pinned source intent")
    return {"schemaVersion":1,"kind":"FIRST_RELEASE_PINNED_SOURCE",
            "repository":"pgextwin/" + extension["name"], "extension":extension["name"],
            "releasePolicy":"manual-only","candidateId":record["candidateId"],
            "source":{k:upstream[k] for k in ("repository","ref","version","commit")}}



def read(path):
    item = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(item, dict):
        raise WatchError("JSON root must be an object")
    return item


def policy_valid(policy):
    expected = publication_policy.load_candidate_policy(BUILD_ROOT)
    if set(policy) != set(expected) or policy["schemaVersion"] != expected["schemaVersion"]:
        raise WatchError("unsupported candidate policy")
    # An explicit opt-out still yields the existing disabled plan.
    if policy["enabled"] is False:
        expected["enabled"] = False
    if type(policy["enabled"]) is not bool or policy != expected:
        raise WatchError("Step 19 allows only explicit opt-in with manual-only Release policy")


def api(url):
    # Releases/tags endpoints return arrays; Git ref/tag endpoints return objects.
    # The caller validates each endpoint's expected shape. Fail closed on mismatch.
    return github_get_json(url, os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))


def peel_tag(repository, tag, fetch=api):
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", tag) or tag.startswith("-") or ".." in tag:
        raise WatchError("invalid upstream tag")
    prefix = "https://api.github.com/repos/" + repository
    ref_object = fetch(prefix + "/git/ref/tags/" + quote(tag, safe="/"))
    if not isinstance(ref_object, dict):
        raise WatchError("Git tag reference must be an object")
    target = ref_object.get("object")
    for i in range(5):
        if not isinstance(target, dict) or target.get("type") not in {"commit", "tag"}:
            raise WatchError("unsupported or missing Git tag object")
        sha = target.get("sha")
        if not isinstance(sha, str) or not HEX_SHA.fullmatch(sha):
            raise WatchError("invalid object SHA")
        if target["type"] == "commit":
            return sha.lower()
        tag_object = fetch(prefix + "/git/tags/" + sha)
        if not isinstance(tag_object, dict):
            raise WatchError("annotated tag response must be an object")
        if i == 0 and tag_object.get("tag") != tag:
            raise WatchError("annotated tag name does not match")
        target = tag_object.get("object")
    raise WatchError("annotated tag nesting too deep")


def plan(extension, watch, policy, fetch=api, lifecycle=None, *, branch_style="legacy"):
    policy_valid(policy)
    watch = resolve_watch(extension, watch)
    validate_watch_semantics(extension, watch)
    result = {"schemaVersion": 1, "extension": extension["name"], "repository": watch["repository"],
              "detectedAt": utc_now(), "releasePolicy": "manual-only",
              "status": "disabled" if not policy["enabled"] else "no-op", "updates": []}
    if not policy["enabled"]:
        return result
    observation = detect_extension_update(extension, watch, fetch, result["detectedAt"], "pgextwin/build", "step19")
    # A legacy manifest without full SHA pins may never get an upstream
    # version bump. Generate a candidate that pins the *current* stable tag
    # exactly, without changing its ref/version or silently publishing it.
    # Only the automation-owned candidate PR may apply this pinned baseline.
    baseline = False
    initial = False
    if observation["status"] == "up-to-date":
        series = extension.get("upstream", {}).get("perPostgresql")
        if series is not None:
            missing = [(int(m), value) for m,value in series.items()
                       if not value.get("commit")]
        else:
            value = extension["upstream"]
            missing = [(None,value)] if not value.get("commit") else []
        if not missing:
            repo = "pgextwin/" + extension["name"]
            if repo not in FIRST_RELEASE or not no_formal_release(repo, fetch):
                return result
            if "perPostgresql" in extension["upstream"]:
                raise WatchError("initial candidate requires uniform pinned upstream")
            value = extension["upstream"]
            if peel_tag(watch["repository"], value["ref"], fetch) != value["commit"]:
                raise WatchError("initial upstream pin/tag mismatch")
            initial = True
            missing = [(None, value)]
        for major, value in missing:
            pattern = (watch["perPostgresql"][str(major)]["tagPattern"]
                       if major is not None else watch["stableTagPattern"])
            if not re.fullmatch(pattern, value["ref"], flags=0):
                raise WatchError("unpinned baseline ref is not a stable release tag")
        observations = [{
            "postgresqlMajor": m,
            "current": {"ref": value["ref"], "version": value["version"]},
            "candidate": {"ref": value["ref"], "version": value["version"],
                          "url": "https://github.com/" + watch["repository"] + "/tree/" + value["ref"]}
        } for m,value in missing]
        baseline = True
    elif observation["status"] == "update-available" and observation["updates"]:
        observations = observation["updates"]
    else:
        raise WatchError("indeterminate candidate detection")
    eligible = None
    if lifecycle is not None:
        from datetime import date
        allowed = extension.get("postgresql", {}).get("majors")
        if allowed is None:
            allowed = range(int(extension["postgresql"]["minMajor"]), int(extension["postgresql"]["maxMajor"]) + 1)
        allowed = {int(x) for x in allowed}
        if lifecycle.get("schemaVersion") != 1 or not isinstance(lifecycle.get("postgresql"), list):
            raise WatchError("invalid PostgreSQL lifecycle metadata")
        eligible = {int(x["major"]) for x in lifecycle["postgresql"]
                    if int(x["major"]) in allowed and date.fromisoformat(x["eol"]) >= date.today()}
        if not eligible:
            raise WatchError("no maintained PostgreSQL major eligible for candidate CI")
    for one in observations:
        major = one.get("postgresqlMajor")
        if eligible is not None and major is not None and int(major) not in eligible:
            continue
        c = one["candidate"]
        old = one["current"]
        if baseline:
            if c["ref"] != old["ref"] or str(c["version"]) != str(old["version"]):
                raise WatchError("baseline pin cannot change upstream ref/version")
        elif natural_key(c["version"]) <= natural_key(str(old["version"])):
            raise WatchError("downgrade or same-version switch is forbidden")
        result["updates"].append({
            "major": one.get("postgresqlMajor"),
            "oldRef": old["ref"], "oldVersion": str(old["version"]),
            "ref": c["ref"], "version": str(c["version"]),
            "commit": peel_tag(watch["repository"], c["ref"], fetch),
            "notes": c.get("url", ""),
            "pinOnly": baseline and not initial,
            "initialOnly": initial,
        })
    if not result["updates"]:
        return result
    stable = json.dumps(sorted([(x["major"], x["ref"], x["commit"]) for x in result["updates"]],
                               key=lambda x: str(x[0])), separators=(",", ":"))
    digest = hashlib.sha256((watch["repository"] + "\n" + ("initial-release\n" if initial else "") + stable).encode()).hexdigest()[:20]
    result.update({"candidateId": digest, "branch": candidate_branch.format_branch(
        extension["name"], digest, branch_style), "status": "candidate"})
    if initial:
        result["firstRelease"] = True
    return result


def apply(extension, record, pin_remaining=False, fetch=api):
    if record.get("status") != "candidate" or extension["name"] != record["extension"]:
        raise WatchError("candidate manifest identity mismatch")
    modified = copy.deepcopy(extension)
    per_major = "perPostgresql" in modified["upstream"]
    if not per_major and len(record["updates"]) != 1:
        raise WatchError("uniform extension should have one new stable candidate")
    for update in record["updates"]:
        target = modified["upstream"]["perPostgresql"].get(str(update["major"])) if per_major else modified["upstream"]
        if not isinstance(target, dict):
            raise WatchError("unsupported PostgreSQL series")
        if target["ref"] != update["oldRef"] or str(target["version"]) != update["oldVersion"]:
            raise WatchError("configured version changed since plan")
        if update.get("initialOnly") is True:
            if (record.get("firstRelease") is not True or
                    target.get("commit") != update["commit"] or
                    update["ref"] != update["oldRef"] or
                    str(update["version"]) != update["oldVersion"]):
                raise WatchError("initial candidate cannot modify pinned upstream")
        elif update.get("pinOnly") is True:
            if target.get("commit") or update["ref"] != update["oldRef"] or str(update["version"]) != update["oldVersion"]:
                raise WatchError("baseline may only add a missing SHA to exactly the current stable ref")
        elif natural_key(update["version"]) <= natural_key(update["oldVersion"]):
            raise WatchError("candidate cannot downgrade")
        target.update({"ref": update["ref"], "version": update["version"], "commit": update["commit"]})
    if pin_remaining and per_major:
        for major, target in modified["upstream"]["perPostgresql"].items():
            if not isinstance(target, dict) or not target.get("ref"):
                raise WatchError("missing series ref")
            pinned = peel_tag(record["repository"], target["ref"], fetch)
            existing = target.get("commit")
            if existing and existing.lower() != pinned:
                raise WatchError("existing PostgreSQL series tag moved")
            target["commit"] = pinned
    return modified


def execute(*args):
    r = subprocess.run(list(args), text=True, capture_output=True, check=False)
    if r.returncode != 0:
        raise WatchError(args[0] + " exited " + str(r.returncode) + ": " + r.stderr[:500])
    return r.stdout.strip()


def approved_automatic_candidate_policy(repository, main_sha, workflow_path):
    """Authenticate only the protected policy transition used by bot repair.

    This is permission to reconcile an unpublished candidate, never a Release
    receipt. The source caller, actual immutable shared checkout and complete
    live protected central policy must all identify the same approved snapshot.
    """
    def require(ok, reason):
        if not ok:
            raise WatchError("candidate policy transition DENIED: " + reason)
    root = Path(__file__).resolve().parents[1]
    shared_sha = execute("git", "-C", str(root), "rev-parse", "HEAD")
    require(bool(HEX_SHA.fullmatch(shared_sha)), "immutable shared checkout SHA missing")
    workflow = execute("git", "show", main_sha + ":" + workflow_path)
    prefix = "pgextwin/build/.github/workflows/candidate-update.yml@"
    callers = re.findall(r"^    uses: " + re.escape(prefix) + r"([0-9a-f]{40})$",
                         workflow, re.M)
    require(workflow.count(prefix) == 1 and callers == [shared_sha],
            "candidate caller is not the exact immutable approved shared snapshot")
    central = json.loads(execute("gh", "api", "--method", "GET",
                                "repos/pgextwin/build/branches/main"))
    require(type(central) is dict and central.get("protected") is True
            and (central.get("commit") or {}).get("sha") == shared_sha,
            "protected central main differs from the immutable caller")
    required = (((central.get("protection") or {}).get("required_status_checks") or {})
                .get("checks"))
    require(type(required) is list and any(type(item) is dict
            and item.get("context") == "resolver" and item.get("app_id") == 15368
            for item in required), "central required App15368 resolver missing")
    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, root / "scripts" / file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    contents = load("candidate_repair_contents", "github_contents.py")
    issuer = load("candidate_repair_policy_issuer", "automatic-publisher-receipt-issuer.py")
    objects = []
    for name in ("automation-fleet.json", "release-promotion.json",
                 "unattended-publication.json", "publisher-write-boundary.json"):
        path = "metadata/" + name
        response = json.loads(execute("gh", "api", "--method", "GET",
            "repos/pgextwin/build/contents/" + path + "?ref=" + shared_sha))
        try:
            objects.append(contents.decode_json_file(response, path))
        except (ValueError, TypeError) as exc:
            raise WatchError("candidate policy transition DENIED: unverified central policy blob") from exc
    try:
        decision = issuer.deployment_policy(*objects)
    except (issuer.Denied, ValueError, TypeError, KeyError) as exc:
        raise WatchError("candidate policy transition DENIED: incomplete automatic policy bundle") from exc
    require(decision.get("staticPublisherReady") is True
            and repository in decision.get("registeredRepositories", [])
            and decision.get("publicationAuthorized") is False
            and decision.get("publishableReceipt") is False,
            "automatic policy does not cover this nonpublishing candidate repair")
    return shared_sha




def repair_exact_bot_candidate_base_sync(record, repository, proposal_file, proposal, marker, branch):
    """Repair only a verified two-parent base sync by a real scheduled bot push.

    The human-authored merge is preserved, never relabeled or rewritten. A new
    empty bot-authored commit restores the immutable marker. Its new HEAD must
    obtain fresh original pull_request CI; old checks never authorize merging.
    """
    def require(ok, reason):
        if not ok:
            raise WatchError("candidate bot repair DENIED: " + reason)

    require(os.environ.get("GITHUB_EVENT_NAME") == "schedule"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_REPOSITORY") == repository
            and bool(os.environ.get("GH_TOKEN")),
            "genuine first-attempt protected-main schedule required")
    main_sha = os.environ.get("GITHUB_SHA", "")
    require(bool(HEX_SHA.fullmatch(main_sha))
            and execute("git", "rev-parse", "HEAD") == main_sha,
            "scheduled main checkout mismatch")
    main = json.loads(execute("gh", "api", "repos/" + repository + "/branches/main"))
    require(main.get("protected") is True
            and (main.get("commit") or {}).get("sha") == main_sha,
            "current protected main changed")
    remote_head = execute("git", "rev-parse", "refs/remotes/origin/" + branch)
    require(bool(HEX_SHA.fullmatch(remote_head)), "missing immutable remote HEAD")
    listed = json.loads(execute("gh", "pr", "list", "--repo", repository,
                                "--head", branch, "--state", "all", "--limit", "100",
                                "--json", "number,body,state,headRefOid,headRefName,baseRefName,isDraft"))
    require(len(listed) == 1 and type(listed[0].get("number")) is int
            and listed[0].get("state") == "OPEN"
            and listed[0].get("isDraft") is True
            and listed[0].get("headRefOid") == remote_head
            and listed[0].get("headRefName") == branch
            and listed[0].get("baseRefName") == "main"
            and marker in (listed[0].get("body") or ""),
            "single exact draft candidate PR required")
    pr = json.loads(execute("gh", "api", "repos/" + repository +
                            "/pulls/" + str(listed[0]["number"])))
    pr_base = (pr.get("base") or {}).get("sha")
    require(pr.get("number") == listed[0]["number"] and pr.get("state") == "open"
            and pr.get("draft") is True and pr.get("merged") is not True
            and (pr.get("user") or {}).get("login") == "github-actions[bot]"
            and (pr.get("user") or {}).get("type") == "Bot"
            and marker in (pr.get("body") or "")
            and (pr.get("head") or {}).get("sha") == remote_head
            and (pr.get("head") or {}).get("ref") == branch
            and ((pr.get("head") or {}).get("repo") or {}).get("full_name") == repository
            and (pr.get("base") or {}).get("ref") == "main"
            and ((pr.get("base") or {}).get("repo") or {}).get("full_name") == repository
            and type(pr_base) is str and bool(HEX_SHA.fullmatch(pr_base)),
            "REST bot identity, base, draft, branch or HEAD mismatch")
    parents = execute("git", "rev-list", "--parents", "-n", "1", remote_head).split()
    require(len(parents) == 3 and parents[0] == remote_head
            and bool(HEX_SHA.fullmatch(parents[1]))
            and bool(HEX_SHA.fullmatch(parents[2])),
            "only exact bot-ancestor + previously protected-main two-parent sync is repairable")
    original, previous_main = parents[1], parents[2]
    # REST can retain the base recorded at the prior human sync after a
    # protected caller-pin merge advances main. Accept only that exact second
    # parent or current main; arbitrary/ancestor-looking PR bases remain denied.
    require(pr_base in (previous_main, main_sha),
            "REST PR base is neither exact synchronized base nor current main")
    # The shared caller-pin update may advance protected main after the human
    # base sync. Only a strict fast-forward main ancestry is acceptable.
    execute("git", "merge-base", "--is-ancestor", previous_main, main_sha)
    approved_central = None
    if previous_main != main_sha:
        workflow_path = ".github/workflows/update-watch.yml"
        policy_path = "config/release-promotion.json"
        paths = execute("git", "diff", "--name-only", previous_main, main_sha).splitlines()
        regression_path = "tests/test_required_windows_summary.py"
        regression_cutover = set(paths) == {workflow_path, policy_path, regression_path}
        require(len(paths) == len(set(paths)) and
                (set(paths) in ({workflow_path}, {workflow_path, policy_path})
                 or regression_cutover),
                "protected main advanced beyond the exact caller/policy cutover")
        if regression_cutover:
            # Some consumers update immutable caller assertions alongside the
            # protected policy migration. Accept ONLY exact positive pin
            # substitutions, not arbitrary test edits or relaxed negatives.
            previous_workflow = execute("git", "show", previous_main + ":" + workflow_path)
            current_workflow = execute("git", "show", main_sha + ":" + workflow_path)
            old_tests = execute("git", "show", previous_main + ":" + regression_path)
            new_tests = execute("git", "show", main_sha + ":" + regression_path)
            expected_tests = old_tests
            new_pins = []
            for caller, count in (("operator-update-auto.yml", 2),
                                  ("verify-native-pr-candidate.yml", 1)):
                prefix = "pgextwin/build/.github/workflows/" + caller + "@"
                pattern = r"^    uses: " + re.escape(prefix) + r"([0-9a-f]{40})$"
                old_pins = re.findall(pattern, previous_workflow, re.M)
                current_pins = re.findall(pattern, current_workflow, re.M)
                require(len(old_pins) == len(current_pins) == 1
                        and old_pins[0] != current_pins[0]
                        and expected_tests.count(caller + "@" + old_pins[0]) == count,
                        "regression change is not an exact positive caller-pin cutover")
                expected_tests = expected_tests.replace(
                    caller + "@" + old_pins[0], caller + "@" + current_pins[0])
                new_pins.append(current_pins[0])
            require(new_tests == expected_tests and len(set(new_pins)) == 1,
                    "regression change modifies more than the three positive caller pins")
        if policy_path in paths:
            before = json.loads(execute("git", "show", previous_main + ":" + policy_path))
            after = json.loads(execute("git", "show", main_sha + ":" + policy_path))
            require(type(before) is dict and type(after) is dict
                    and type(before.get("schemaVersion")) is int
                    and type(after.get("schemaVersion")) is int
                    and before == {"schemaVersion": 1, "enabled": True,
                                   "releasePolicy": "manual-dispatch"}
                    and after == {"schemaVersion": 1, "enabled": True,
                                  "releasePolicy": "automatic-signed-schedule"}
                    and before.get("enabled") is True and after.get("enabled") is True,
                    "local publication policy is not the exact protected transition")
            approved_central = approved_automatic_candidate_policy(repository, main_sha, workflow_path)
            if regression_cutover:
                require(new_pins == [approved_central, approved_central],
                        "regression pin expectations are not the live protected central snapshot")
    require(execute("git", "log", "-1", "--format=%an", original) == "github-actions[bot]"
            and execute("git", "log", "-1", "--format=%ae", original)
                == "41898282+github-actions[bot]@users.noreply.github.com"
            and marker in execute("git", "log", "-1", "--format=%B", original),
            "original candidate must be immutable bot-authored marker commit")
    require(execute("git", "diff", "--name-only", previous_main, remote_head).strip()
            == proposal_file
            and execute("git", "rev-parse", original + ":" + proposal_file)
                == execute("git", "rev-parse", remote_head + ":" + proposal_file)
            and execute("git", "rev-parse", previous_main + ":" + proposal_file)
                == execute("git", "rev-parse", main_sha + ":" + proposal_file)
            and json.loads(execute("git", "show", remote_head + ":" + proposal_file)) == proposal,
            "synchronized tree or current main differs from immutable candidate manifest")
    runs = json.loads(execute("gh", "api", "repos/" + repository +
                              "/actions/runs?event=pull_request&head_sha=" +
                              remote_head + "&per_page=100"))
    genuine = [run for run in runs.get("workflow_runs", [])
               if run.get("event") == "pull_request"
               and run.get("head_sha") == remote_head
               and run.get("head_branch") == branch
               and run.get("path") == ".github/workflows/windows.yml"
               and run.get("status") == "completed"
               and run.get("conclusion") == "success"
               and run.get("run_attempt") == 1
               and (run.get("repository") or {}).get("full_name") == repository]
    require(len(genuine) == 1, "one genuine successful original native PR Run required")
    # Refuse a source or policy race before any bot commit. The subsequent
    # non-forced push also refuses a concurrently advanced candidate branch.
    final_main = json.loads(execute("gh", "api", "repos/" + repository + "/branches/main"))
    require(final_main.get("protected") is True
            and (final_main.get("commit") or {}).get("sha") == main_sha,
            "protected main advanced during candidate verification")
    if approved_central is not None:
        final_central = json.loads(execute("gh", "api", "--method", "GET",
                                          "repos/pgextwin/build/branches/main"))
        require(final_central.get("protected") is True
                and (final_central.get("commit") or {}).get("sha") == approved_central,
                "approved central policy advanced during candidate verification")
    # Preserve both the original bot and human sync commits; never rewrite.
    # A real scheduled GITHUB_TOKEN bot either adds an empty marker commit or
    # merges the newly protected main forward. Neither path grants CI credit.
    execute("git", "checkout", "-B", branch, "refs/remotes/origin/" + branch)
    execute("git", "config", "user.name", "github-actions[bot]")
    execute("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    if previous_main == main_sha:
        execute("git", "commit", "--allow-empty", "-m",
                "chore: reconcile verified candidate base (nonpublishing)\n\n" + marker)
    else:
        execute("git", "merge", "--no-ff", "-m",
                "chore: reconcile protected candidate base (nonpublishing)\n\n" + marker,
                main_sha)
    new_head = execute("git", "rev-parse", "HEAD")
    require(bool(HEX_SHA.fullmatch(new_head)) and new_head != remote_head
            and execute("git", "diff", "--name-only", main_sha, new_head).strip()
                == proposal_file
            and execute("git", "rev-parse", new_head + ":" + proposal_file)
                == execute("git", "rev-parse", remote_head + ":" + proposal_file)
            and json.loads(execute("git", "show", new_head + ":" + proposal_file)) == proposal,
            "bot repair must preserve exact manifest-only diff on current protected main")
    execute("git", "push", "origin", "HEAD:refs/heads/" + branch)
    print("BOT_REPAIR_NONPUBLISHING: preserved " + remote_head +
          "; new HEAD " + new_head + " requires fresh native PR CI")


def recover_failed_first_release(record, repository, proposal_file, proposal, marker,
                                 remote, prs, runs):
    """Forward-only bot-owned branch repair after a *failed* candidate dispatch.

    Only a fresh human-authorized first-attempt UPDATE on the exact protected
    main can request recovery. Previous failed run/ZIP/decision evidence remains
    immutable; never force push, reuse a failed Run ID or grant PUBLISH.
    """
    def require(ok, reason):
        if not ok:
            raise WatchError("candidate recovery DENIED: " + reason)

    require(repository in FIRST_RELEASE and record.get("firstRelease") is True
            and proposal_file == FIRST_FILE, "not the 3-repo first-release path")
    require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_ACTOR") == "ShutenOishi"
            and os.environ.get("GITHUB_TRIGGERING_ACTOR") == "ShutenOishi"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "fresh first-attempt human UPDATE required")
    main_sha = os.environ.get("GITHUB_SHA", "")
    require(bool(HEX_SHA.fullmatch(main_sha)), "missing exact main SHA")
    require(len(prs) == 1 and len(runs) == 1 and bool(remote),
            "one existing owned PR and one failed historical dispatch required")
    listed, failed = prs[0], runs[0]
    branch = record["branch"]
    number = listed.get("number")
    require(type(number) is int and number > 0 and listed.get("state") == "OPEN"
            and marker in (listed.get("body") or ""),
            "listed candidate PR missing or lacks automation marker")
    # gh pr list uses the GitHub GraphQL Actor login (which can differ from
    # REST bot login). Never infer repository bot identity from that display
    # field. Read authoritative PR metadata via authenticated, read-only REST.
    pr = json.loads(execute("gh", "api", "repos/" + repository + "/pulls/" + str(number)))
    head, base, actor = (pr.get("head") or {}), (pr.get("base") or {}), (pr.get("user") or {})
    original = head.get("sha")
    require(type(pr) is dict and pr.get("number") == number
            and pr.get("state") == "open" and pr.get("draft") is True
            and pr.get("merged") is not True and actor.get("type") == "Bot"
            and actor.get("login") == "github-actions[bot]"
            and head.get("ref") == branch and (head.get("repo") or {}).get("full_name") == repository
            and base.get("ref") == "main" and (base.get("repo") or {}).get("full_name") == repository
            and marker in (pr.get("body") or "") and bool(HEX_SHA.fullmatch(str(original))),
            "REST candidate PR ownership, branch, draft or HEAD changed")
    # Cross-check the one CLI listing's branch and head if supplied, but its
    # GraphQL author.login is *not* a stable REST bot identity.
    require(listed.get("headRefOid") in (None, original)
            and listed.get("headRefName") in (None, branch)
            and listed.get("baseRefName") in (None, "main")
            and listed.get("isDraft") in (None, True),
            "CLI PR listing and REST HEAD/branch disagree")
    require(re.fullmatch(re.escape(original) + r"\s+refs/heads/" + re.escape(branch), remote.strip()),
            "remote candidate HEAD differs from bot PR; no overwrite")
    require(type(failed) is dict and type(failed.get("databaseId")) is int
            and failed["databaseId"] > 0
            and failed.get("event") == "workflow_dispatch"
            and failed.get("status") == "completed"
            and failed.get("conclusion") == "failure"
            and failed.get("headSha") == original,
            "only a genuine failed exact-HEAD dispatch may be recovered")
    verified_run = json.loads(execute("gh", "api", "repos/" + repository +
                                      "/actions/runs/" + str(failed["databaseId"])))
    require(type(verified_run) is dict and verified_run.get("id") == failed["databaseId"]
            and verified_run.get("event") == "workflow_dispatch"
            and verified_run.get("status") == "completed"
            and verified_run.get("conclusion") == "failure"
            and verified_run.get("run_attempt") == 1
            and verified_run.get("head_sha") == original
            and verified_run.get("head_branch") == branch
            and verified_run.get("path") == ".github/workflows/windows.yml"
            and (verified_run.get("actor") or {}).get("login") == "github-actions[bot]"
            and (verified_run.get("repository") or {}).get("full_name") == repository,
            "REST failed candidate Run identity or immutable conclusion mismatch")
    main = json.loads(execute("gh", "api", "repos/" + repository + "/branches/main"))
    require(type(main) is dict and main.get("protected") is True and
            (main.get("commit") or {}).get("sha") == main_sha,
            "current protected main must match fresh human authorization")
    require(execute("git", "rev-parse", "HEAD") == main_sha,
            "checkout not on exactly the operator-approved main")
    require(execute("git", "rev-parse", "refs/remotes/origin/" + branch) == original
            and execute("git", "log", "-1", "--format=%an", original) == "github-actions[bot]",
            "remote candidate HEAD must be the original bot-authored commit")
    # No rebases, force pushes, or replacement of historical candidate bytes.
    # This merge remains a descendant of the old original candidate commit.
    execute("git", "checkout", "-B", branch, "refs/remotes/origin/" + branch)
    execute("git", "config", "user.name", "github-actions[bot]")
    execute("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    execute("git", "merge", "--no-ff", "-m", "chore: refresh immutable candidate base\n\n" + marker, main_sha)
    new_head = execute("git", "rev-parse", "HEAD")
    require(bool(HEX_SHA.fullmatch(new_head)) and new_head != original,
            "candidate base sync did not create a new HEAD")
    require(execute("git", "diff", "--name-only", main_sha, new_head).strip() == proposal_file,
            "candidate changed anything other than its immutable intent")
    require(json.loads(execute("git", "show", "HEAD:" + proposal_file)) == proposal,
            "candidate intent changed during base sync")
    # A non-forced push fails if the branch moved concurrently, protecting the
    # original bot-owned PR and its old forensic record.
    execute("git", "push", "origin", "HEAD:refs/heads/" + branch)
    print("RECOVERY: retained failed Run " + str(failed["databaseId"]) +
          " as FAILURE; new exact-head Windows dispatch " + new_head)
    execute("gh", "workflow", "run", "windows.yml", "--repo", repository, "--ref", branch)


def propose(record, manifest_path, repository, watch_path, policy_path=None):
    if record.get("status") != "candidate" or repository != os.environ.get("GITHUB_REPOSITORY"):
        raise WatchError("untrusted candidate caller")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or not os.environ.get("GH_TOKEN"):
        raise WatchError("proposer requires trusted main and GH_TOKEN")
    propose_candidate(record, manifest_path, repository, watch_path, policy_path)


def regenerated_candidate_id(predecessor_id, predecessor_number):
    """Hash each closed predecessor into its successor so unchanged PR history replays the same chain."""
    material = f"pgextwin-candidate-regeneration:v1\n{predecessor_id}\n{predecessor_number}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def writer_pull_request(repository, number, writer):
    # GraphQL author.login uses app/<slug> for App authors. The authenticated
    # REST user supplies the configured <slug>[bot] login.
    try:
        pr = json.loads(execute("gh", "api", f"repos/{repository}/pulls/{number}"))
    except ValueError as exc:
        raise WatchError("invalid candidate PR REST response") from exc
    actor = pr.get("user") if isinstance(pr, dict) else None
    if (not isinstance(actor, dict) or type(pr.get("number")) is not int or pr["number"] != number
            or actor.get("type") != "Bot" or actor.get("login") != writer[0]
            or type(actor.get("id")) is not int or actor["id"] != writer[1]):
        raise WatchError("candidate PR does not belong to the configured writer")
    return pr


def candidate_pull_requests(repository, branch, marker, writer):
    writer = DEFAULT_LOCAL_WRITER if writer is None else writer
    if (not isinstance(writer, (tuple, list)) or len(writer) != 2
            or not isinstance(writer[0], str) or not writer[0]
            or type(writer[1]) is not int or writer[1] <= 0):
        raise WatchError("invalid configured candidate writer")
    try:
        prs = json.loads(execute("gh", "pr", "list", "--repo", repository, "--head", branch, "--state", "all",
                                "--limit", "100", "--json",
                                "number,body,state,url,headRefOid,headRefName,baseRefName,isDraft,isCrossRepository"))
    except ValueError as exc:
        raise WatchError("invalid candidate PR listing response") from exc
    if not isinstance(prs, list):
        raise WatchError("candidate PR listing must be an array")
    if len(prs) > 1:
        raise WatchError("multiple PRs for candidate")
    if not prs:
        return prs
    pr = prs[0]
    if not isinstance(pr, dict):
        raise WatchError("candidate PR must be an object")
    number = pr.get("number")
    if type(number) is not int or number <= 0:
        raise WatchError("candidate PR number is invalid")
    if (pr.get("headRefName") != branch or pr.get("baseRefName") != "main"
            or pr.get("isCrossRepository") is not False):
        raise WatchError("candidate PR has an unexpected head or base")
    body = pr.get("body")
    if (not isinstance(body, str) or marker not in body
            or body.count("<!-- " + MARKER_PREFIX + ":") != 1):
        raise WatchError("candidate PR is not automation-owned")
    state = pr.get("state")
    if state not in ("OPEN", "CLOSED", "MERGED"):
        raise WatchError("candidate PR state is invalid")
    if not isinstance(pr.get("url"), str) or not pr["url"]:
        raise WatchError("candidate PR URL is invalid")
    rest_pr = writer_pull_request(repository, number, writer)
    if (rest_pr.get("state") != ("open" if state == "OPEN" else "closed")
            or rest_pr.get("merged") is not (state == "MERGED")):
        raise WatchError("candidate PR state differs between GitHub APIs")
    for side, expected_ref in (("head", branch), ("base", "main")):
        ref = rest_pr.get(side)
        repo = ref.get("repo") if isinstance(ref, dict) else None
        if (not isinstance(repo, dict) or repo.get("full_name") != repository
                or ref.get("ref") != expected_ref):
            raise WatchError("candidate PR has an unexpected REST head or base")
    oid = pr.get("headRefOid")
    if not isinstance(oid, str) or not HEX_SHA.fullmatch(oid) or rest_pr["head"].get("sha") != oid:
        raise WatchError("candidate PR head differs between GitHub APIs")
    rest_body = rest_pr.get("body")
    if (not isinstance(rest_body, str) or marker not in rest_body
            or rest_body.count("<!-- " + MARKER_PREFIX + ":") != 1):
        raise WatchError("candidate PR REST marker is missing, duplicate or mismatched")
    return prs


def verify_created_regeneration(repository, url, writer, branch, ref, body):
    prefix = f"https://github.com/{repository}/pull/"
    number = url.removeprefix(prefix)
    if not url.startswith(prefix) or not re.fullmatch(r"[1-9][0-9]*", number):
        raise WatchError("created candidate PR URL is invalid")
    pr = writer_pull_request(repository, int(number), writer)
    head, base = pr.get("head"), pr.get("base")
    for side in (head, base):
        repo = side.get("repo") if isinstance(side, dict) else None
        if not isinstance(repo, dict) or repo.get("full_name") != repository:
            raise WatchError("created regenerated PR has an unexpected repository")
    if (pr.get("state") != "open"
            or pr.get("merged") is not False or pr.get("draft") is not True
            or not isinstance(pr.get("body"), str) or pr["body"].strip() != body.strip()
            or head.get("ref") != branch or base.get("ref") != "main"
            or head.get("sha") != execute("git", "rev-parse", ref)
            or base.get("sha") != execute("git", "log", "-1", "--format=%P", ref)):
        raise WatchError("created regenerated PR differs from the exact proposal")


def propose_candidate(record, manifest_path, repository, watch_path, policy_path=None, *,
                      writer=None, fetch=api, origin_body=None, on_created=None,
                      authority_policy=None, now=None):
    """Apply a proposal after the local or central caller authenticates its context."""
    if repository == candidate_branch.CENTRAL_REPOSITORY:
        style = "central"
        extension = record.get("extension")
        manifest_path = str(manifest_path)
        try:
            if authority_policy is None:
                authority_policy = local_auth_central.load_policy(BUILD_ROOT)
            local_auth_central.validate_policy(authority_policy, datetime.now(timezone.utc) if now is None else now)
        except local_auth_central.TicketRejected as exc:
            raise WatchError(exc.code) from exc
    else:
        config = read(manifest_path)
        extension = config["name"]
        try:
            style = candidate_branch.branch_style_for_repository(repository, extension)
            parsed = candidate_branch.parse_branch(record.get("branch"), expected_extension=extension)
        except ValueError as exc:
            raise WatchError("invalid immutable candidate branch") from exc
        if parsed.style != style or parsed.candidate_id != record.get("candidateId"):
            raise WatchError("invalid immutable candidate branch")
    # Enforce the live central authority again immediately before any mutation.
    import importlib.util
    fleet_path = Path(__file__).with_name("fleet-control.py")
    spec = importlib.util.spec_from_file_location("fleet_control", fleet_path)
    fleet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fleet)
    policy = publication_policy.load_candidate_policy(BUILD_ROOT) if policy_path is None else read(policy_path)
    registry = fleet.get_live() if writer is None else fleet.get_live(lambda url, token: fetch(url))
    if style == "central":
        registered = local_auth_central.registered_extensions(fleet.validate(registry))

        def enforce_scope(candidate_branch_name, candidate_id, changes, *, allow_legacy_reuse=False):
            try:
                local_auth_central.enforce_central_candidate(
                    policy=authority_policy, now=now, repository=repository, extension=extension,
                    registered_extensions=registered, branch=candidate_branch_name,
                    expected_candidate_id=candidate_id, changes=changes,
                    allow_legacy_reuse=allow_legacy_reuse)
            except local_auth_central.TicketRejected as exc:
                raise WatchError(exc.code) from exc

        def check_diff(base, head, branch, candidate_id, *, allow_legacy_reuse=False):
            try:
                changes = local_auth_central.changes_from_name_status(
                    execute("git", "diff", "--name-status", "-z", "-M", "-C", base, head))
            except local_auth_central.TicketRejected as exc:
                raise WatchError(exc.code) from exc
            except UnicodeError as exc:
                raise WatchError("MALFORMED_CHANGE") from exc
            enforce_scope(branch, candidate_id, changes, allow_legacy_reuse=allow_legacy_reuse)

        enforce_scope(record.get("branch"), record.get("candidateId"),
                      [{"filename": manifest_path, "status": "modified"}])
        parsed = candidate_branch.parse_branch(record["branch"], allow_legacy=False)
        if parsed.candidate_id != record.get("candidateId"):
            raise WatchError("BRANCH_CANDIDATE_ID_MISMATCH")
        if record.get("firstRelease") is True:
            raise WatchError("central repository does not accept first-release candidates")
        config = read(manifest_path)

    allowed, mode = fleet.decide(registry, "pgextwin/" + extension, config,
                                 load_watch(config, watch_path), "candidate", policy)
    if not allowed:
        raise WatchError("candidate proposal denied by live central policy: " + mode)
    if config["upstream"]["repository"] != record["repository"]:
        raise WatchError("upstream repository changed")
    proposal_file = manifest_path
    proposal = apply(config, record, pin_remaining=True, fetch=fetch)
    if record.get("firstRelease") is True:
        if not no_formal_release(repository, fetch):
            raise WatchError("formal Release exists; no new first-release candidate")
        if Path(FIRST_FILE).exists():
            raise WatchError("initial Release candidate intent already merged")
        proposal_file = FIRST_FILE
        proposal = initial_intent(config, record)
    for update in record["updates"]:
        if peel_tag(record["repository"], update["ref"], fetch) != update["commit"]:
            raise WatchError("upstream tag moved after plan")

    def lookup(candidate_id, marker):
        branch = candidate_branch.format_branch(extension, candidate_id, style)
        prs = candidate_pull_requests(repository, branch, marker, writer)
        if style == "central":
            legacy_branch = candidate_branch.format_branch(extension, candidate_id, "legacy")
            legacy_prs = candidate_pull_requests(repository, legacy_branch, marker, writer)
            if prs and legacy_prs:
                raise WatchError("ambiguous candidate PRs exist in both legacy and central branch formats")
            if legacy_prs:
                return legacy_branch, legacy_prs
        return branch, prs

    candidate_id = parsed.candidate_id
    predecessor = None
    seen_ids = set()
    while True:
        if candidate_id in seen_ids:
            raise WatchError("candidate regeneration repeats a candidate ID")
        if len(seen_ids) > 8:
            raise WatchError("candidate regeneration chain exceeds depth limit")
        seen_ids.add(candidate_id)
        marker = "<!-- " + MARKER_PREFIX + ":" + candidate_id + " -->"
        branch, prs = lookup(candidate_id, marker)
        if not prs or prs[0]["state"] == "OPEN":
            break
        if prs[0]["state"] == "MERGED":
            return
        predecessor = candidate_id, prs[0]["number"]
        candidate_id = regenerated_candidate_id(*predecessor)

    record = {**record, "candidateId": candidate_id, "branch": branch}
    if record.get("firstRelease") is True:
        proposal["candidateId"] = candidate_id
    remote = execute("git", "ls-remote", "--heads", "origin", "refs/heads/" + branch)
    if remote:
        execute("git", "fetch", "--no-tags", "origin", "refs/heads/" + branch + ":refs/remotes/origin/" + branch)
        remote_ref = "refs/remotes/origin/" + branch
        if prs:
            fetched_head = execute("git", "rev-parse", remote_ref)
            if not HEX_SHA.fullmatch(fetched_head) or fetched_head != prs[0]["headRefOid"]:
                raise WatchError("fetched candidate branch head differs from candidate PR")
        message = execute("git", "log", "-1", "--format=%B", remote_ref)
        if marker not in message:
            if style == "central" or writer is not None:
                raise WatchError("central writer requires the original immutable candidate marker")
            repair_exact_bot_candidate_base_sync(
                record, repository, proposal_file, proposal, marker, branch)
            return
        if style == "central":
            parsed_remote = candidate_branch.parse_branch(branch)
            check_diff("HEAD", remote_ref, branch, candidate_id,
                       allow_legacy_reuse=parsed_remote.style == "legacy")
        actual = json.loads(execute("git", "show", remote_ref + ":" + proposal_file))
        if actual != proposal:
            raise WatchError("existing branch differs from immutable candidate")
        if writer is not None and (
                execute("git", "log", "-1", "--format=%P", remote_ref) != execute("git", "rev-parse", "HEAD")
                or style == "legacy" and execute("git", "diff", "--name-only", "HEAD", remote_ref) != proposal_file):
            raise WatchError("central writer cannot reuse a branch with a changed base or extra files")
    elif prs:
        raise WatchError("open candidate PR has no existing remote branch")
    else:
        if lookup(candidate_id, marker)[1]:
            raise WatchError("candidate PR appeared before creating its branch")
        execute("git", "checkout", "-b", branch)
        Path(proposal_file).write_text(json.dumps(proposal, indent=2) + "\n", encoding="utf-8")
        login, user_id = DEFAULT_LOCAL_WRITER if writer is None else writer
        execute("git", "config", "user.name", login)
        execute("git", "config", "user.email", f"{user_id}+{login}@users.noreply.github.com")
        execute("git", "add", "--", proposal_file)
        execute("git", "commit", "-m", "chore: propose upstream candidate\n\n" + marker)
        if style == "central":
            check_diff("HEAD~1", "HEAD", branch, candidate_id)
        execute("git", "push", "--set-upstream", "origin", branch)
    if prs:
        url = prs[0]["url"]
    else:
        body = [marker, "## Automated upstream Windows candidate (NOT a Release)", "",
                ("FIRST RELEASE: source pins unchanged; sole diff is a new immutable intent file."
                 if record.get("firstRelease") is True else "Stable upstream version change."),
                "This PR was created by Step 19 and is draft until reviewed.",
                "The candidate CI is explicitly dispatched because GITHUB_TOKEN PR CI may await approval.",
                "No Release, Catalog or Website mutation occurs.", "",
                "| PG series | Previous | Candidate | Pinned upstream commit | Release notes |",
                "| --- | --- | --- | --- | --- |"]
        for u in record["updates"]:
            body.append("| " + str(u["major"] or "all configured") + " | " +
                        u["oldVersion"] + " (" + u["oldRef"] + ") | " +
                        u["version"] + " (" + u["ref"] + ") | " + u["commit"] +
                        " | " + str(u["notes"]) + " |")
        body += ["", "Manual review: source diff, license, export audit, Test Contract, Windows compatibility.",
                 "A separate attested Release build and publication gate remain mandatory."]
        ref = "refs/remotes/origin/" + branch if remote else "HEAD"
        if predecessor is not None:
            previous_id, number = predecessor
            body.extend(["", f"Regenerated from closed PR [#{number}](https://github.com/{repository}/pull/{number}) "
                             f"(candidate `{previous_id}`)."])
        if origin_body is not None:
            body.append(origin_body(ref, record, predecessor))
        body_path = Path(os.environ.get("RUNNER_TEMP", ".")) / "pgextwin-candidate-pr.md"
        body_text = "\n".join(body) + "\n"
        body_path.write_text(body_text, encoding="utf-8")
        if lookup(candidate_id, marker)[1]:
            raise WatchError("candidate PR appeared while preparing its branch")
        url = execute("gh", "pr", "create", "--repo", repository, "--head", branch, "--base", "main",
                      "--title", "chore: candidate " + record["extension"] + " " +
                      record["updates"][0]["version"], "--body-file", str(body_path), "--draft")
        if on_created is not None:
            on_created(url, record, predecessor)
        elif predecessor is not None and writer is not None:
            # Preserve the local writer path when it has no origin callbacks.
            verify_created_regeneration(repository, url, writer, branch, ref, body_text)
    print("Candidate PR: " + url)
    runs = json.loads(execute("gh", "run", "list", "--repo", repository, "--workflow", "windows.yml",
                              "--branch", branch, "--event", "workflow_dispatch", "--limit", "100",
                              "--json", "databaseId,event,status,conclusion,url,headSha"))
    if runs:
        # General fleet retains once-only behavior. Only Wave3 first Release
        # can recover, and only from one failed exact-HEAD dispatch with a
        # fresh real human UPDATE on protected main.
        if record.get("firstRelease") is True:
            if (len(runs) == 1 and runs[0].get("status") == "completed"
                    and runs[0].get("conclusion") == "success"
                    and len(prs) == 1 and runs[0].get("headSha") == prs[0].get("headRefOid")):
                print("Exact candidate Windows dispatch already succeeded; do not repeat")
                return
            recover_failed_first_release(record, repository, proposal_file, proposal,
                                         marker, remote, prs, runs)
            return
        print("Candidate dispatched previously; no repeat build")
        return
    execute("gh", "workflow", "run", "windows.yml", "--repo", repository, "--ref", branch)
    print("Windows CI dispatched for " + branch)


def suppressed(extension, mode):
    """Emit an auditable central-policy decision without contacting upstream."""
    from datetime import datetime, timezone
    if mode not in {"WATCH", "OFF"}:
        raise WatchError("only WATCH/OFF may suppress candidate planning")
    return {
        "schemaVersion": 1,
        "extension": extension["name"],
        "repository": extension["upstream"]["repository"],
        "detectedAt": datetime.now(timezone.utc).isoformat(),
        "releasePolicy": "manual-only",
        "status": "centrally-suppressed",
        "mode": mode,
        "updates": [],
    }


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="action", required=True)
    a = sub.add_parser("plan")
    a.add_argument("--lifecycle")
    a.add_argument("--policy")
    for key in ("extension", "watch", "output"):
        a.add_argument("--" + key, required=True)
    b = sub.add_parser("propose")
    b.add_argument("--policy")
    for key in ("record", "extension", "repository", "watch"):
        b.add_argument("--" + key, required=True)
    d = sub.add_parser("record-suppressed")
    d.add_argument("--extension", required=True)
    d.add_argument("--mode", required=True, choices=["WATCH", "OFF"])
    d.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        if args.action == "record-suppressed":
            record = suppressed(read(args.extension), args.mode)
            Path(args.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(record))
        elif args.action == "plan":
            policy = publication_policy.load_candidate_policy(BUILD_ROOT) if args.policy is None else read(args.policy)
            extension = read(args.extension)
            record = plan(extension, load_watch(extension, args.watch), policy,
                          lifecycle=read(args.lifecycle) if args.lifecycle else None)
            Path(args.output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("candidate=" + str(record["status"] == "candidate").lower() + "\n")
            print(json.dumps(record))
        else:
            propose(read(args.record), args.extension, args.repository, args.watch, args.policy)
        return 0
    except (WatchError, OSError, ValueError, KeyError, TypeError) as err:
        print("Candidate automation failed CLOSED: " + str(err), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
