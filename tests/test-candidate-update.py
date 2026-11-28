from __future__ import annotations
import base64
import copy
import json
import os
import tempfile
from unittest.mock import Mock, patch
import importlib.util
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
import update_watch_lib
from candidate_branch import format_branch, parse_branch
from update_watch_lib import WatchError
import fleet_candidate_origin as origin_module
spec = importlib.util.spec_from_file_location("candidate_update", ROOT/"scripts/candidate-update.py")
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SHA = "1"*40
TAG_SHA = "2"*40
EXT={"schemaVersion":1,"name":"plpgsql_check","upstream":{"repository":"test/ext","ref":"v2.10.13","version":"2.10.13"},"postgresql":{"majors":[15,16,17,18]}}
WATCH={"schemaVersion":1,"source":"github","repository":"test/ext","strategy":"github-releases","prereleases":False,"stableTagPattern":r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$"}
POLICY={"schemaVersion":1,"enabled":True,"releasePolicy":"manual-only","workflow":"windows.yml"}

APP_WRITER = ("pgextwin-fleet-candidate[bot]", 999001)
LOCAL_REPO = "pgextwin/plpgsql_check"
CENTRAL_REPO = "pgextwin/build"
PR_HEAD = "b" * 40
REGISTRY_RESPONSE = {"encoding": "base64", "content": base64.b64encode(
    (ROOT / "metadata/automation-fleet.json").read_bytes()).decode()}

def fixture(url):
    if url.endswith("/releases?per_page=100"):
        return [{"tag_name":"v2.10.13","prerelease":False,"draft":False},
                {"tag_name":"v2.10.14-rc1","prerelease":True,"draft":False},
                {"tag_name":"v2.10.14","prerelease":False,"draft":False,"html_url":"https://github.com/test/ext/releases/tag/v2.10.14"}]
    if url.endswith("/git/ref/tags/v2.10.14"): return {"object":{"type":"tag","sha":TAG_SHA}}
    if url.endswith("/git/tags/"+TAG_SHA): return {"tag":"v2.10.14","object":{"type":"commit","sha":SHA}}
    raise WatchError("unexpected fixture URL "+url)

def expect_fail(f):
    try: f()
    except WatchError: return
    raise AssertionError("expected fail-closed WatchError")

def candidate_marker(branch):
    return "<!-- " + c.MARKER_PREFIX + ":" + parse_branch(branch).candidate_id + " -->"


def list_pr(repo, branch, number=114, state="OPEN"):
    return {"number": number, "body": candidate_marker(branch), "state": state,
            "url": f"https://github.com/{repo}/pull/{number}", "headRefOid": PR_HEAD,
            "headRefName": branch, "baseRefName": "main", "isCrossRepository": False}


def rest_pr(repo, listed, writer):
    return {"number": listed["number"], "body": listed["body"],
            "state": "open" if listed["state"] == "OPEN" else "closed",
            "merged": listed["state"] == "MERGED", "draft": True,
            "user": {"type": "Bot", "login": writer[0], "id": writer[1]},
            "head": {"ref": listed["headRefName"], "sha": listed["headRefOid"], "repo": {"full_name": repo}},
            "base": {"ref": "main", "sha": "a" * 40, "repo": {"full_name": repo}}}


def assert_no_writes_or_dispatch(calls):
    writes = {("git", "checkout"), ("git", "add"), ("git", "commit"), ("git", "push"),
              ("git", "config"), ("gh", "release")}
    assert not any(args[:2] in writes or args[:3] in {("gh", "pr", "create"), ("gh", "workflow", "run")}
                   for args in calls), calls


def exercise_proposer_safety():
    """Simulate existing branches/PRs and GitHub API failures; never make network writes."""
    record=c.plan(EXT,WATCH,POLICY,fixture)
    marker="<!-- "+c.MARKER_PREFIX+":"+record["candidateId"]+" -->"
    central=json.loads((ROOT/"metadata/automation-fleet.json").read_text(encoding="utf-8"))
    response={"encoding":"base64","content":base64.b64encode(json.dumps(central).encode()).decode()}
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        manifest = root / "extension.json"
        manifest.write_text(json.dumps(EXT))
        original_manifest = manifest.read_bytes()
        (root/"watch.json").write_text(json.dumps(WATCH))
        (root/"policy.json").write_text(json.dumps(POLICY))
        scenarios=[
            ("duplicate", [{"number":1,"body":marker,"state":"OPEN","url":"https://example/1"},
                           {"number":2,"body":marker,"state":"OPEN","url":"https://example/2"}], [], True),
            ("human", [{"number":1,"body":"not owned","state":"OPEN","url":"https://example/1"}], [], True),
            ("prior-run", [{"number":1,"body":marker,"state":"OPEN","url":"https://example/1"}],
                          [{"databaseId":100,"event":"workflow_dispatch","status":"completed","conclusion":"success"}], False),
            ("merged", [{"number":1,"body":marker,"state":"MERGED","url":"https://example/1"}], [], False),
            ("unknown-state", [{"number":1,"body":marker,"state":"UNKNOWN","url":"https://example/1"}], [], True),
            ("unowned-closed", [{"number":1,"body":"not owned","state":"CLOSED","url":"https://example/1"}], [], True),
        ]
        for name,prs,runs,must_fail in scenarios:
            calls=[]
            def execute(*args):
                calls.append(args)
                if args[:2]==("git","ls-remote"): return "ab refs/heads/"+record["branch"]
                if args[:2]==("git","fetch"): return ""
                if args[:2]==("git","log"): return "candidate branch\n"+marker
                if args[:2]==("git","show"): return json.dumps(c.apply(EXT,record))
                if args[:3]==("gh","pr","list"):
                    return json.dumps([dict(pr, headRefName=record["branch"], baseRefName="main",
                                            isCrossRepository=False, headRefOid=PR_HEAD) for pr in prs])
                if args == ("gh", "api", f"repos/{LOCAL_REPO}/pulls/1"):
                    listed = list_pr(LOCAL_REPO, record["branch"], 1, prs[0]["state"])
                    return json.dumps(rest_pr(LOCAL_REPO, listed, ("github-actions[bot]", 41898282)))
                if args[:3]==("gh","run","list"): return json.dumps(runs)
                raise AssertionError("unexpected or mutating command: "+repr(args))
            with patch.dict(os.environ,{"GITHUB_REPOSITORY":"pgextwin/plpgsql_check",
                                      "GITHUB_REF":"refs/heads/main","GH_TOKEN":"fixture-token"}), \
                 patch.object(update_watch_lib,"github_get_json",lambda url,token:response), \
                 patch.object(c,"execute",execute),patch.object(c,"peel_tag",lambda *args,**kwargs:SHA):
                task=lambda:c.propose(record,str(root/"extension.json"),"pgextwin/plpgsql_check",
                                      str(root/"watch.json"),str(root/"policy.json"))
                if must_fail: expect_fail(task)
                else: assert task() is None
            assert_no_writes_or_dispatch(calls)
            if name in ("prior-run", "merged"):
                assert calls[0][:3] == ("gh", "pr", "list")
                assert calls[0][calls[0].index("--state") + 1] == "all"
                assert calls[1] == ("gh", "api", f"repos/{LOCAL_REPO}/pulls/1")
            if name == "merged":
                assert len(calls) == 2
        calls = []
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": LOCAL_REPO,
                                     "GITHUB_REF": "refs/heads/main", "GH_TOKEN": "fixture-token"}), \
             patch.object(update_watch_lib, "github_get_json", side_effect=WatchError("API outage")), \
             patch.object(c, "execute", side_effect=lambda *args: calls.append(args)):
            expect_fail(lambda: c.propose(record, str(manifest), LOCAL_REPO,
                                          str(root / "watch.json"), str(root / "policy.json")))
        assert calls == []
        assert_no_writes_or_dispatch(calls)
        assert manifest.read_bytes() == original_manifest


def exercise_upstream_and_pr_lookup_outages():
    """TC-07 covers the local entry point and central/App writer."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        manifest, watch = root / "extension.json", root / "watch.json"
        manifest.write_text(json.dumps(EXT), encoding="utf-8")
        watch.write_text(json.dumps(WATCH), encoding="utf-8")
        original = manifest.read_bytes()
        for repo, style, writer in ((LOCAL_REPO, "legacy", None), (CENTRAL_REPO, "central", APP_WRITER)):
            record = c.plan(EXT, WATCH, POLICY, fixture, branch_style=style)
            for outage in ("tag", "list", "rest"):
                reads, calls = [], []

                def fetch(url):
                    reads.append(url)
                    if url.endswith("/contents/metadata/automation-fleet.json?ref=main"):
                        return REGISTRY_RESPONSE
                    if outage == "tag" and "/git/ref/tags/" in url:
                        raise WatchError("tag API outage")
                    return fixture(url)

                def execute(*args):
                    calls.append(args)
                    if args[:3] == ("gh", "pr", "list"):
                        if outage == "list":
                            raise WatchError("listing API outage")
                        return json.dumps([list_pr(repo, record["branch"])])
                    if args == ("gh", "api", f"repos/{repo}/pulls/114") and outage == "rest":
                        raise WatchError("REST PR API outage")
                    raise AssertionError(args)

                with patch.dict(os.environ, {"GITHUB_REPOSITORY": repo, "GITHUB_REF": "refs/heads/main",
                                            "GH_TOKEN": "fixture", "RUNNER_TEMP": temp}), \
                     patch.object(c, "github_get_json", side_effect=lambda url, token: fetch(url)), \
                     patch.object(update_watch_lib, "github_get_json", side_effect=lambda url, token: fetch(url)), \
                     patch.object(c, "execute", execute):
                    if writer is None:
                        expect_fail(lambda: c.propose(record, str(manifest), repo, str(watch)))
                    else:
                        expect_fail(lambda: c.propose_candidate(
                            record, str(manifest), repo, str(watch), writer=writer, fetch=fetch))
                assert any("/git/ref/tags/" in url for url in reads), (repo, outage)
                assert len(calls) == {"tag": 0, "list": 1, "rest": 2}[outage], (repo, outage, calls)
                assert_no_writes_or_dispatch(calls)
                assert manifest.read_bytes() == original


def exercise_writer_identity_normalization():
    """TC-10 authenticates the GraphQL App author via the independent REST bot user."""
    record = c.plan(EXT, WATCH, POLICY, fixture, branch_style="central")
    branch = record["branch"]
    marker = candidate_marker(branch)
    scenarios = [
        ("graphql-app-author-accepted", "OPEN", None),
        ("rest-type", "OPEN", lambda pr: pr["user"].update(type="User")),
        ("rest-login", "OPEN", lambda pr: pr["user"].update(login="other-app[bot]")),
        ("rest-id", "OPEN", lambda pr: pr["user"].update(id=999002)),
        ("rest-id-type", "OPEN", lambda pr: pr["user"].update(id=str(APP_WRITER[1]))),
        ("rest-number", "OPEN", lambda pr: pr.update(number=999)),
        ("rest-state", "OPEN", lambda pr: pr.update(state="closed")),
        ("closed-is-merged", "CLOSED", lambda pr: pr.update(merged=True)),
        ("open-is-merged", "OPEN", lambda pr: pr.update(merged=True)),
        ("merged-is-unmerged", "MERGED", lambda pr: pr.update(merged=False)),
        ("rest-head-ref", "OPEN", lambda pr: pr["head"].update(ref="main")),
        ("rest-base-ref", "OPEN", lambda pr: pr["base"].update(ref="other")),
        ("rest-head-repo", "OPEN", lambda pr: pr["head"]["repo"].update(full_name=LOCAL_REPO)),
        ("rest-base-repo", "OPEN", lambda pr: pr["base"]["repo"].update(full_name=LOCAL_REPO)),
        ("rest-head-sha", "OPEN", lambda pr: pr["head"].update(sha="0" * 40)),
        ("rest-marker-missing", "OPEN", lambda pr: pr.update(body="missing")),
        ("rest-marker-duplicate", "OPEN", lambda pr: pr.update(body=f"{marker}\n{marker}")),
    ]
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        manifest, watch = root / "extension.json", root / "watch.json"
        manifest.write_text(json.dumps(EXT), encoding="utf-8")
        watch.write_text(json.dumps(WATCH), encoding="utf-8")
        original = manifest.read_bytes()
        for name, state, mutate in scenarios:
            listed = list_pr(CENTRAL_REPO, branch, state=state)
            listed["author"] = {"login": "app/pgextwin-fleet-candidate"}
            rest = rest_pr(CENTRAL_REPO, listed, APP_WRITER)
            if mutate:
                mutate(rest)
            calls = []

            def execute(*args):
                calls.append(args)
                if args[:3] == ("gh", "pr", "list"):
                    return json.dumps([listed] if branch in args else [])
                if args == ("gh", "api", f"repos/{CENTRAL_REPO}/pulls/114"):
                    return json.dumps(rest)
                if args[:2] == ("git", "ls-remote"):
                    return f"{PR_HEAD} refs/heads/{branch}"
                if args[:2] == ("git", "fetch"):
                    return ""
                if args[:2] == ("git", "log"):
                    return rest["base"]["sha"] if "--format=%P" in args else marker
                if args[:2] == ("git", "rev-parse"):
                    return rest["base"]["sha"]
                if args[:2] == ("git", "show"):
                    return json.dumps(c.apply(EXT, record))
                if args[:2] == ("git", "diff"):
                    return str(manifest)
                if args[:3] == ("gh", "run", "list"):
                    return "[]"
                if args[:3] == ("gh", "workflow", "run"):
                    return ""
                raise AssertionError(args)

            with patch.object(c, "execute", execute), patch.object(c, "peel_tag", return_value=SHA):
                def task():
                    return c.propose_candidate(record, str(manifest), CENTRAL_REPO, str(watch),
                                               writer=APP_WRITER, fetch=lambda url: REGISTRY_RESPONSE)

                if mutate:
                    expect_fail(task)
                else:
                    assert task() is None
            assert calls[1] == ("gh", "api", f"repos/{CENTRAL_REPO}/pulls/114"), name
            if mutate:
                assert_no_writes_or_dispatch(calls)
                assert manifest.read_bytes() == original, name
            else:
                assert sum(args[:3] == ("gh", "workflow", "run") for args in calls) == 1, name


def exercise_new_candidate_positive():
    """Mock the complete new-branch -> draft-PR -> Windows dispatch path; no live PR."""
    record=c.plan(EXT,WATCH,POLICY,fixture)
    marker="<!-- "+c.MARKER_PREFIX+":"+record["candidateId"]+" -->"
    central=json.loads((ROOT/"metadata/automation-fleet.json").read_text(encoding="utf-8"))
    response={"encoding":"base64","content":base64.b64encode(json.dumps(central).encode()).decode()}
    with tempfile.TemporaryDirectory() as temp:
        root=Path(temp)
        manifest=root/"extension.json"
        manifest.write_text(json.dumps(EXT),encoding="utf-8")
        (root/"watch.json").write_text(json.dumps(WATCH),encoding="utf-8")
        (root/"policy.json").write_text(json.dumps(POLICY),encoding="utf-8")
        commands=[]
        def execute(*args):
            commands.append(args)
            if args[:2]==("git","ls-remote"): return ""
            if args[:3]==("gh","pr","list"): return "[]"
            if args[:3]==("gh","pr","create"): return "https://example.invalid/draft/1"
            if args[:3]==("gh","run","list"): return "[]"
            if args[:3]==("gh","workflow","run"): return ""
            if args[0]=="git": return ""
            raise AssertionError("unexpected operation "+repr(args))
        with patch.dict(os.environ,{"GITHUB_REPOSITORY":"pgextwin/plpgsql_check",
                                    "GITHUB_REF":"refs/heads/main","GH_TOKEN":"fixture-token",
                                    "RUNNER_TEMP":temp}), \
             patch.object(update_watch_lib,"github_get_json",lambda url,token:response), \
             patch.object(c,"execute",execute), \
             patch.object(c,"peel_tag",lambda *args,**kwargs:SHA):
            assert c.propose(record,str(manifest),"pgextwin/plpgsql_check",
                             str(root/"watch.json"),str(root/"policy.json")) is None
        updated=json.loads(manifest.read_text(encoding="utf-8"))
        assert updated["upstream"]["commit"]==SHA and updated["upstream"]["ref"]=="v2.10.14"
        assert sum(x[:2]==("git","push") for x in commands)==1
        assert sum(x[:3]==("gh","pr","create") for x in commands)==1
        assert sum(x[:3]==("gh","workflow","run") for x in commands)==1
        created=[x for x in commands if x[:3]==("gh","pr","create")][0]
        assert "--draft" in created and "--base" in created
        commit=[x for x in commands if x[:2]==("git","commit")][0]
        assert marker in " ".join(commit)
        assert not any(x[:2]==("gh","release") for x in commands)


def exercise_central_proposal_guards():
    record = c.plan(EXT, WATCH, POLICY, fixture, branch_style="central")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        manifest, watch = root / "extension.json", root / "watch.json"
        manifest.write_text(json.dumps(EXT), encoding="utf-8")
        watch.write_text(json.dumps(WATCH), encoding="utf-8")
        original = manifest.read_bytes()
        calls = []

        def execute(*args):
            calls.append(args)
            if args[:3] == ("gh", "pr", "list"):
                return "[]"
            if args[:2] == ("git", "ls-remote"):
                return f"{PR_HEAD} {args[-1]}"
            if args[:2] == ("git", "fetch"):
                return ""
            if args[:2] == ("git", "log"):
                return "candidate without an immutable marker"
            raise AssertionError(args)

        def task(candidate_record):
            return c.propose_candidate(candidate_record, str(manifest), CENTRAL_REPO, str(watch), fetch=fixture)

        with patch.object(c, "execute", execute), \
             patch.object(update_watch_lib, "github_get_json", return_value=REGISTRY_RESPONSE), \
             patch.object(c, "repair_exact_bot_candidate_base_sync") as repair:
            for invalid in (dict(record, firstRelease=True),
                            dict(record, branch=format_branch(EXT["name"], record["candidateId"], "legacy")),
                            dict(record, branch=format_branch("pg_bigm", record["candidateId"], "central"))):
                expect_fail(lambda: task(invalid))
            assert calls == []
            expect_fail(lambda: task(record))
            assert any(args[:2] == ("git", "log") for args in calls)
            repair.assert_not_called()
        assert_no_writes_or_dispatch(calls)
        assert manifest.read_bytes() == original


def exercise_candidate_regeneration(style="legacy", predecessor_style="legacy"):
    """Drive a closed base, an open successor, and a second closed predecessor."""
    record = c.plan(EXT, WATCH, POLICY, fixture, branch_style=style)
    original = copy.deepcopy(record)
    repository = CENTRAL_REPO if style == "central" else LOCAL_REPO
    writer = APP_WRITER
    parent, head = "a"*40, "b"*40
    actor = {"type": "Bot", "login": writer[0], "id": writer[1]}

    def listed_pr(branch, number, state):
        return list_pr(repository, branch, number, state)

    base_branch = format_branch(EXT["name"], record["candidateId"], predecessor_style)
    prs = {base_branch: listed_pr(base_branch, 114, "CLOSED")}
    branches = set()
    dispatched = set()
    rest_users = {}
    origin = Mock()
    created = Mock()
    def build_origin(ref, effective, predecessor):
        origin_record = {"decision": effective}
        if predecessor is not None:
            origin_record["regeneration"] = {
                "predecessorCandidateId": predecessor[0], "predecessorPrNumber": predecessor[1]}
        return origin_module.marker(origin_record)
    origin.side_effect = build_origin
    calls = []
    current_branch = None
    race = False
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        manifest = root/"extension.json"
        watch = root/"watch.json"
        policy = root/"policy.json"
        watch.write_text(json.dumps(WATCH), encoding="utf-8")
        policy.write_text(json.dumps(POLICY), encoding="utf-8")

        def execute(*args):
            nonlocal current_branch
            calls.append(args)
            if args[:3] == ("gh", "pr", "list"):
                branch = args[args.index("--head") + 1]
                return json.dumps([prs[branch]] if branch in prs else [])
            if args[:2] == ("gh", "api"):
                number = int(args[2].rsplit("/", 1)[1])
                pr = next(pr for pr in prs.values() if pr["number"] == number)
                rest = rest_pr(repository, pr, writer)
                rest["user"] = rest_users.get(number, actor)
                return json.dumps(rest)
            if args[:2] == ("git", "ls-remote"):
                branch = args[-1].removeprefix("refs/heads/")
                return f"{head} {args[-1]}" if branch in branches else ""
            if args[:3] == ("git", "checkout", "-b"):
                current_branch = args[3]
                return ""
            if args[:2] == ("git", "push"):
                branches.add(args[-1])
                if race:
                    parsed = parse_branch(args[-1])
                    other_branch = format_branch(EXT["name"], parsed.candidate_id, "legacy")
                    prs[other_branch] = listed_pr(other_branch, 999, "OPEN")
                return ""
            if args[:3] == ("git", "rev-parse", "HEAD"):
                return head if current_branch else parent
            if args[:2] == ("git", "log"):
                return parent if "--format=%P" in args else candidate_marker(args[-1].removeprefix("refs/remotes/origin/"))
            if args[:2] == ("git", "show"):
                return json.dumps(c.apply(EXT, record))
            if args[:2] == ("git", "diff"):
                return str(manifest)
            if args[:3] == ("gh", "pr", "create"):
                branch = args[args.index("--head") + 1]
                assert branch in branches and branch not in prs and "--draft" in args
                body = Path(args[args.index("--body-file") + 1]).read_text(encoding="utf-8")
                prs[branch] = dict(listed_pr(branch, 114 + len(prs), "OPEN"), body=body)
                return prs[branch]["url"]
            if args[:3] == ("gh", "run", "list"):
                branch = args[args.index("--branch") + 1]
                return json.dumps([{"databaseId": 100}] if branch in dispatched else [])
            if args[:3] == ("gh", "workflow", "run"):
                branch = args[args.index("--ref") + 1]
                assert branch in prs and branch not in dispatched
                dispatched.add(branch)
                return ""
            if args[:2] in {("git", "fetch"), ("git", "config"), ("git", "add"), ("git", "commit")}:
                return ""
            raise AssertionError("unexpected command " + repr(args))

        def task():
            nonlocal current_branch
            calls.clear()
            current_branch = None
            manifest.write_text(json.dumps(EXT), encoding="utf-8")
            c.propose_candidate(record, str(manifest), repository, str(watch), str(policy),
                                writer=writer, fetch=lambda url: REGISTRY_RESPONSE,
                                origin_body=origin, on_created=created)

        def assert_new_proposal(predecessor, branch):
            parsed = parse_branch(branch, expected_extension=EXT["name"])
            predecessor_id = parse_branch(predecessor).candidate_id
            number = prs[predecessor]["number"]
            assert parsed.style == style
            assert parsed.candidate_id == c.regenerated_candidate_id(predecessor_id, number)
            assert [args[-1] for args in calls if args[:2] == ("git", "ls-remote")] == ["refs/heads/" + branch]
            assert [args[-1] for args in calls if args[:2] == ("git", "push")] == [branch]
            assert sum(args[:3] == ("gh", "pr", "create") for args in calls) == 1
            assert [args[-1] for args in calls if args[:3] == ("gh", "workflow", "run")] == [branch]
            assert any(args[:2] == ("git", "commit") and candidate_marker(branch) in args[-1] for args in calls)
            assert prs[branch]["body"].startswith(candidate_marker(branch) + "\n")
            attested = origin_module.parse_marker(prs[branch]["body"])
            assert attested["decision"]["candidateId"] == parsed.candidate_id
            assert attested["regeneration"] == {
                "predecessorCandidateId": predecessor_id, "predecessorPrNumber": number}
            assert origin.call_args.args[1]["candidateId"] == parsed.candidate_id
            assert origin.call_args.args[2] == (predecessor_id, number)
            assert created.call_args.args[1]["candidateId"] == parsed.candidate_id
            assert created.call_args.args[2] == (predecessor_id, number)
            assert prs[predecessor]["url"] in prs[branch]["body"]
            assert predecessor_id in prs[branch]["body"]
            assert prs[predecessor]["state"] == "CLOSED"
            assert record == original

        def assert_scanned(*candidate_branches):
            expected = []
            for candidate_branch in candidate_branches:
                candidate_id = parse_branch(candidate_branch).candidate_id
                expected.append(format_branch(EXT["name"], candidate_id, style))
                if style == "central":
                    expected.append(format_branch(EXT["name"], candidate_id, "legacy"))
            assert [args[args.index("--head") + 1] for args in calls
                    if args[:3] == ("gh", "pr", "list")] == expected

        with patch.dict(os.environ, {"RUNNER_TEMP": temp}), \
             patch.object(c, "execute", execute), patch.object(c, "peel_tag", return_value=SHA):
            if style == "central":
                alternate_style = "legacy" if predecessor_style == "central" else "central"
                alternate = format_branch(EXT["name"], record["candidateId"], alternate_style)
                prs[base_branch]["state"] = "OPEN"
                branches.add(base_branch)
                dispatched.add(base_branch)
                task()
                assert_scanned(base_branch)
                assert_no_writes_or_dispatch(calls)
                assert any(args[:3] == ("gh", "run", "list") and base_branch in args for args in calls)
                assert alternate not in branches

                branches.clear()
                expect_fail(task)
                assert_no_writes_or_dispatch(calls)

                prs[base_branch]["state"] = "MERGED"
                task()
                assert_scanned(base_branch)
                assert_no_writes_or_dispatch(calls)
                assert all(args[0] == "gh" for args in calls) and len(calls) == 3

                prs[alternate] = listed_pr(alternate, 999, "OPEN")
                expect_fail(task)
                assert_scanned(base_branch)
                assert_no_writes_or_dispatch(calls)
                del prs[alternate]
                dispatched.clear()
                prs[base_branch]["state"] = "CLOSED"

            task()
            first, = branches
            assert first != base_branch
            assert_new_proposal(base_branch, first)

            task()
            assert_scanned(base_branch, first)
            assert ("gh", "api", f"repos/{repository}/pulls/115") in calls
            assert not any(args[:3] in {("gh", "pr", "create"), ("gh", "workflow", "run")} for args in calls)
            assert not any(args[:2] == ("git", "push") for args in calls)

            rest_users[115] = dict(actor, login="other-app[bot]")
            expect_fail(task)
            assert not any(args[0] == "git" or args[:3] == ("gh", "workflow", "run") for args in calls)
            del rest_users[115]

            prs[first]["state"] = "CLOSED"
            task()
            second, = branches - {first}
            assert second not in {base_branch, first}
            assert_new_proposal(first, second)
            assert dispatched == {first, second}

            prs[second]["state"] = "MERGED"
            task()
            assert_scanned(base_branch, first, second)
            assert all(args[:3] == ("gh", "pr", "list") or args[:2] == ("gh", "api") for args in calls)
            assert origin.call_count == 2 and created.call_count == 2

            # The base candidate still gets the same origin callback contract,
            # with its unchanged decision and no regeneration field.
            prs.clear()
            task()
            base_attestation = origin_module.parse_marker(prs[record["branch"]]["body"])
            assert base_attestation["decision"] == original
            assert "regeneration" not in base_attestation
            assert origin.call_args.args[2] is None and created.call_args.args[2] is None

            if style == "central":
                # A legacy PR appearing during branch preparation must stop PR creation and dispatch.
                prs.clear()
                branches.clear()
                race = True
                expect_fail(task)
                assert_scanned(record["branch"], record["branch"])
                assert not any(args[:3] in {("gh", "pr", "create"), ("gh", "workflow", "run")}
                               for args in calls)


def main():
    for mode in ("WATCH", "OFF"):
        record=c.suppressed(EXT,mode)
        assert record["status"]=="centrally-suppressed"
        assert record["mode"]==mode and record["updates"]==[]
        assert record["releasePolicy"]=="manual-only"
        assert record["repository"]=="test/ext"
    expect_fail(lambda:c.suppressed(EXT,"BUILD"))
    expect_fail(lambda:c.suppressed(EXT,"UNKNOWN"))
    p=c.plan(EXT,WATCH,POLICY,fixture)
    assert p["status"]=="candidate" and p["updates"][0]["commit"]==SHA and p["updates"][0]["version"]=="2.10.14"
    assert len(p["candidateId"])==20 and p["branch"].startswith("auto-candidate/")
    assert c.plan(EXT,WATCH,POLICY,fixture)["candidateId"]==p["candidateId"]
    central = c.plan(EXT, WATCH, POLICY, fixture, branch_style="central")
    assert central["candidateId"] == p["candidateId"]
    assert central["branch"] == f"auto-candidate/{EXT['name']}/{p['candidateId']}"
    upgraded=c.apply(EXT,p)
    assert upgraded["upstream"]["commit"]==SHA and upgraded["upstream"]["ref"]=="v2.10.14"
    expect_fail(lambda:c.apply(upgraded,p))
    assert c.plan(upgraded,WATCH,POLICY,fixture)["status"]=="no-op"
    expect_fail(lambda:c.plan(EXT,WATCH,POLICY,lambda u: (_ for _ in ()).throw(WatchError("API unavailable"))))
    expect_fail(lambda:c.plan(EXT,WATCH,POLICY,lambda u: {"object":{"type":"commit","sha":"BAD"}} if "/git/ref/" in u else fixture(u)))
    bogus=copy.deepcopy(POLICY);bogus["releasePolicy"]="automatic"
    expect_fail(lambda:c.plan(EXT,WATCH,bogus,fixture))
    disabled=copy.deepcopy(POLICY);disabled["enabled"]=False
    assert c.plan(EXT,WATCH,disabled,fixture)["status"]=="disabled"
    old=copy.deepcopy(EXT);old["upstream"]["version"]="2.10.15";old["upstream"]["ref"]="v2.10.15"
    expect_fail(lambda:c.plan(old,WATCH,POLICY,fixture))  # Unresolvable current ref cannot be trusted/pinned.
    series=copy.deepcopy(EXT);series["upstream"]={"repository":"test/ext","perPostgresql":{
        "15":{"ref":"REL15_1_0_0","version":"1.0.0"},"16":{"ref":"REL16_1_0_0","version":"1.0.0"}}}
    watch=copy.deepcopy(WATCH);watch.pop("stableTagPattern");watch["strategy"]="github-releases-per-postgresql"
    watch["perPostgresql"]={"15":{"tagPattern":r"^REL15_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},
                            "16":{"tagPattern":r"^REL16_(?P<version>[0-9]+_[0-9]+_[0-9]+)$"},
                            "19":{"tagPattern":r"^REL19_(?P<version>[0-9]+_[0-9]+_[0-9]+)$","informational":True}}
    def series_fixture(u):
        if "/releases?" in u:
            return [{"tag_name":"REL15_1_0_1","draft":False,"prerelease":False},
                    {"tag_name":"REL19_1_0_1","draft":False,"prerelease":False}]
        if "/git/ref/tags/REL15_1_0_1" in u: return {"object":{"type":"commit","sha":SHA}}
        raise WatchError("unexpected URL "+u)
    q=c.plan(series,watch,POLICY,series_fixture)
    assert len(q["updates"])==1 and q["updates"][0]["major"]==15
    assert c.apply(series,q)["upstream"]["perPostgresql"]["16"]["ref"]=="REL16_1_0_0"
    # Source-pinning a stable current release does not change its version.
    baseline=copy.deepcopy(EXT)
    baseline["upstream"]["ref"]="v2.10.14"
    baseline["upstream"]["version"]="2.10.14"
    baseline_plan=c.plan(baseline,WATCH,POLICY,fixture)
    assert baseline_plan["status"]=="candidate"
    assert baseline_plan["updates"][0]["pinOnly"] is True
    assert baseline_plan["updates"][0]["ref"]=="v2.10.14"
    assert baseline_plan["updates"][0]["oldRef"]=="v2.10.14"
    untrusted_ref=copy.deepcopy(baseline)
    untrusted_ref["upstream"]["ref"]="release/2.10.14"
    expect_fail(lambda:c.plan(untrusted_ref,WATCH,POLICY,fixture))
    verified=c.apply(baseline,baseline_plan)
    assert verified["upstream"]["commit"]==SHA and verified["upstream"]["version"]=="2.10.14"
    assert c.plan(verified,WATCH,POLICY,fixture)["status"]=="no-op"
    expect_fail(lambda:c.apply(verified,baseline_plan))
    tampered=copy.deepcopy(baseline_plan)
    tampered["updates"][0]["version"]="2.10.15"
    expect_fail(lambda:c.apply(baseline,tampered))
    tampered=copy.deepcopy(baseline_plan)
    tampered["updates"][0]["pinOnly"]=False
    expect_fail(lambda:c.apply(baseline,tampered))
    # Per-PG unchanged baseline pins all unpinned currently stable sources.
    per=copy.deepcopy(series)
    per["upstream"]["perPostgresql"]["15"]["ref"]="REL15_1_0_1"
    per["upstream"]["perPostgresql"]["15"]["version"]="1.0.1"
    per["upstream"]["perPostgresql"]["16"]["ref"]="REL16_1_0_1"
    per["upstream"]["perPostgresql"]["16"]["version"]="1.0.1"
    def stable_series_fetch(u):
        if "/releases?" in u:
            return [{"tag_name":"REL15_1_0_1","draft":False,"prerelease":False},
                    {"tag_name":"REL16_1_0_1","draft":False,"prerelease":False}]
        if "/git/ref/tags/REL15_1_0_1" in u or "/git/ref/tags/REL16_1_0_1" in u:
            return {"object":{"type":"commit","sha":SHA}}
        raise WatchError("unexpected baseline URL "+u)
    baseline_pg=c.plan(per,watch,POLICY,stable_series_fetch)
    assert baseline_pg["status"]=="candidate"
    assert len(baseline_pg["updates"])==2
    assert all(u["pinOnly"] is True for u in baseline_pg["updates"])
    pinned_pg=c.apply(per,baseline_pg)
    assert all(v["commit"]==SHA for v in pinned_pg["upstream"]["perPostgresql"].values())
    exercise_proposer_safety()
    exercise_upstream_and_pr_lookup_outages()
    exercise_writer_identity_normalization()
    exercise_new_candidate_positive()
    exercise_central_proposal_guards()
    exercise_candidate_regeneration()
    exercise_candidate_regeneration("central", "central")
    exercise_candidate_regeneration("central", "legacy")
    print("Step 19/20 candidate and proposer-safety fixture tests passed")

if __name__=="__main__":main()
