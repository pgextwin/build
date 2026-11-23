"""Resolve pilot signing routes from protected workflow pins and live Run references."""

import base64
import json
from pathlib import Path
import re

CENTRAL = "pgextwin/build"
OWNER_WRAPPER = ".github/workflows/chat-signed-main-source.yml"
OWNER_CALLER = ".github/workflows/chat-signed-main.yml"
CANDIDATE_CALLER = ".github/workflows/update-watch.yml"
CANDIDATE_AUDIT = ".github/workflows/verify-signed-candidate-readonly.yml"
SIGNER = ".github/workflows/build-extension-attested.yml"
LEGACY_AUDIT = "0ba07c7ad9fdbf20afba0a10264ecadb01ecc3df"
POLICY = "metadata/windows-package-signers.json"
PILOTS = frozenset(("pgextwin/pg_profile", "pgextwin/pg_track_settings"))
SHA = re.compile(r"^[0-9a-f]{40}$")


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def workflow_uses(raw, job_names):
    import yaml

    class Loader(yaml.BaseLoader):
        def construct_mapping(self, node, deep=False):
            mapping = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                require(type(key) is str and key != "<<" and key not in mapping,
                        "ambiguous mapping in protected signing workflow")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    try:
        jobs = yaml.load(raw, Loader=Loader)["jobs"]
        values = [jobs[name]["uses"] for name in job_names]
    except (yaml.YAMLError, TypeError, KeyError) as error:
        raise Denied("protected signing workflow is missing required jobs") from error
    require(all(type(value) is str for value in values), "invalid protected workflow reference")
    return values


def workflow_ref(path, sha):
    require(type(sha) is str and SHA.fullmatch(sha), "expected immutable workflow pin")
    return f"{CENTRAL}/{path}@{sha}"


def contents(get, repo, path, sha):
    require(type(sha) is str and SHA.fullmatch(sha), "expected protected commit")
    value = get(repo, f"contents/{path}?ref={sha}")
    require(type(value) is dict and value.get("type") == "file"
            and value.get("path") == path and value.get("encoding") == "base64"
            and type(value.get("content")) is str, "protected workflow bytes unavailable")
    return base64.b64decode(value["content"].replace("\n", ""), validate=True)


def require_run_refs(run, refs):
    workflows = run.get("referenced_workflows")
    require(type(workflows) is list and all(type(item) is dict for item in workflows),
            "missing authenticated Run workflow references")
    for path, sha in refs:
        expected = workflow_ref(path, sha)
        prefix = f"{CENTRAL}/{path}@"
        matches = [item for item in workflows if str(item.get("path", "")).startswith(prefix)]
        require(len(matches) == 1 and matches[0].get("path") == expected and matches[0].get("sha") == sha,
                f"Run does not resolve the approved workflow: {path}")


def read_policy(raw=None):
    if raw is None:
        raw = (Path(__file__).resolve().parents[1] / POLICY).read_bytes()

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate route policy key")
            result[key] = value
        return result

    policy = json.loads(raw, object_pairs_hook=unique)
    require(type(policy) is dict and policy.get("schemaVersion") == 1
            and set(policy) == {"schemaVersion", "candidateSigner", "candidateAudit", "ownerWrappers"}
            and type(policy.get("ownerWrappers")) is dict
            and set(policy["ownerWrappers"]) == PILOTS
            and all(type(sha) is str and SHA.fullmatch(sha) for sha in policy["ownerWrappers"].values()),
            "invalid protected pilot route policy")
    workflow_ref(SIGNER, policy["candidateSigner"])
    if policy["candidateAudit"] is not None:
        workflow_ref(CANDIDATE_AUDIT, policy["candidateAudit"])
    return policy


def owner_signer(get, repo, source_sha, run, wrapper_sha, parse_signer, *, wrapper_raw=None):
    require(repo in PILOTS, "repository outside the owner-source pilot")
    caller = contents(get, repo, OWNER_CALLER, source_sha)
    require(workflow_uses(caller, ["signed_main_source"]) == [workflow_ref(OWNER_WRAPPER, wrapper_sha)],
            "protected owner-source caller does not name the approved wrapper")
    if wrapper_raw is None:
        wrapper_raw = contents(get, CENTRAL, OWNER_WRAPPER, wrapper_sha)
    signer = parse_signer(wrapper_raw)
    require_run_refs(run, ((OWNER_WRAPPER, wrapper_sha), (SIGNER, signer)))
    return signer


def candidate_signer(get, repo, source_sha, run, policy, legacy_signer):
    if repo not in PILOTS:
        return legacy_signer
    caller = contents(get, repo, CANDIDATE_CALLER, source_sha)
    jobs = ["candidate_attested_build", "candidate_signed_audit"]
    declarations = workflow_uses(caller, jobs)
    legacy = ((SIGNER, legacy_signer), (CANDIDATE_AUDIT, LEGACY_AUDIT))
    current = ((SIGNER, policy["candidateSigner"]), (CANDIDATE_AUDIT, policy["candidateAudit"]))
    for routes in (legacy, current):
        if all(sha for _, sha in routes) and declarations == [workflow_ref(path, sha) for path, sha in routes]:
            require_run_refs(run, routes)
            return routes[0][1]
    raise Denied("protected candidate caller does not name an approved signer and audit pair")
