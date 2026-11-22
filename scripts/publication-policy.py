"""Read canonical publication policies and derive the legacy local shapes."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "shared_fleet_policy", Path(__file__).with_name("fleet-policy.py"))
fleet_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fleet_policy)


class Denied(ValueError):
    pass


def _require(ok, reason):
    if not ok:
        raise Denied(reason)


def _read(build_root, filename, fields):
    try:
        policy = fleet_policy.read(Path(build_root) / "metadata" / filename)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise Denied(f"cannot read {filename}: {exc}") from exc
    _require(set(policy) == fields and type(policy["schemaVersion"]) is int
             and policy["schemaVersion"] == 1,
             f"unsupported {filename} fields or schema version")
    return policy


def _is_repository(repository):
    return type(repository) is str and fleet_policy.REPO.fullmatch(repository) is not None


def _validate_allowed_repositories(policy, filename):
    allowed = policy["allowedRepositories"]
    _require(type(allowed) is list and bool(allowed)
             and all(_is_repository(repository) for repository in allowed)
             and len(set(allowed)) == len(allowed),
             f"invalid or duplicate repository in {filename}")


def load_candidate_policy(build_root):
    """Load the established enabled, nonpublishing Windows candidate policy."""
    policy = _read(build_root, "candidate-build.json",
                   {"schemaVersion", "enabled", "releasePolicy", "workflow"})
    _require(policy["enabled"] is True and policy["releasePolicy"] == fleet_policy.MANUAL
             and policy["workflow"] == "windows.yml",
             "invalid candidate-build.json policy")
    return policy


def _release_promotion(build_root):
    filename = "release-promotion.json"
    policy = _read(build_root, filename, {"schemaVersion", "allowedRepositories", "releasePolicy"})
    _require(policy["releasePolicy"] in ("manual-dispatch", fleet_policy.AUTOMATIC),
             "unsupported release-promotion.json release policy")
    _validate_allowed_repositories(policy, filename)
    return policy


def release_promotion_from(policy, repository):
    """Project an already parsed central policy for an intake gate."""
    return {"schemaVersion": 1, "enabled": repository in policy["allowedRepositories"],
            "releasePolicy": policy["releasePolicy"]}


def owner_source_from(owner_policy, release_policy, repository):
    """Project already parsed central owner-source and release policies."""
    return {"schemaVersion": 1, "enabled": repository in owner_policy["allowedRepositories"],
            "sourceKind": owner_policy["sourceKind"], "releasePolicy": release_policy["releasePolicy"]}


def release_promotion_policy(build_root, repository):
    """Derive the legacy local release-promotion policy for a repository."""
    _require(_is_repository(repository), "invalid repository")
    return release_promotion_from(_release_promotion(build_root), repository)


def owner_source_policy(build_root, repository):
    """Derive the legacy local owner-source policy for a repository."""
    _require(_is_repository(repository), "invalid repository")
    filename = "owner-source-publication.json"
    policy = _read(build_root, filename,
                   {"schemaVersion", "sourceKind", "mode", "allowedRepositories", "ownerLogin", "ownerId"})
    _require(policy["sourceKind"] == "OWNER_ISSUE_COMMENT_MAIN_SIGNING" and policy["mode"] == "ENFORCE"
             and type(policy["ownerLogin"]) is str and bool(policy["ownerLogin"])
             and type(policy["ownerId"]) is int and policy["ownerId"] > 0,
             "invalid owner-source-publication.json policy")
    _validate_allowed_repositories(policy, filename)
    return owner_source_from(policy, _release_promotion(build_root), repository)
