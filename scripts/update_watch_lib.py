from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

PRE_RELEASE_WORDS = re.compile(r"(?:^|[._-])(alpha|beta|rc|preview|pre)(?:[0-9._-]|$)", re.I)
VERSION_BITS = re.compile(r"\d+")


class WatchError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_text(value: Any, limit: int = 300) -> str:
    text = str(value if value is not None else "")
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    text = text.replace("${{", "$&#123;&#123;")
    return html.escape(text[:limit], quote=False)


def natural_key(value: str) -> tuple[int, ...]:
    bits = tuple(int(x) for x in VERSION_BITS.findall(value))
    return bits or (0,)


def github_get_json(url: str, token: str | None = None, timeout: int = 30) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pgextwin-update-watch/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise WatchError(f"upstream query failed: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WatchError(f"upstream returned malformed JSON: {exc}") from exc


def validate_watch_semantics(extension: dict[str, Any], watch: dict[str, Any]) -> None:
    if extension.get("upstream", {}).get("repository") != watch.get("repository"):
        raise WatchError("update-watch repository must match config/extension.json upstream.repository")
    if watch.get("source") != "github" or watch.get("prereleases") is not False:
        raise WatchError("only GitHub stable-only update watches are supported in schemaVersion 1")
    strategy = watch.get("strategy")
    if strategy == "github-releases-per-postgresql":
        current = extension.get("upstream", {}).get("perPostgresql")
        if not isinstance(current, dict) or not current:
            raise WatchError("per-PostgreSQL watch requires upstream.perPostgresql in extension config")
        rules = watch.get("perPostgresql")
        if not isinstance(rules, dict) or not rules:
            raise WatchError("per-PostgreSQL watch requires perPostgresql rules")
        for major in current:
            if str(major) not in rules:
                raise WatchError(f"missing update-watch rule for PostgreSQL {major}")
    elif strategy in {"github-releases", "github-tags"}:
        upstream = extension.get("upstream", {})
        if not upstream.get("ref") or not upstream.get("version"):
            raise WatchError("single-version watch requires upstream.ref and upstream.version")
        if not watch.get("stableTagPattern"):
            raise WatchError("single-version watch requires stableTagPattern")
    else:
        raise WatchError(f"unsupported strategy: {strategy}")


def _candidate_from_release(release: dict[str, Any], pattern: re.Pattern[str]) -> dict[str, Any] | None:
    if release.get("draft") or release.get("prerelease"):
        return None
    tag = release.get("tag_name")
    if not isinstance(tag, str) or PRE_RELEASE_WORDS.search(tag) or not pattern.fullmatch(tag):
        return None
    return {
        "ref": tag,
        "version": _version_from_match(pattern.fullmatch(tag), tag),
        "url": str(release.get("html_url") or ""),
        "publishedAt": release.get("published_at"),
        "source": "release",
    }


def _candidate_from_tag(item: dict[str, Any], pattern: re.Pattern[str], repository: str) -> dict[str, Any] | None:
    tag = item.get("name")
    if not isinstance(tag, str) or PRE_RELEASE_WORDS.search(tag) or not pattern.fullmatch(tag):
        return None
    return {
        "ref": tag,
        "version": _version_from_match(pattern.fullmatch(tag), tag),
        "url": f"https://github.com/{repository}/tree/{quote(tag, safe='')}",
        "publishedAt": None,
        "source": "tag",
    }


def _version_from_match(match: re.Match[str] | None, fallback: str) -> str:
    if match is not None and "version" in match.groupdict() and match.group("version"):
        return match.group("version").replace("_", ".")
    return fallback


def _best(candidates: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    items = list(candidates)
    if not items:
        return None
    return max(items, key=lambda x: natural_key(str(x["version"])))


def detect_extension_update(
    extension: dict[str, Any],
    watch: dict[str, Any],
    fetch_json: Callable[[str], Any],
    detected_at: str,
    watcher_repository: str,
    watcher_sha: str,
) -> dict[str, Any]:
    validate_watch_semantics(extension, watch)
    repository = watch["repository"]
    strategy = watch["strategy"]
    endpoint = "releases?per_page=100" if strategy != "github-tags" else "tags?per_page=100"
    payload = fetch_json(f"https://api.github.com/repos/{repository}/{endpoint}")
    if not isinstance(payload, list):
        raise WatchError("upstream response must be a JSON array")

    result: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "extension-upstream",
        "extension": extension.get("name"),
        "repository": repository,
        "strategy": strategy,
        "status": "up-to-date",
        "current": None,
        "candidate": None,
        "updates": [],
        "informationalCandidates": [],
        "detectedAt": detected_at,
        "watcher": {"repository": watcher_repository, "sha": watcher_sha},
    }

    if strategy == "github-releases-per-postgresql":
        currents = extension["upstream"]["perPostgresql"]
        result["current"] = {str(k): v for k, v in currents.items()}
        for major, rule in watch["perPostgresql"].items():
            pattern = re.compile(rule["tagPattern"])
            candidates = [_candidate_from_release(x, pattern) for x in payload if isinstance(x, dict)]
            best = _best(x for x in candidates if x)
            if major not in currents:
                if best and rule.get("informational", False):
                    info = dict(best)
                    info["postgresqlMajor"] = int(major)
                    result["informationalCandidates"].append(info)
                continue
            current = currents[major]
            if best and best["ref"] != current["ref"] and natural_key(best["version"]) > natural_key(str(current["version"])):
                update = {
                    "postgresqlMajor": int(major),
                    "current": {"ref": current["ref"], "version": current["version"]},
                    "candidate": best,
                }
                result["updates"].append(update)
        if result["updates"]:
            result["status"] = "update-available"
            result["candidate"] = {"perPostgresql": result["updates"]}
        return result

    pattern = re.compile(watch["stableTagPattern"])
    if strategy == "github-releases":
        candidates = [_candidate_from_release(x, pattern) for x in payload if isinstance(x, dict)]
    else:
        candidates = [_candidate_from_tag(x, pattern, repository) for x in payload if isinstance(x, dict)]
    best = _best(x for x in candidates if x)
    current = extension["upstream"]
    result["current"] = {"ref": current["ref"], "version": current["version"]}
    if best and best["ref"] != current["ref"] and natural_key(best["version"]) > natural_key(str(current["version"])):
        result["status"] = "update-available"
        result["candidate"] = best
        majors = extension.get("postgresql", {}).get("majors")
        if majors is None:
            majors = list(range(int(extension["postgresql"]["minMajor"]), int(extension["postgresql"]["maxMajor"]) + 1))
        result["updates"] = [{"postgresqlMajors": majors, "current": result["current"], "candidate": best}]
    return result


def candidate_signature(result: dict[str, Any]) -> str:
    stable = {
        "kind": result.get("kind"),
        "extension": result.get("extension"),
        "repository": result.get("repository"),
        "status": result.get("status"),
        "updates": result.get("updates", []),
        "drift": result.get("drift", []),
        "newMajors": result.get("newMajors", []),
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def decide_issue_action(result: dict[str, Any], issues: list[dict[str, Any]], marker: str) -> dict[str, Any]:
    owned = [i for i in issues if marker in str(i.get("body") or "") and str(i.get("state", "OPEN")).upper() == "OPEN"]
    if len(owned) > 1:
        raise WatchError("multiple open automation-owned issues found for one watch marker")
    existing = owned[0] if owned else None
    if result.get("status") == "indeterminate":
        raise WatchError("indeterminate detection result must not mutate issues")
    if result.get("status") == "up-to-date":
        return {"action": "close", "issue": existing} if existing else {"action": "none", "issue": None}
    if result.get("status") != "update-available":
        raise WatchError(f"unsupported detection status: {result.get('status')}")
    sig_marker = f"<!-- pgextwin-update-watch-candidate:{candidate_signature(result)} -->"
    if existing is None:
        return {"action": "create", "issue": None, "signatureMarker": sig_marker}
    if sig_marker in str(existing.get("body") or ""):
        return {"action": "none", "issue": existing, "signatureMarker": sig_marker}
    return {"action": "update", "issue": existing, "signatureMarker": sig_marker}
