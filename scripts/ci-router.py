#!/usr/bin/env python3
"""Common selective CI router for the central monorepo (F21-02).

The router is hosted by ``validate.yml`` -- the workflow behind the
required status check ``resolver`` -- which already starts on every pull
request and every push to ``main``.  The router maps the changed paths of
a change to the set of extensions whose per-extension CI must run,
following the union rule of F1 DESIGN chapter 2 section 2.1 and the load
and contention rules of PLAN-F section 5.4:

* ``extensions/<name>/**`` selects exactly ``<name>``.  Deletions and
  renames evaluate the old path as well as the new one, so a change that
  only touches the old side of a rename still selects the old extension.
* Several extension paths select the union of their extensions.
* Shared build / CI foundation paths (``scripts/``, ``windows/``,
  ``schema/``, ``tests/``, ``.github/``, ``metadata/``) select the
  representative smoke set -- the three F2 pilots -- by default.  The
  full registered matrix is reserved for explicit triggers or wave
  control (PLAN-F 5.4) and is available via ``--shared-policy all``.
* Documentation changes (``docs/**`` and Markdown outside
  ``extensions/``) select nothing.
* Anything the router cannot classify selects every registered extension
  (the safety side of DESIGN 2.1).  A malformed change list, or an
  ``extensions/`` path component that Windows cannot carry, is an
  extraction failure and exits non-zero instead of silently routing --
  extraction failure is kept distinct from "no targets" (DESIGN 2.1).

The router always produces a conclusion for well-formed input: an empty
target set is a successful routing (``resolver_conclusion`` is
``"success"`` and ``pending`` is always 0), so the required check never
stalls in Pending just because a change touches no extension.

The registered extension set is the union of the central fleet registry
``metadata/automation-fleet.json`` (the 26 extensions of CB-73) and any
``extensions/<name>/`` directories present in the tree, so extensions
landed by later migrations are recognised without a router edit.  Names
are validated with the same rules as the central declaration validator
(``scripts/central-extension.py``): one source of truth for what a legal
extension name is.

Input is the GitHub pull-request / compare file list shape::

    [{"filename": "extensions/pg_bigm/extension.json",
      "status": "modified",
      "previous_filename": "..."}]        # only for renames / copies

``previous_filename`` is evaluated whenever it is present, and a
``renamed`` / ``copied`` status without it is rejected as malformed.

The module also fixes the processing-type ``concurrency`` contract of
DESIGN 2.2 / PLAN-F 5.4 (see ``CONCURRENCY_CONTRACT``): one group per
processing type, every current group with ``cancel-in-progress: false``
(the CB-73 fixed value, matching all live workflows), and per-series
groups that carry the matrix keys (extension, PostgreSQL major,
candidate id) so the series jobs of one extension never cancel each
other.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FLEET_PATH = ROOT / "metadata" / "automation-fleet.json"


def _load_central():
    spec = importlib.util.spec_from_file_location(
        "central_extension", ROOT / "scripts" / "central-extension.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


central = _load_central()

# Representative smoke set for shared-foundation changes: the three F2
# pilots in their PLAN-F migration order.  Output is always sorted, so
# this tuple only fixes membership.
PILOT_SMOKE_EXTENSIONS = ("pg_permissions", "pg_bigm", "pgaudit")

# Repository roots whose contents are shared build / CI foundation for
# every extension (DESIGN 2.1 shared rows).  A change under any of them
# selects the representative smoke set by default.
SHARED_ROOTS = frozenset({"scripts", "windows", "schema", "tests", ".github", "metadata"})


class RouterError(Exception):
    """The change list cannot be routed (extraction failure)."""


def _validate_extension_name(name, origin):
    if not isinstance(name, str) or not central.NAME_RE.match(name):
        raise RouterError(f"{origin}: {name!r} is not a legal extension name")
    error = central.windows_name_error(name)
    if error is not None:
        raise RouterError(f"{origin}: extension name {name!r} is unusable: {error}")


def registered_extensions(fleet_path=FLEET_PATH, extensions_root=None):
    """Sorted registered extension names (fleet registry + tree layout)."""
    names = set()
    fleet = json.loads(Path(fleet_path).read_text(encoding="utf-8"))
    entries = fleet.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RouterError(f"{fleet_path}: fleet registry has no entries list")
    for entry in entries:
        repository = entry.get("repository") if isinstance(entry, dict) else None
        if not isinstance(repository, str) or not repository.startswith("pgextwin/"):
            raise RouterError(f"{fleet_path}: malformed fleet entry {entry!r}")
        name = repository.split("/", 1)[1]
        _validate_extension_name(name, f"{fleet_path} entry {repository!r}")
        names.add(name)
    if extensions_root is not None:
        layout = Path(extensions_root) / "extensions"
        if layout.is_dir():
            for child in sorted(layout.iterdir()):
                if child.is_dir():
                    _validate_extension_name(child.name, f"{layout} directory")
                    names.add(child.name)
    return sorted(names)


def _validate_path(path, origin):
    if not isinstance(path, str) or not path:
        raise RouterError(f"{origin}: path must be a non-empty string, got {path!r}")
    if path.startswith("/") or "\\" in path:
        raise RouterError(f"{origin}: path must be a relative POSIX path, got {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RouterError(f"{origin}: path has an empty, '.' or '..' component: {path!r}")
    return parts


def classify_path(path, *, registered, smoke):
    """Classify one changed path.

    Returns ``(kind, targets)`` where kind is one of ``extension``,
    ``documentation``, ``shared`` or ``unclassified`` and targets is a
    frozenset of extension names the path selects.
    """
    parts = _validate_path(path, "changed path")
    if parts[0] == "extensions" and len(parts) >= 2:
        _validate_extension_name(parts[1], f"changed path {path!r}")
        return "extension", frozenset({parts[1]})
    if parts[0] == "docs" or path.lower().endswith(".md"):
        return "documentation", frozenset()
    if parts[0] in SHARED_ROOTS:
        return "shared", frozenset(smoke)
    return "unclassified", frozenset(registered)


def route_changes(changes, *, registered, smoke):
    """Route a GitHub-shaped change list to the target extension matrix."""
    if not isinstance(changes, list):
        raise RouterError(f"change list must be a JSON array, got {type(changes).__name__}")
    targets = set()
    classified = []
    for index, change in enumerate(changes):
        origin = f"change[{index}]"
        if not isinstance(change, dict):
            raise RouterError(f"{origin}: entry must be an object, got {change!r}")
        filename = change.get("filename")
        if not isinstance(filename, str) or not filename:
            raise RouterError(f"{origin}: entry has no usable 'filename': {change!r}")
        status = change.get("status")
        if status is not None and not isinstance(status, str):
            raise RouterError(f"{origin}: 'status' must be a string: {change!r}")
        previous = change.get("previous_filename")
        if status in ("renamed", "copied") and not previous:
            raise RouterError(
                f"{origin}: status {status!r} without 'previous_filename': {change!r}"
            )
        for label, path in (("filename", filename), ("previous_filename", previous)):
            if path is None:
                continue
            kind, selected = classify_path(path, registered=registered, smoke=smoke)
            targets |= selected
            classified.append(
                {
                    "path": path,
                    "origin": label,
                    "kind": kind,
                    "targets": sorted(selected),
                }
            )
    ordered = sorted(targets)
    return {
        "schemaVersion": 1,
        "targets": ordered,
        "matrix": {"include": [{"extension": name} for name in ordered]},
        "has_targets": bool(ordered),
        "pending": 0,
        "resolver_conclusion": "success",
        "classified": classified,
    }


# ---------------------------------------------------------------------------
# Processing-type concurrency contract (DESIGN 2.2, PLAN-F 5.4, CB-73).
#
# One group per processing type.  Every current group fixes
# cancel-in-progress to false -- the CB-73 fixed value, matching all live
# workflows.  DESIGN 2.2 marks PR validation as the one type where
# cancellation would be permissible; the current fixed value keeps it
# false there too, and the contract records that distinction instead of
# silently widening it.  Signing, publishing and catalog updates keep
# their existing authorization / exclusion units (DESIGN 2.2) and are
# recorded with group None: the router does not rename them.
# ---------------------------------------------------------------------------

ROUTER_WORKFLOW_GROUP = (
    "ci-router-${{ github.workflow }}-"
    "${{ github.event.pull_request.number || github.ref }}"
)

CONCURRENCY_CONTRACT = {
    "pr-validation": {
        "group": "ci-{extension}-pr-{pr_number}",
        "cancel_in_progress": False,
    },
    "postmerge": {
        "group": "postmerge-{extension}",
        "cancel_in_progress": False,
    },
    "candidate-ci": {
        "group": "candidate-ci-{extension}-{candidate_id}",
        "cancel_in_progress": False,
    },
    "candidate-writer": {
        "group": "candidate-writer-{extension}",
        "cancel_in_progress": False,
    },
    "fleet-watch": {
        "group": "fleet-watch",
        "cancel_in_progress": False,
    },
    "signing": {"group": None, "cancel_in_progress": False},
    "publishing": {"group": None, "cancel_in_progress": False},
    "catalog-update": {"group": None, "cancel_in_progress": False},
    "router": {"group": ROUTER_WORKFLOW_GROUP, "cancel_in_progress": False},
}


def concurrency_group(kind, *, extension=None, pr_number=None, candidate_id=None,
                      pg_major=None):
    """Render the concurrency group for one job of a processing type.

    Series jobs pass ``pg_major`` so the PostgreSQL series of one
    extension land in distinct groups and never cancel each other
    (DESIGN 2.2 matrix-key rule).  Types that keep an existing unit
    (signing, publishing, catalog update) raise RouterError instead of
    inventing a replacement group.
    """
    entry = CONCURRENCY_CONTRACT.get(kind)
    if entry is None:
        raise RouterError(f"unknown processing type {kind!r}")
    template = entry["group"]
    if template is None:
        raise RouterError(
            f"processing type {kind!r} keeps its existing authorization unit; "
            "the router does not assign it a new group"
        )
    values = {
        "extension": extension,
        "pr_number": pr_number,
        "candidate_id": candidate_id,
    }
    group = template
    for key, value in values.items():
        placeholder = "{" + key + "}"
        if placeholder in group:
            if value is None:
                raise RouterError(f"processing type {kind!r} requires {key}")
            group = group.replace(placeholder, str(value))
    if "{" in group or "}" in group:
        raise RouterError(f"processing type {kind!r}: unfilled group template {template!r}")
    if pg_major is not None:
        group = f"{group}-pg{pg_major}"
    return group


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--files",
        default="-",
        help="JSON change list in GitHub file-list shape ('-' reads stdin)",
    )
    parser.add_argument("--fleet", default=str(FLEET_PATH),
                        help="fleet registry JSON (default: metadata/automation-fleet.json)")
    parser.add_argument(
        "--extensions-root",
        default=str(ROOT),
        help="tree whose extensions/ layout is unioned into the registry",
    )
    parser.add_argument(
        "--shared-policy",
        choices=("smoke", "all"),
        default="smoke",
        help="shared-foundation changes select the pilot smoke set (default) "
        "or every registered extension",
    )
    parser.add_argument(
        "--format",
        choices=("json", "github"),
        default="json",
        help="output format: JSON document or $GITHUB_OUTPUT lines",
    )
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.files == "-" else Path(args.files).read_text(encoding="utf-8")
        try:
            changes = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RouterError(f"change list is not valid JSON: {exc}") from exc
        registered = registered_extensions(args.fleet, args.extensions_root)
        smoke = PILOT_SMOKE_EXTENSIONS if args.shared_policy == "smoke" else registered
        result = route_changes(changes, registered=registered, smoke=smoke)
    except RouterError as exc:
        print(f"ci-router: {exc}", file=sys.stderr)
        return 2

    if args.format == "github":
        print(f"matrix={json.dumps(result['matrix'], separators=(',', ':'))}")
        print(f"has_targets={'true' if result['has_targets'] else 'false'}")
        print(f"targets={','.join(result['targets'])}")
        print(f"resolver_conclusion={result['resolver_conclusion']}")
        print(f"pending={result['pending']}")
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
