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
  A syntactically legal ``<name>`` that is not in the registered set
  selects nothing of its own (B2-SOL-M2): the extension may have been
  retired or renamed away together with its registry entry, so its
  impact on the registered set is unknown and the path falls back to
  every registered extension, like any unclassified path, instead of
  becoming a lone fictional target.
  A file directly under ``extensions/`` is not extension content (the
  PR-B1 layout rule) and is an extraction failure, as is a case variant
  of the ``extensions/`` root itself, which would collide with it on a
  Windows checkout.
* Several extension paths select the union of their extensions.
* Shared build / CI foundation paths (``scripts/``, ``windows/``,
  ``schema/``, ``tests/``, ``.github/``, ``metadata/``) select the
  representative smoke set -- the three F2 pilots -- by default, whatever
  the file extension: a Markdown file under a shared root is still a
  shared-foundation change.  The full registered matrix is reserved for
  explicit triggers or wave control (PLAN-F 5.4) and is available via
  ``--shared-policy all``.
* Documentation changes (``docs/**`` and Markdown at the repository
  root) select nothing.
* Anything the router cannot classify selects every registered extension
  (the safety side of DESIGN 2.1).  A malformed change list, or an
  ``extensions/`` path component that Windows cannot carry, is an
  extraction failure and exits non-zero instead of silently routing --
  extraction failure is kept distinct from "no targets" (DESIGN 2.1).

The router always produces a conclusion for well-formed input: an empty
target set is a successful routing (``resolver_conclusion`` is
``"success"`` and ``pending`` is always 0), so the required check never
stalls in Pending just because a change touches no extension.

The routed matrix is a launch contract, not a display (B2-SOL-M1):
``validate.yml`` publishes the router result as the ``resolver`` job
outputs, and a dependent matrix job consumes the *launch* matrix
through ``fromJSON`` to call the reusable per-extension workflow
(``build-extension.yml``) once per launchable extension.  A target is
launchable only while its packaging subtree ``extensions/<name>/`` is
present in the tree -- the subtrees land with the F2-2 pilot migrations
and the F3a waves -- so until then the launch matrix is empty and the
dependent job is skipped, while the required ``resolver`` check still
succeeds and no target is silently dropped from the routing itself.

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

The workflow computes that list from the event's own commits
(B2-SOL-R2-M1): ``validate.yml`` pins the diff to the pull request's
base/head SHAs (or the push before/after SHAs) and runs
``git diff --name-status -z -M -C`` over the range the event
defines -- the three-dot (merge-base) range ``BASE...HEAD`` for a
pull request, the two-dot range ``BEFORE..AFTER`` for a push --
after completing the two pinned commits' history with a
conditional ``--unshallow`` fetch when the checkout is shallow
(B2R5-M1).  ``changes_from_name_status()`` converts the output to
the shape above.  A list fetched by pull-request number would
describe the pull request's current state instead, which a re-run
-- bound to the original event's checkout and payload -- could
silently disagree with.

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
import re
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


_NAME_PATTERN = None


def _schema_name_pattern():
    """The declaration ``name`` pattern, read from the PR-B1 schema.

    The pattern literal lives only in
    ``schema/central-extension.schema.json`` (PR-B1); the router reads
    it from ``central.SCHEMA_PATH`` instead of duplicating it, the same
    way it reuses ``central.NAME_RE`` and ``central.windows_name_error``.
    """
    global _NAME_PATTERN
    if _NAME_PATTERN is None:
        try:
            schema = json.loads(central.SCHEMA_PATH.read_text(encoding="utf-8"))
            _NAME_PATTERN = re.compile(schema["properties"]["name"]["pattern"])
        except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
            raise RouterError(
                f"cannot read the declaration name pattern from "
                f"{central.SCHEMA_PATH}: {exc}"
            ) from exc
    return _NAME_PATTERN


def _validate_extension_name(name, origin):
    if not isinstance(name, str) or not central.NAME_RE.match(name):
        raise RouterError(f"{origin}: {name!r} is not a legal extension name")
    if not _schema_name_pattern().fullmatch(name):
        raise RouterError(
            f"{origin}: {name!r} does not match the central declaration "
            "name pattern (no leading or repeated dots)"
        )
    error = central.windows_name_error(name)
    if error is not None:
        raise RouterError(f"{origin}: extension name {name!r} is unusable: {error}")


def _check_casefold_collision(name, others, origin):
    """Reject ``name`` if it case-collides with a different name.

    On a Windows checkout two names that differ only in case are the
    same directory, so the tree cannot hold both (the PR-B1 rule
    SOL-B1-R2-01, enforced for extension roots by
    ``central.validate_tree``).
    """
    folded = name.casefold()
    for other in others:
        if other != name and other.casefold() == folded:
            raise RouterError(
                f"{origin}: extension name {name!r} collides with {other!r} "
                "on a case-insensitive filesystem"
            )


def registered_extensions(fleet_path=FLEET_PATH, extensions_root=None):
    """Sorted registered extension names (fleet registry + tree layout)."""
    names = set()
    try:
        fleet = json.loads(Path(fleet_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RouterError(f"{fleet_path}: cannot read the fleet registry: {exc}") from exc
    if not isinstance(fleet, dict):
        raise RouterError(f"{fleet_path}: fleet registry must be a JSON object")
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
        # The PR-B1 layout rules (central.validate_tree): the inspected
        # tree must be the tree that lands in the protected commit, so
        # neither the extensions root nor an extension root may be a
        # symbolic link.
        if layout.is_symlink():
            raise RouterError(f"{layout}: the extensions root must not be a symbolic link")
        if layout.is_dir():
            for child in sorted(layout.iterdir()):
                if child.is_symlink():
                    raise RouterError(
                        f"{child}: symbolic link extension roots are not allowed"
                    )
                if child.is_dir():
                    _validate_extension_name(child.name, f"{layout} directory")
                    names.add(child.name)
    ordered = sorted(names)
    for index, name in enumerate(ordered):
        _check_casefold_collision(name, ordered[index + 1:], "registered extensions")
    return ordered


def _validate_path(path, origin):
    if not isinstance(path, str) or not path:
        raise RouterError(f"{origin}: path must be a non-empty string, got {path!r}")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise RouterError(f"{origin}: path contains control characters: {path!r}")
    if path.startswith("/") or "\\" in path:
        raise RouterError(f"{origin}: path must be a relative POSIX path, got {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise RouterError(f"{origin}: path has an empty, '.' or '..' component: {path!r}")
    return parts


def classify_path(path, *, registered, smoke):
    """Classify one changed path.

    Returns ``(kind, targets, name)`` where kind is one of
    ``extension``, ``documentation``, ``shared`` or ``unclassified``,
    targets is a frozenset of extension names the path selects, and
    name is the ``extensions/<name>`` component the path was judged
    under (``None`` for other roots).  The name is reported even when
    it is unregistered and the path falls back, so the caller can
    still apply the within-change case-collision rule to it.

    The evaluation order matters: the ``extensions/`` root is judged
    first (a case variant of it is an extraction failure, never a
    document), then the shared build / CI foundation roots (a Markdown
    file under a shared root is still a shared change), and only then
    documentation, which is limited to ``docs/**`` and Markdown at the
    repository root.  Anything else is unclassified and falls back to
    every registered extension -- including a legal ``extensions/``
    name that is not in the registered set (B2-SOL-M2).
    """
    parts = _validate_path(path, "changed path")
    root = parts[0]
    if root.lower() == "extensions":
        if root != "extensions":
            raise RouterError(
                f"changed path {path!r}: root {root!r} collides with the "
                "'extensions' root on a case-insensitive filesystem"
            )
        if len(parts) < 3:
            raise RouterError(
                f"changed path {path!r}: a file directly under 'extensions/' "
                "is not extension content (the PR-B1 layout rule)"
            )
        name = parts[1]
        _validate_extension_name(name, f"changed path {path!r}")
        _check_casefold_collision(name, registered, f"changed path {path!r}")
        if name in registered:
            return "extension", frozenset({name}), name
        # A legal name that is not registered is not a target of its
        # own (B2-SOL-M2): a deletion or rename can outlive the
        # registry entry (the extension was retired or renamed away in
        # the same change), so the impact on the registered set is
        # unknown and the path takes the safety side -- every
        # registered extension -- like any unclassified path.
        # Extraction failure is reserved for input that cannot be
        # trusted (illegal or colliding names, malformed lists), which
        # is a different case from an unknown impact: failing the
        # required check would block the very change that retires or
        # renames an extension.
        return "unclassified", frozenset(registered), name
    if root in SHARED_ROOTS:
        return "shared", frozenset(smoke), None
    if root == "docs" or (len(parts) == 1 and path.lower().endswith(".md")):
        return "documentation", frozenset(), None
    return "unclassified", frozenset(registered), None


# The file statuses the GitHub REST API reports for pull-request and
# compare file lists.  A missing or unknown status means the change
# list is not in the documented shape, so it is an extraction failure
# rather than a silently accepted entry.
VALID_STATUSES = frozenset(
    {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}
)

# The mapping from ``git diff --name-status`` status letters to the
# GitHub file-list values above, fixed for the pinned-diff conversion
# (B2-SOL-R2-M1).  A type change (file <-> symlink <-> submodule) is
# git's T, which the API calls "changed"; rename / copy entries carry
# a similarity score (R100, C075) and are followed by the old path and
# then the new path.  U (unmerged) has no mapping: a commit-to-commit
# diff never produces it, so it is an extraction failure like any
# other unknown letter.
GIT_NAME_STATUS_MAP = {
    "A": "added",
    "C": "copied",
    "D": "removed",
    "M": "modified",
    "R": "renamed",
    "T": "changed",
}


def changes_from_name_status(data):
    """Convert ``git diff --name-status -z -M -C`` output to a change list.

    ``data`` is the raw NUL-separated byte stream.  Rename and copy
    entries are followed by the old path and then the new path; every
    other entry by its single path.  Anything outside that shape --
    an unknown status letter, a malformed similarity score, a score
    on a simple status, a truncated rename / copy pair, an empty
    path, or a path that is not valid UTF-8 -- is an extraction
    failure, so the caller falls back to the safety side instead of
    routing an untrusted list.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise RouterError(
            f"name-status input must be bytes, got {type(data).__name__}")
    data = bytes(data)
    if data and not data.endswith(b"\0"):
        # A non-empty ``git diff --name-status -z`` stream always
        # ends with a NUL terminator; a missing one means the stream
        # was truncated mid-entry (B2R5-N1).
        raise RouterError("name-status stream is missing its final NUL")
    fields = data.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes = []
    index = 0
    while index < len(fields):
        raw_token = fields[index]
        index += 1
        try:
            token = raw_token.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RouterError(
                f"name-status token is not ASCII: {raw_token!r}") from exc
        if not token:
            raise RouterError("name-status stream has an empty status field")
        letter, score = token[0], token[1:]
        if letter not in GIT_NAME_STATUS_MAP:
            raise RouterError(f"unknown git name-status {token!r}")
        if letter in ("R", "C"):
            if (not score or len(score) > 3 or not score.isdigit()
                    or not 0 <= int(score) <= 100):
                # ``git diff -M -C`` always reports a similarity
                # score in the range 0-100 for rename / copy
                # entries; a missing or out-of-range score is a
                # malformed stream (B2R5-N1).  The length is checked
                # before the conversion: an absurdly long digit
                # string would otherwise make int() itself raise
                # ValueError (Python's conversion digit limit) and
                # escape the RouterError diagnostic path
                # (B2-SOL-R3-N1).
                raise RouterError(
                    f"malformed similarity score in git name-status {token!r}")
        elif score:
            raise RouterError(
                f"unexpected score on git name-status {token!r}")
        paths = []
        for _ in range(2 if letter in ("R", "C") else 1):
            if index >= len(fields):
                raise RouterError(
                    f"name-status stream ends inside a {token!r} entry")
            raw_path = fields[index]
            index += 1
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RouterError(
                    f"name-status path is not UTF-8: {raw_path!r}") from exc
            if not path:
                raise RouterError(
                    f"name-status {token!r} entry has an empty path")
            paths.append(path)
        change = {"filename": paths[-1], "status": GIT_NAME_STATUS_MAP[letter]}
        if letter in ("R", "C"):
            change["previous_filename"] = paths[0]
        changes.append(change)
    return changes


def route_changes(changes, *, registered, smoke):
    """Route a GitHub-shaped change list to the target extension matrix."""
    if not isinstance(changes, list):
        raise RouterError(f"change list must be a JSON array, got {type(changes).__name__}")
    targets = set()
    classified = []
    selected_names = []
    for index, change in enumerate(changes):
        origin = f"change[{index}]"
        if not isinstance(change, dict):
            raise RouterError(f"{origin}: entry must be an object, got {change!r}")
        filename = change.get("filename")
        if not isinstance(filename, str) or not filename:
            raise RouterError(f"{origin}: entry has no usable 'filename': {change!r}")
        status = change.get("status")
        if not isinstance(status, str) or status not in VALID_STATUSES:
            raise RouterError(
                f"{origin}: 'status' must be one of {sorted(VALID_STATUSES)}, "
                f"got {status!r}"
            )
        previous = change.get("previous_filename")
        if status in ("renamed", "copied") and not previous:
            raise RouterError(
                f"{origin}: status {status!r} without 'previous_filename': {change!r}"
            )
        for label, path in (("filename", filename), ("previous_filename", previous)):
            if path is None:
                continue
            kind, selected, name = classify_path(
                path, registered=registered, smoke=smoke)
            if name is not None:
                # Every extensions/<name> component in the change --
                # registered or not -- joins the within-change
                # case-collision rule: two case variants in one change
                # would be the same directory on a Windows checkout.
                _check_casefold_collision(name, selected_names, origin)
                selected_names.append(name)
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


def launchable_targets(targets, extensions_root):
    """Routed targets whose per-extension CI can launch from this tree.

    The dependent matrix job in ``validate.yml`` calls the reusable
    per-extension workflow (``build-extension.yml``) against the
    extension's in-tree packaging subtree ``extensions/<name>/``.  A
    target whose subtree has not landed in the monorepo yet -- the
    subtrees arrive with the F2-2 pilot migrations and the F3a waves --
    has nothing for that workflow to build, so the launch matrix is
    the routed targets intersected with the subtrees present in the
    tree.  Symbolic-link subtrees never launch: the PR-B1 layout rules
    already bar them from the registered set.  The check is
    self-contained for direct callers: a symbolic-link ``extensions/``
    root itself (or a missing one) launches nothing, without relying
    on the registry path having rejected the link first (B2R3-N1).
    """
    layout = Path(extensions_root) / "extensions"
    if layout.is_symlink() or not layout.is_dir():
        return []
    return sorted(
        name
        for name in targets
        if (layout / name).is_dir() and not (layout / name).is_symlink()
    )


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
    "${{ github.event.pull_request.number || "
    "github.event_name == 'push' && "
    "format('{0}-{1}', github.ref, github.run_id) || github.ref }}"
)

# The router entry's template below is the Python-side rendering of
# ROUTER_WORKFLOW_GROUP: the GitHub Actions expression is kept as the
# workflow constant above (validate.yml declares it verbatim), while
# concurrency_group() renders the same shape from the {workflow} and
# {scope} placeholders (the workflow name and the scope the
# expression resolves to).  The scope is the pull-request number for
# a pull request and the ref for other events -- except pushes,
# where it is "<ref>-<run id>": GitHub keeps a single pending slot
# per concurrency group, so a push group keyed only by ref would let
# a newer run displace a waiting push run, and that push's landing
# SHA would never be routed (B2-SOL-R3-M1).  A run id is stable
# across re-runs of the same run, so re-running a push keeps its
# group while distinct pushes never share one.
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
    "router": {"group": "ci-router-{workflow}-{scope}", "cancel_in_progress": False},
}


_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_CANDIDATE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")


def _validate_group_value(kind, key, value):
    """Validate one concurrency-group value and return its string form.

    Every value that lands in a group is checked before substitution:
    an empty or malformed matrix key would collapse distinct jobs into
    one group (or split one series across groups), which is exactly
    what the contract exists to prevent.
    """
    origin = f"processing type {kind!r}"
    if key == "extension":
        _validate_extension_name(value, origin)
        return value
    if key in ("pr_number", "pg_major"):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RouterError(
                f"{origin}: {key} must be a positive integer, got {value!r}"
            )
        return str(value)
    if key == "candidate_id":
        if not isinstance(value, str) or not _CANDIDATE_ID_RE.match(value):
            raise RouterError(
                f"{origin}: candidate_id must be a non-empty identifier "
                f"([A-Za-z0-9._-]), got {value!r}"
            )
        return value
    # workflow / scope are free-form labels (a workflow name contains
    # spaces, a scope is a ref); only emptiness and placeholder
    # injection are barred.
    if not isinstance(value, str) or not value or "{" in value or "}" in value:
        raise RouterError(
            f"{origin}: {key} must be a non-empty string without braces, "
            f"got {value!r}"
        )
    return value


def concurrency_group(kind, *, extension=None, pr_number=None, candidate_id=None,
                      pg_major=None, workflow=None, scope=None):
    """Render the concurrency group for one job of a processing type.

    Series jobs pass ``pg_major`` so the PostgreSQL series of one
    extension land in distinct groups and never cancel each other
    (DESIGN 2.2 matrix-key rule).  Types that keep an existing unit
    (signing, publishing, catalog update) raise RouterError instead of
    inventing a replacement group.  The ``router`` type renders the
    workflow group of ROUTER_WORKFLOW_GROUP from its ``workflow`` and
    ``scope`` values.

    Substitution is a single pass over the template, and every value
    is validated first, so a value can never inject a second
    placeholder into the rendered group.
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
    provided = {
        "extension": extension,
        "pr_number": pr_number,
        "candidate_id": candidate_id,
        "workflow": workflow,
        "scope": scope,
    }
    values = {
        key: _validate_group_value(kind, key, value)
        for key, value in provided.items()
        if value is not None
    }

    def substitute(match):
        key = match.group(1)
        if key not in values:
            raise RouterError(f"processing type {kind!r} requires {key}")
        return values[key]

    group = _PLACEHOLDER_RE.sub(substitute, template)
    if "{" in group or "}" in group:
        raise RouterError(f"processing type {kind!r}: unfilled group template {template!r}")
    if pg_major is not None:
        group = f"{group}-pg{_validate_group_value(kind, 'pg_major', pg_major)}"
    return group


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--files",
        default="-",
        help="JSON change list in GitHub file-list shape ('-' reads stdin)",
    )
    parser.add_argument(
        "--name-status",
        metavar="FILE",
        default=None,
        help="convert a 'git diff --name-status -z -M -C' stream (FILE, "
        "or '-' for stdin) to the JSON change list and exit",
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

    if args.name_status is not None:
        try:
            if args.name_status == "-":
                raw_stream = sys.stdin.buffer.read()
            else:
                try:
                    raw_stream = Path(args.name_status).read_bytes()
                except OSError as exc:
                    raise RouterError(
                        f"cannot read the name-status stream "
                        f"{args.name_status}: {exc}"
                    ) from exc
            print(json.dumps(changes_from_name_status(raw_stream)))
        except RouterError as exc:
            print(f"ci-router: {exc}", file=sys.stderr)
            return 2
        return 0

    try:
        if args.files == "-":
            raw = sys.stdin.read()
        else:
            try:
                raw = Path(args.files).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise RouterError(
                    f"cannot read the change list {args.files}: {exc}"
                ) from exc
        try:
            changes = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RouterError(f"change list is not valid JSON: {exc}") from exc
        registered = registered_extensions(args.fleet, args.extensions_root)
        smoke = PILOT_SMOKE_EXTENSIONS if args.shared_policy == "smoke" else registered
        result = route_changes(changes, registered=registered, smoke=smoke)
        launch = launchable_targets(result["targets"], args.extensions_root)
        result["launch_targets"] = launch
        result["launch_matrix"] = {
            "include": [{"extension": name} for name in launch]
        }
        result["has_launch_targets"] = bool(launch)
    except RouterError as exc:
        print(f"ci-router: {exc}", file=sys.stderr)
        return 2

    if args.format == "github":
        print(f"matrix={json.dumps(result['matrix'], separators=(',', ':'))}")
        print(f"has_targets={'true' if result['has_targets'] else 'false'}")
        print(f"targets={','.join(result['targets'])}")
        print(f"launch_matrix={json.dumps(result['launch_matrix'], separators=(',', ':'))}")
        print(f"has_launch_targets={'true' if result['has_launch_targets'] else 'false'}")
        print(f"resolver_conclusion={result['resolver_conclusion']}")
        print(f"pending={result['pending']}")
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
