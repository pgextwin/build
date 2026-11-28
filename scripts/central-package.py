#!/usr/bin/env python3
"""Common build / packaging / K2 / K4 verification foundation for the
central monorepo (F21-04).

Provides the shared side of:
  * upstream pinned-SHA comparison (the declared commit in
    ``extensions/<name>/extension.json`` is the only source of truth),
  * deterministic ZIP packaging and SHA-256 generation,
  * the K2 byte-integrity handoff chain T0 -> T1 -> T2 -> T3 (the same
    ZIP bytes must be presented at every stage; any byte change breaks
    the recorded SHA-256 / size and is rejected),
  * the K4 per-version license original comparison, with the same entry
    semantics as ``scripts/verify-license-bytes.py`` (upstream-origin
    entries must match the upstream bytes at the pinned commit,
    packaging / build entries must match their pinned SHA-256, duplicate
    repository paths / build targets are rejected, and at least one
    upstream-verified entry is required),
  * the adapter execution-context boundary: ``build_adapter_environment``
    builds the only environment the common foundation may pass to
    extension-specific adapter / test code, and it never carries signing,
    Publisher, or local-auth credentials (CB70-12).

The ``verify-licenses`` CLI binds the K4 comparison to the target
declaration: the expected upstream commit is selected from the
declaration for the requested PostgreSQL major, the expected packaging
commit is supplied by the caller as a trusted value, both repositories
must resolve to those commits before any blob is read, and every blob
is then read at the resolved SHA (``git cat-file blob <sha>:<path>``),
exactly like ``verify-license-bytes.py``, so untracked or modified
worktree files, symbolic links, and references that move during the
comparison cannot leak into the K4 comparison. Every Git read runs
with replace refs disabled, so a local ``refs/replace/*`` entry
cannot substitute another object's bytes for the pinned one while
the document records the pinned SHA. The emitted document
uses the ``verify-license-bytes.py`` shape (``licenses``), which
``scripts/windows-package.ps1`` consumes directly.

Actual pilot execution of these foundations is F2-2; this module is the
shared foundation plus its positive / negative tests.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}\Z")
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")
GENERATED_SOURCES = ("upstream", "buildOutput")
STAGES = ("T0", "T1", "T2", "T3")
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_pinned_commit(declared_commit, actual_commit):
    """Reject when the fetched upstream HEAD differs from the declaration."""
    if not isinstance(declared_commit, str) or not SHA40_RE.fullmatch(declared_commit):
        raise ValueError(f"Declared upstream commit is not a full SHA: {declared_commit!r}")
    if not isinstance(actual_commit, str) or not SHA40_RE.fullmatch(actual_commit):
        raise ValueError(f"Actual upstream commit is not a full SHA: {actual_commit!r}")
    if declared_commit.lower() != actual_commit.lower():
        raise ValueError(
            f"Upstream commit mismatch: declared {declared_commit} but fetched {actual_commit}."
        )


# The OrdinalIgnoreCase fold, measured against the reference
# implementation (PowerShell 7.4.16, [StringComparer]::OrdinalIgnoreCase)
# over the whole Unicode range -- the Basic Multilingual Plane
# exhaustively, and every cased astral character (Deseret, Osage,
# and the other cased astral blocks, whose simple case mappings
# Python and .NET agree on exactly): two characters collide under
# OrdinalIgnoreCase exactly when they belong to one measured
# equivalence class. Python's str.upper() reproduces those classes
# except at the code points below (SOL-B1-R3-04):
#   * U+0131 (LATIN SMALL LETTER DOTLESS I) and U+017F (LATIN SMALL
#     LETTER LONG S): str.upper() folds them to I / S, but
#     OrdinalIgnoreCase keeps them distinct, so the fold must not
#     map them at all.
#   * The Greek ypogegrammeni letters (U+1F80..U+1F87, U+1F90..
#     U+1F97, U+1FA0..U+1FA7, U+1FB3, U+1FC3, U+1FF3): their full
#     uppercase mapping expands to two characters, so a length-based
#     str.upper() rule keeps them unfolded, while OrdinalIgnoreCase
#     maps them to their single-character simple uppercase forms
#     (U+1F88.., U+1FBC, U+1FCC, U+1FFC).
# With these overrides the fold's equality classes match the
# measured OrdinalIgnoreCase classes on every BMP code point.
_ORDINAL_IGNORE_CASE_OVERRIDES = {
    0x0131: 0x0131,
    0x017F: 0x017F,
    0x1F80: 0x1F88, 0x1F81: 0x1F89, 0x1F82: 0x1F8A, 0x1F83: 0x1F8B,
    0x1F84: 0x1F8C, 0x1F85: 0x1F8D, 0x1F86: 0x1F8E, 0x1F87: 0x1F8F,
    0x1F90: 0x1F98, 0x1F91: 0x1F99, 0x1F92: 0x1F9A, 0x1F93: 0x1F9B,
    0x1F94: 0x1F9C, 0x1F95: 0x1F9D, 0x1F96: 0x1F9E, 0x1F97: 0x1F9F,
    0x1FA0: 0x1FA8, 0x1FA1: 0x1FA9, 0x1FA2: 0x1FAA, 0x1FA3: 0x1FAB,
    0x1FA4: 0x1FAC, 0x1FA5: 0x1FAD, 0x1FA6: 0x1FAE, 0x1FA7: 0x1FAF,
    0x1FB3: 0x1FBC, 0x1FC3: 0x1FCC, 0x1FF3: 0x1FFC,
}


def _ordinal_ignore_case_key(name):
    """Fold a ZIP entry name the way windows-package.ps1 compares it.

    Resolve-WindowsPackage compares install destinations with
    [StringComparison]::OrdinalIgnoreCase. That comparison is a
    per-character simple case mapping: a character whose full
    uppercase mapping is not a single character (ß, whose full
    mapping is "SS") keeps its original form. str.casefold()
    applies the full Unicode mapping and expands ß to "ss", which
    made this entrance reject pairs the existing contract accepts
    (docs/straße next to docs/STRASSE/a.txt, SOL-B1-R2-N1); a plain
    str.upper() fold diverges from the measured OrdinalIgnoreCase
    classes at the code points in _ORDINAL_IGNORE_CASE_OVERRIDES
    (SOL-B1-R3-04). The fold here is the measured one: ß stays ß,
    ASCII case variants fold together, and the Greek ypogegrammeni
    letters fold to their simple uppercase forms exactly as the
    reference implementation does.
    """
    folded = []
    for char in name:
        override = _ORDINAL_IGNORE_CASE_OVERRIDES.get(ord(char))
        if override is not None:
            folded.append(chr(override))
            continue
        upper = char.upper()
        folded.append(upper if len(upper) == 1 else char)
    return "".join(folded)


def write_deterministic_zip(entries, out_path):
    """Write a byte-reproducible ZIP from {arcname: bytes} and describe it."""
    if not entries:
        raise ValueError("Cannot package an empty entry set.")
    # Every entry name is validated before the archive is opened, under
    # the same Windows path contract as license paths (Assert-PackagePath
    # in scripts/windows-package.ps1): no backslash separators (Windows
    # Zip Slip), no Windows-invalid characters (brackets included), no
    # trailing space / dot segments, no reserved device names, no
    # absolute names, and no two names that collide on a
    # case-insensitive filesystem -- neither as identical names nor as
    # a file-versus-directory prefix pair (one name a strict path
    # prefix of another), the same conflict windows-package.ps1
    # rejects for install destinations. The collision comparison uses
    # the OrdinalIgnoreCase fold of _ordinal_ignore_case_key, matching
    # the comparison windows-package.ps1 itself performs.
    folded = []
    for arcname in entries:
        _validate_relative_path(arcname, "ZIP entry name")
        key = _ordinal_ignore_case_key(arcname)
        for existing in folded:
            if key == existing or key.startswith(existing + "/") or existing.startswith(key + "/"):
                raise ValueError(
                    f"ZIP entry names collide on a case-insensitive filesystem: '{arcname}'."
                )
        folded.append(key)
    out_path = Path(out_path)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname in sorted(entries):
            info = zipfile.ZipInfo(arcname, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entries[arcname])
    return {
        "fileName": out_path.name,
        "size": out_path.stat().st_size,
        "sha256": sha256_file(out_path),
    }


def read_zip_entries(zip_path):
    with zipfile.ZipFile(zip_path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def handoff_record(stage, extension, pg_major, zip_path, previous=None):
    """Record one K2 handoff point (T0..T3) for a packaged ZIP."""
    if stage not in STAGES:
        raise ValueError(f"Unknown handoff stage: {stage!r}")
    index = STAGES.index(stage)
    if index == 0 and previous is not None:
        raise ValueError("The T0 handoff record must not have a previous record.")
    if index > 0:
        if previous is None:
            raise ValueError(
                f"The {stage} handoff record requires the {STAGES[index - 1]} record as previous."
            )
        if not isinstance(previous, dict) or previous.get("stage") != STAGES[index - 1]:
            raise ValueError(
                f"The {stage} handoff record's previous record must be stage {STAGES[index - 1]}."
            )
    if not isinstance(extension, str) or not extension:
        raise ValueError("Handoff record requires a nonempty extension name.")
    if isinstance(pg_major, bool) or not isinstance(pg_major, int) or pg_major < 1:
        raise ValueError("Handoff record requires a positive integer PostgreSQL major.")
    zip_path = Path(zip_path)
    size = zip_path.stat().st_size
    if size <= 0:
        raise ValueError("Handoff record requires a nonempty packaged ZIP.")
    record = {
        "schemaVersion": 1,
        "stage": stage,
        "extension": extension,
        "pgMajor": pg_major,
        "fileName": zip_path.name,
        "size": size,
        "sha256": sha256_file(zip_path),
        "previousStage": previous["stage"] if previous else None,
        "previousSha256": previous["sha256"] if previous else None,
    }
    return record


def _validate_handoff_record(record, stage):
    """Fail-closed shape validation for one handoff record (K2).

    A chain of well-linked but empty or malformed records (empty digest,
    zero size, wrong schema version) must never verify: every field the
    chain comparison relies on is type- and format-checked first.
    """
    if not isinstance(record, dict):
        raise ValueError(f"Handoff {stage} record is not a JSON object.")
    if record.get("stage") != stage:
        raise ValueError(
            f"Handoff record must be stage {stage}, got {record.get('stage')!r}."
        )
    schema_version = record.get("schemaVersion")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise ValueError(f"Handoff {stage} schemaVersion must be 1, got {schema_version!r}.")
    for key in ("previousStage", "previousSha256"):
        if key not in record:
            raise ValueError(
                f"Handoff {stage} record is missing '{key}'; an absent key "
                "is not interchangeable with an explicit null."
            )
    for key in ("extension", "fileName"):
        value = record.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Handoff {stage} '{key}' must be a nonempty string.")
    pg_major = record.get("pgMajor")
    if isinstance(pg_major, bool) or not isinstance(pg_major, int) or pg_major < 1:
        raise ValueError(f"Handoff {stage} 'pgMajor' must be a positive integer.")
    size = record.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError(f"Handoff {stage} 'size' must be a positive integer.")
    digest = record.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ValueError(f"Handoff {stage} 'sha256' must be a 64-digit lowercase hex digest.")


def verify_handoff_chain(records, *, expected_sha256, expected_size,
                         expected_extension, expected_pg_major, expected_file_name):
    """Verify a complete T0 -> T1 -> T2 -> T3 chain for one ZIP.

    A K2 pass is only ever returned against independent expectations:
    the SHA-256 and size measured by the trusted packaging step, and
    the target extension / PostgreSQL major / file name the chain is
    supposed to describe. All five expectations are required arguments;
    there is no call form that verifies a chain against itself. Every
    stage must present the identical bytes for the expected target,
    linked in order, so a chain rebuilt wholesale from tampered T0
    bytes, or recorded for a different target, is rejected here (K2).
    """
    if not isinstance(records, list) or len(records) != len(STAGES):
        got = len(records) if isinstance(records, list) else type(records).__name__
        raise ValueError(
            f"Handoff chain must contain exactly {len(STAGES)} records, got {got}."
        )
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a 64-digit lowercase hex digest.")
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size <= 0
    ):
        raise ValueError("expected_size must be a positive integer.")
    if not isinstance(expected_extension, str) or not expected_extension:
        raise ValueError("expected_extension must be a nonempty string.")
    if (
        isinstance(expected_pg_major, bool)
        or not isinstance(expected_pg_major, int)
        or expected_pg_major < 1
    ):
        raise ValueError("expected_pg_major must be a positive integer.")
    if not isinstance(expected_file_name, str) or not expected_file_name:
        raise ValueError("expected_file_name must be a nonempty string.")
    expectations = {
        "extension": expected_extension,
        "pgMajor": expected_pg_major,
        "fileName": expected_file_name,
        "size": expected_size,
        "sha256": expected_sha256,
    }
    first = records[0]
    for index, (record, stage) in enumerate(zip(records, STAGES)):
        _validate_handoff_record(record, stage)
        for key in ("extension", "pgMajor", "fileName", "size", "sha256"):
            if record.get(key) != first.get(key):
                raise ValueError(
                    f"Handoff {stage} differs from T0 on '{key}': "
                    f"{record.get(key)!r} != {first.get(key)!r} (K2 byte integrity)."
                )
            if record.get(key) != expectations[key]:
                raise ValueError(
                    f"Handoff {stage} '{key}' is {record.get(key)!r} but the "
                    f"trusted expectation is {expectations[key]!r} (K2 byte integrity)."
                )
        expected_previous = records[index - 1] if index else None
        if record.get("previousStage") != (expected_previous["stage"] if expected_previous else None):
            raise ValueError(f"Handoff {stage} previousStage linkage is broken.")
        if record.get("previousSha256") != (expected_previous["sha256"] if expected_previous else None):
            raise ValueError(f"Handoff {stage} previousSha256 linkage is broken.")


_WINDOWS_INVALID_SEGMENT_CHARS = re.compile(r'[<>:"\\|\[\]?*\x00-\x1f]')
_WINDOWS_RESERVED_SEGMENT = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$)(?:\.|$)",
    re.IGNORECASE,
)


def _validate_relative_path(path, label):
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise ValueError(f"Invalid {label} '{path}'.")
    for part in path.split("/"):
        # Same segment contract as Assert-PackagePath in
        # scripts/windows-package.ps1: no empty / "." / ".." segments,
        # no Windows-invalid characters (which also rejects drive-letter
        # forms such as "C:"), no trailing space or dot, and no reserved
        # device names.
        if (
            not part or part in (".", "..")
            or _WINDOWS_INVALID_SEGMENT_CHARS.search(part)
            or part.endswith((" ", "."))
            or _WINDOWS_RESERVED_SEGMENT.match(part)
        ):
            raise ValueError(f"Invalid {label} '{path}'.")


# Adapter execution-context boundary (DESIGN 1.3, CB70-12). The common
# foundation executes extension-specific adapter / test code only
# through run_adapter_script below, with an environment built here: a
# strict allowlist of non-secret build variables copied from the base
# environment, plus additional build inputs the caller enumerates
# explicitly as name -> value pairs. Values are never pulled out of the
# parent environment by name: a by-name pull is not a strict allowlist,
# because an unlisted credential variable would pass any denylist.
# Signing OIDC request tokens, the Actions runtime token and
# file-command variables (GITHUB_ENV / GITHUB_OUTPUT / ...), the
# GITHUB_TOKEN / GH_TOKEN namespace, Publisher variables, local-auth
# credentials, and anything token / secret / key / auth shaped are
# never passed, so adapter code cannot reach signing, Publisher, or
# authorization material through the process environment.
#
# The names that locate the account's persistent configuration (home
# and profile directories, tool config roots, git config switches)
# are boundary-managed as well: they are never copied from the parent
# environment and callers may not supply them as extras. Instead,
# run_adapter_script binds every one of them to a fresh per-run clean
# home, so tools invoked by adapter code (git, gh, pwsh) cannot reach
# the parent account's persistent credential stores
# (~/.config/gh/hosts.yml, ~/.git-credentials, ~/.gitconfig,
# PowerShell profiles, ...) through the environment.
ADAPTER_ENV_ALLOWLIST = frozenset({
    "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL", "TZ",
})
ADAPTER_ENV_MANAGED_NAMES = frozenset({
    "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA",
    "LOCALAPPDATA", "XDG_CONFIG_HOME", "GH_CONFIG_DIR",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
})
ADAPTER_ENV_FORBIDDEN_PREFIXES = (
    "ACTIONS_", "GITHUB_", "PUBLISHER_", "LOCAL_AUTH_", "LOCAL-AUTH",
)
ADAPTER_ENV_FORBIDDEN_MARKERS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE",
    "_KEY", "APIKEY", "AUTH", "JWT", "CERT", "PASSPHRASE", "SIGNING",
    "ADMISSION", "OIDC", "ATTEST",
)
_ADAPTER_ENV_KEY_WORD_RE = re.compile(r"(?:^|_)KEY(?:_|$)")
ADAPTER_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}\Z")


def _adapter_env_key_forbidden(key):
    upper = key.upper()
    # "PUBLISHER" is forbidden in any position (PUBLISHER,
    # MY_PUBLISHER, PUBLISHER_TOKEN, ...), and "KEY" as a whole word
    # (KEY, KEY_PEM, APP_KEY, ...): a prefix/marker list alone let the
    # bare and infix forms through.
    if "PUBLISHER" in upper:
        return True
    if _ADAPTER_ENV_KEY_WORD_RE.search(upper):
        return True
    if upper.startswith(ADAPTER_ENV_FORBIDDEN_PREFIXES):
        return True
    return any(marker in upper for marker in ADAPTER_ENV_FORBIDDEN_MARKERS)


def build_adapter_environment(base_env, extra_values=None):
    """Build the credential-free environment for adapter execution.

    Only allowlisted non-secret variables are copied from ``base_env``.
    ``extra_values`` is the caller's explicit enumeration of additional
    build inputs (name -> value, constructed by the caller, never read
    from the parent environment). An extra name must be a well-formed
    variable name, must not collide with the base allowlist (base
    variables come from the base environment only, so PATH and friends
    cannot be overridden into a write path), must not be one of the
    boundary-managed persistent-configuration names (HOME, APPDATA,
    GH_CONFIG_DIR, git config switches, ... -- run_adapter_script
    binds those to a clean home), and must not be credential-shaped;
    every violation is a hard error (fail-closed) instead of a silent
    drop, so a caller can never smuggle a signing or Publisher
    credential, or a pointer at the parent account's persistent
    configuration, into the adapter context.
    """
    env = {}
    for key, value in base_env.items():
        if key.upper() in ADAPTER_ENV_MANAGED_NAMES:
            continue
        if key.upper() in ADAPTER_ENV_ALLOWLIST and not _adapter_env_key_forbidden(key):
            env[key] = value
    for key, value in (extra_values or {}).items():
        if not isinstance(key, str) or not ADAPTER_ENV_NAME_RE.fullmatch(key):
            raise ValueError(f"Invalid extra adapter environment variable name: {key!r}")
        if key.upper() in ADAPTER_ENV_ALLOWLIST:
            raise ValueError(
                f"Extra adapter environment variable collides with the base "
                f"allowlist and cannot be overridden: {key}"
            )
        if key.upper() in ADAPTER_ENV_MANAGED_NAMES:
            raise ValueError(
                f"Persistent-configuration variable is managed by the "
                f"adapter boundary and cannot be supplied: {key}"
            )
        if _adapter_env_key_forbidden(key):
            raise ValueError(
                f"Credential-bearing environment variable must not be passed "
                f"to adapter code: {key}"
            )
        if not isinstance(value, str):
            raise ValueError(
                f"Extra adapter environment variable must be a string: {key}"
            )
        env[key] = value
    return env


def _bind_clean_home(env, clean_home):
    """Bind every persistent-configuration name to a fresh clean home.

    Tools run by adapter code (git, gh, pwsh) locate account
    configuration through these names; pointing all of them at an
    empty directory created for this run means the parent account's
    persistent credential stores are unreachable through the
    environment, while the tools still find a writable home.
    """
    home = str(clean_home)
    appdata = clean_home / "AppData" / "Roaming"
    local_appdata = clean_home / "AppData" / "Local"
    xdg_config = clean_home / ".config"
    for directory in (appdata, local_appdata, xdg_config):
        directory.mkdir(parents=True, exist_ok=True)
    drive, tail = os.path.splitdrive(home)
    env["HOME"] = home
    env["USERPROFILE"] = home
    env["HOMEDRIVE"] = drive
    env["HOMEPATH"] = tail or home
    env["APPDATA"] = str(appdata)
    env["LOCALAPPDATA"] = str(local_appdata)
    env["XDG_CONFIG_HOME"] = str(xdg_config)
    env["GH_CONFIG_DIR"] = str(clean_home / "gh")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = str(clean_home / ".gitconfig")


ADAPTER_SCRIPT_SUFFIXES = (".ps1", ".psm1")


def decode_powershell_script(data):
    """Decode a PowerShell script exactly as the supported host does.

    This is the same encoding contract the static scan enforces in
    central-extension.py (decode_powershell_script there): the
    supported host is PowerShell 7, which selects the encoding from
    the byte-order mark (UTF-8, UTF-16 LE/BE, UTF-32 LE/BE) and
    reads BOM-less files as UTF-8. Outside the contract, raising
    ValueError: BOM-less bytes that are not valid UTF-8 (Windows
    PowerShell 5.1 would read them as the legacy ANSI code page,
    so the executed text would differ from the inspected text --
    and 5.1 is not a supported host at this entry at all,
    SOL-B1-R3-02), a doubled byte-order mark, and an embedded NUL
    character (SOL-B1-R3-03).
    """
    try:
        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            text = data.decode("utf-32")
        elif data.startswith(b"\xef\xbb\xbf"):
            text = data.decode("utf-8-sig")
        elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        else:
            text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            "script encoding is outside the supported contract "
            "(UTF-8, or UTF-16/UTF-32 with a byte-order mark): "
            f"{error}"
        ) from None
    if text.startswith("\ufeff"):
        raise ValueError(
            "script carries more than one byte-order mark; the "
            "residual U+FEFF is not part of the executed text the "
            "scan inspects."
        )
    if "\x00" in text:
        raise ValueError(
            "script contains an embedded NUL character, which the "
            "host does not execute as inspected text."
        )
    return text


def assert_adapter_script_encoding(script_path):
    """Refuse a script whose encoding is outside the shared contract.

    The execution entry and the static scan must agree on the text
    of the script that runs (SOL-B1-R2-02): the scan decodes with
    decode_powershell_script, and this gate applies the same
    decoding to the resolved script before the host is invoked, so
    a script the scan cannot interpret the way the host does never
    executes through the common entry. The shared decoding also
    refuses a doubled byte-order mark and an embedded NUL, the two
    byte forms under which the host reports an error yet exits 0
    (SOL-B1-R3-03): they never reach the host through this entry,
    so that silent-success path is closed here.
    """
    decode_powershell_script(Path(script_path).read_bytes())


def adapter_script_kind(script_path, extension_root):
    """Classify an executable adapter-area script, or reject it.

    Returns ``(kind, resolved_script, resolved_root)``: the resolved
    paths are the ones run_adapter_script actually executes with, so
    the inspected file and the executed file cannot drift apart even
    when the caller passes relative paths.

    The executable set is a subset of the statically scanned set
    (DESIGN 1.3): the tree validator statically scans ``adapter.ps1``
    and every executable script under ``tests/`` (any suffix), while
    execution through the common entry is limited to PowerShell --
    the extension root ``adapter.ps1`` and PowerShell scripts under
    ``tests/``. Anything else -- other locations, other suffixes,
    symbolic links (the root itself, any intermediate directory, or
    the script itself), nonexistent files, paths escaping the
    extension root -- is refused, so executed code always comes from
    inside the inspected tree.
    """
    root = Path(extension_root)
    if root.is_symlink():
        raise ValueError("Adapter execution root must not be a symbolic link.")
    script = Path(script_path)
    if script.is_symlink():
        raise ValueError(f"Adapter script must not be a symbolic link: {script_path}")
    if script.suffix.lower() not in ADAPTER_SCRIPT_SUFFIXES:
        raise ValueError(f"Adapter script must be PowerShell (.ps1/.psm1): {script_path}")
    # Intermediate directories between the root and the script must
    # not be symbolic links either: a tests/ subdirectory that links
    # elsewhere would execute code outside the inspected tree even if
    # the final resolved path happened to land back inside the root.
    # The walk uses unresolved absolute paths so it applies to the
    # path the caller actually named (relative paths included).
    absolute_root = Path(os.path.abspath(root))
    absolute_script = Path(os.path.abspath(script))
    try:
        named_rel = absolute_script.relative_to(absolute_root)
    except ValueError:
        named_rel = None
    if named_rel is not None:
        current = absolute_root
        for part in named_rel.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise ValueError(
                    f"Adapter script path traverses a symbolic link: {script_path}"
                )
    try:
        resolved_root = root.resolve()
        resolved_script = script.resolve()
        rel = resolved_script.relative_to(resolved_root)
    except (OSError, ValueError):
        raise ValueError(
            f"Adapter script is outside the extension root: {script_path}"
        ) from None
    if not resolved_script.is_file():
        raise ValueError(f"Adapter script does not exist as a file: {script_path}")
    parts = rel.parts
    if parts == ("adapter.ps1",):
        return "adapter", resolved_script, resolved_root
    if len(parts) >= 2 and parts[0] == "tests":
        return "test", resolved_script, resolved_root
    raise ValueError(
        f"Adapter script is outside the executable set (adapter.ps1 or tests/): {script_path}"
    )


def run_adapter_script(script_path, script_args=(), *, extension_root,
                       base_env=None, extra_values=None, timeout=None,
                       executable=None):
    """Run one adapter-area script through the common execution boundary.

    This is the only entry the common foundation uses to execute
    extension-specific code: the script must belong to the executable
    subset of the statically scanned set (adapter_script_kind), its
    encoding must satisfy the shared encoding contract the scan
    decodes with (assert_adapter_script_encoding), the
    child environment is built by build_adapter_environment (no
    signing / Publisher / local-auth credentials and no Actions
    file-command variables) with every persistent-configuration name
    rebound to a fresh per-run clean home, and the child runs the
    resolved script with the resolved extension root as its working
    directory -- never the caller's directory and never an unresolved
    path -- so settings or credential files sitting in the caller's
    workspace, or in the parent account's home, are not part of the
    execution context. ``executable`` is a test seam for the
    PowerShell executable; by default pwsh (PowerShell 7) is resolved
    from PATH and invoked with -NoProfile -File. PowerShell 7 is
    required: Windows PowerShell 5.1 reads BOM-less sources with the
    legacy ANSI code page, so under 5.1 the executed text of a
    BOM-less UTF-8 script differs from the text the static scan
    inspected, and the entry fails closed instead of falling back
    (SOL-B1-R3-02). The supported CI hosts (GitHub windows-latest
    and ubuntu-latest runners) ship pwsh, so the requirement does
    not change any existing execution path.
    """
    _kind, resolved_script, resolved_root = adapter_script_kind(
        script_path, extension_root
    )
    assert_adapter_script_encoding(resolved_script)
    env = build_adapter_environment(
        dict(os.environ) if base_env is None else base_env, extra_values
    )
    exe = executable or shutil.which("pwsh")
    if exe is None:
        raise RuntimeError(
            "No PowerShell 7 executable (pwsh) is available; the common "
            "entry does not fall back to Windows PowerShell 5.1, whose "
            "ANSI decoding of BOM-less sources would execute text the "
            "static scan did not inspect."
        )
    if executable is None:
        argv = [exe, "-NoProfile", "-File", str(resolved_script), *script_args]
    else:
        argv = [exe, str(resolved_script), *script_args]
    with tempfile.TemporaryDirectory(prefix="pgextwin-adapter-home-") as clean_home:
        _bind_clean_home(env, Path(clean_home))
        return subprocess.run(
            argv, cwd=resolved_root, env=env, timeout=timeout,
            capture_output=True, text=True, check=False,
        )


def verify_license_entries(entries, upstream, packaging):
    """Verify license entries against upstream / packaging byte sources.

    ``upstream`` maps upstream paths to the bytes at the pinned commit;
    ``packaging`` maps repository paths to the packaging-side bytes.
    Entry semantics mirror scripts/verify-license-bytes.py. Returns the
    verified list (path, size, sha256 per entry).
    """
    if not isinstance(entries, list) or not entries:
        raise ValueError("License verification requires at least one license entry.")
    verified = []
    upstream_count = 0
    # Duplicate tracking with the same semantics as
    # verify-license-bytes.py / resolve-matrix.ps1: repository paths are
    # compared case-insensitively (Windows paths collide), an upstream
    # entry and a packaging / build entry may never share one repository
    # path, two upstream entries for one repository path must carry
    # identical bytes, and one build target may be generated only once.
    seen_upstream = {}
    seen_non_upstream = set()
    seen_generated = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each license entry must be a JSON object.")
        origin = entry.get("origin")
        repository_path = entry.get("repositoryPath")
        _validate_relative_path(repository_path, "repositoryPath")
        repository_key = repository_path.casefold()

        if origin is None:
            unknown = set(entry) - {"repositoryPath", "upstreamPath", "upstreamStartMarker"}
            if unknown:
                raise ValueError(f"Unsupported license entry fields: {', '.join(sorted(unknown))}")
            if repository_key in seen_non_upstream:
                raise ValueError(f"Duplicate license repositoryPath '{repository_path}'.")
            upstream_path = entry.get("upstreamPath")
            _validate_relative_path(upstream_path, "upstreamPath")
            if upstream_path not in upstream:
                raise ValueError(f"Upstream license file not found at pinned commit: {upstream_path}")
            upstream_blob = upstream[upstream_path]
            expected = upstream_blob
            provenance = {}
            if "upstreamStartMarker" in entry:
                marker = entry["upstreamStartMarker"]
                if not isinstance(marker, str) or not marker:
                    raise ValueError("Expected a nonempty upstream license start marker.")
                offset = upstream_blob.find(marker.encode("utf-8"))
                if offset < 0:
                    raise ValueError(f"License range start not found in upstream '{upstream_path}'.")
                expected = upstream_blob[offset:]
                provenance = {
                    "upstreamOffset": offset,
                    "upstreamSize": len(upstream_blob),
                    "upstreamSha256": sha256_bytes(upstream_blob),
                }
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            if actual != expected:
                raise ValueError(
                    f"License file '{repository_path}' differs from upstream "
                    f"'{upstream_path}' at the pinned commit (K4)."
                )
            if repository_key in seen_upstream and seen_upstream[repository_key] != expected:
                raise ValueError(
                    f"Conflicting upstream bytes for license file '{repository_path}'."
                )
            seen_upstream[repository_key] = expected
            verified.append({
                "repositoryPath": repository_path,
                "upstreamPath": upstream_path,
                "size": len(expected),
                "sha256": sha256_bytes(expected),
                **provenance,
            })
            upstream_count += 1
        elif origin in ("packaging", "build"):
            expected_keys = (
                {"origin", "repositoryPath", "sha256"}
                if origin == "packaging"
                else {"origin", "repositoryPath", "generatedSource", "generatedPath", "sha256"}
            )
            if set(entry) != expected_keys:
                raise ValueError(f"Invalid fields for {origin} license entry '{repository_path}'.")
            expected_sha256 = entry["sha256"]
            if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
                raise ValueError(f"Invalid pinned license sha256 for '{repository_path}'.")
            if repository_key in seen_upstream or repository_key in seen_non_upstream:
                raise ValueError(f"Duplicate license repositoryPath '{repository_path}'.")
            extra = {}
            if origin == "build":
                if entry["generatedSource"] not in GENERATED_SOURCES:
                    raise ValueError(f"Invalid generatedSource for build license '{repository_path}'.")
                _validate_relative_path(entry["generatedPath"], "generatedPath")
                generated_key = (entry["generatedSource"], entry["generatedPath"].casefold())
                if generated_key in seen_generated:
                    raise ValueError(
                        f"Duplicate build license target "
                        f"'{entry['generatedSource']}:{entry['generatedPath']}'."
                    )
                seen_generated.add(generated_key)
                extra = {
                    "generatedSource": entry["generatedSource"],
                    "generatedPath": entry["generatedPath"],
                }
            if repository_path not in packaging:
                raise ValueError(f"Packaging license file not found: {repository_path}")
            actual = packaging[repository_path]
            digest = sha256_bytes(actual)
            if digest != expected_sha256:
                raise ValueError(
                    f"Packaging license file '{repository_path}' sha256 '{digest}' "
                    f"does not match pinned '{expected_sha256}' (K4)."
                )
            seen_non_upstream.add(repository_key)
            verified.append({
                "origin": origin,
                "repositoryPath": repository_path,
                "size": len(actual),
                "sha256": digest,
                **extra,
            })
        else:
            raise ValueError(f"Unsupported license origin: {origin!r}")

    if upstream_count < 1:
        raise ValueError(
            "License verification requires at least one upstream-verified license file (K4)."
        )
    return verified


def license_entries_for_major(license_block, pg_major):
    """Resolve the declaration license block to the entry list for a major."""
    if not isinstance(license_block, dict):
        raise ValueError("license must be an object.")
    if license_block.get("verifyAgainstUpstream") is not True:
        raise ValueError(
            "Central license verification requires verifyAgainstUpstream to be true; "
            "the central form does not allow opting out of the upstream comparison (K4)."
        )
    if "perPostgresql" in license_block:
        per_major = license_block["perPostgresql"]
        if not isinstance(per_major, dict):
            raise ValueError("license.perPostgresql must be an object.")
        key = str(pg_major)
        if key not in per_major:
            raise ValueError(f"No license entries declared for PostgreSQL {pg_major}.")
        return per_major[key]
    if "files" in license_block:
        return license_block["files"]
    if "upstreamPath" in license_block:
        upstream_path = license_block["upstreamPath"]
        # Canonical mapping of resolve-matrix.ps1: the single upstreamPath
        # form is always packaged under the fixed repository path
        # "LICENSE", whatever the upstream file itself is named (for
        # example pgtap's README.md / COPYRIGHT originals).
        return [{"repositoryPath": "LICENSE", "upstreamPath": upstream_path}]
    raise ValueError("license block declares no upstreamPath, files, or perPostgresql form.")


def verify_declaration_licenses(license_block, pg_major, upstream, packaging):
    """K4 check of a declaration license block for one PostgreSQL major."""
    entries = license_entries_for_major(license_block, pg_major)
    return verify_license_entries(entries, upstream, packaging)


def declared_upstream_commit(declaration, pg_major):
    """Select the declaration's pinned upstream commit for one major.

    The central declaration is the only source of truth for source
    pinning: the single-form ``upstream.commit``, or the per-major
    ``upstream.perPostgresql[<major>].commit`` when the declaration is
    in per-major form. The requested major is itself part of the pin
    binding: it must be a positive integer, and it must be one of the
    majors the declaration actually declares in
    ``postgresql.majors`` -- an undeclared major (or a non-integer
    one) must never ride through on the single-form pin. The upstream
    block must be in exactly one of the two forms, and a per-major
    block may not carry pins for majors outside ``postgresql.majors``.
    Anything else is rejected before any repository is touched.
    """
    if not isinstance(declaration, dict):
        raise ValueError("declaration must be a JSON object.")
    if isinstance(pg_major, bool) or not isinstance(pg_major, int) or pg_major < 1:
        raise ValueError(
            f"PostgreSQL major must be a positive integer, got {pg_major!r}."
        )
    postgresql = declaration.get("postgresql")
    if not isinstance(postgresql, dict):
        raise ValueError("declaration has no postgresql block.")
    majors = postgresql.get("majors")
    if (
        not isinstance(majors, list)
        or not majors
        or any(isinstance(m, bool) or not isinstance(m, int) or m < 1 for m in majors)
    ):
        raise ValueError(
            "declaration postgresql.majors must be a nonempty list of positive integers."
        )
    if pg_major not in majors:
        raise ValueError(
            f"PostgreSQL {pg_major} is not declared in postgresql.majors "
            f"{sorted(set(majors))}; the K4 comparison is bound to declared majors only."
        )
    upstream = declaration.get("upstream")
    if not isinstance(upstream, dict):
        raise ValueError("declaration has no upstream block.")
    if "commit" in upstream and "perPostgresql" in upstream:
        raise ValueError(
            "declaration upstream must be in exactly one form: a single "
            "commit or perPostgresql, not both."
        )
    if "perPostgresql" in upstream:
        per_major = upstream["perPostgresql"]
        if not isinstance(per_major, dict):
            raise ValueError("upstream.perPostgresql must be an object.")
        declared = {str(m) for m in majors}
        outside = set(per_major) - declared
        if outside:
            raise ValueError(
                f"upstream.perPostgresql majors {sorted(outside)} are outside "
                "postgresql.majors."
            )
        key = str(pg_major)
        if key not in per_major:
            raise ValueError(f"No upstream pin declared for PostgreSQL {pg_major}.")
        entry = per_major[key]
        commit = entry.get("commit") if isinstance(entry, dict) else None
    else:
        commit = upstream.get("commit")
    if not isinstance(commit, str) or not SHA40_RE.fullmatch(commit):
        raise ValueError(
            f"Declaration does not pin a full upstream commit for PostgreSQL {pg_major}."
        )
    return commit


def _validate_license_entry_shapes(entries):
    """Structurally validate license entries before any Git access.

    Mirrors the field rules of verify_license_entries so a malformed
    entry set fails with the same diagnostics whether the defect is
    structural or a byte mismatch, and no Git command ever runs on an
    unvalidated entry.
    """
    if not isinstance(entries, list) or not entries:
        raise ValueError("License verification requires at least one license entry.")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each license entry must be a JSON object.")
        origin = entry.get("origin")
        repository_path = entry.get("repositoryPath")
        _validate_relative_path(repository_path, "repositoryPath")
        if origin is None:
            unknown = set(entry) - {"repositoryPath", "upstreamPath", "upstreamStartMarker"}
            if unknown:
                raise ValueError(f"Unsupported license entry fields: {', '.join(sorted(unknown))}")
            _validate_relative_path(entry.get("upstreamPath"), "upstreamPath")
            if "upstreamStartMarker" in entry:
                marker = entry["upstreamStartMarker"]
                if not isinstance(marker, str) or not marker:
                    raise ValueError("Expected a nonempty upstream license start marker.")
        elif origin in ("packaging", "build"):
            expected_keys = (
                {"origin", "repositoryPath", "sha256"}
                if origin == "packaging"
                else {"origin", "repositoryPath", "generatedSource", "generatedPath", "sha256"}
            )
            if set(entry) != expected_keys:
                raise ValueError(f"Invalid fields for {origin} license entry '{repository_path}'.")
            expected_sha256 = entry["sha256"]
            if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
                raise ValueError(f"Invalid pinned license sha256 for '{repository_path}'.")
            if origin == "build":
                if entry["generatedSource"] not in GENERATED_SOURCES:
                    raise ValueError(f"Invalid generatedSource for build license '{repository_path}'.")
                _validate_relative_path(entry["generatedPath"], "generatedPath")
        else:
            raise ValueError(f"Unsupported license origin: {origin!r}")


def _git(repo, *args, **kwargs):
    """Run one Git command for the K4 comparison, replace refs disabled.

    A local git replace ref (refs/replace/*) silently substitutes
    one object for another in ordinary Git reads: with a replace ref
    in place, ``cat-file`` returns the replacement's bytes while the
    caller still records the original pinned SHA, so the comparison
    would pass on bytes the pinned commit does not contain
    (SOL-B1-R2-03). Every Git call the K4 path makes therefore runs
    with replace refs disabled twice over -- the
    ``--no-replace-objects`` option and the GIT_NO_REPLACE_OBJECTS
    environment variable -- so the bytes compared are always the
    bytes of the object the recorded SHA names, on both the
    upstream and the packaging side.
    """
    env = dict(os.environ)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args],
        capture_output=True, env=env, **kwargs,
    )


def _git_resolve_head(repo):
    result = _git(repo, "rev-parse", "HEAD", text=True)
    if result.returncode:
        raise ValueError(f"Not a git repository with a HEAD commit: {repo}")
    return result.stdout.strip()


def _git_blob(repo, commit, path, source):
    """Read one file as the blob recorded at ``commit`` of ``repo``.

    Mirrors verify-license-bytes.py: the comparison input is the fixed
    commit's blob, never the worktree file, so untracked files, local
    modifications, CRLF conversion, and symbolic links cannot leak in.
    The commit is always a resolved SHA supplied by the caller, never
    the moving HEAD reference, and the read runs through _git, so a
    local replace ref cannot substitute another object's bytes for
    the pinned one (SOL-B1-R2-03).
    """
    listing = _git(repo, "ls-tree", commit, "--", path, text=True)
    if listing.returncode or not listing.stdout.strip():
        raise ValueError(f"Configured {source} license file was not found at {commit}: {path}")
    mode = listing.stdout.split(None, 1)[0]
    if mode == "120000":
        raise ValueError(f"Configured {source} license file is a symbolic link at {commit}: {path}")
    result = _git(repo, "cat-file", "blob", f"{commit}:{path}")
    if result.returncode:
        raise ValueError(f"Configured {source} license file was not found at {commit}: {path}")
    return result.stdout


def verify_declaration_licenses_from_git(license_block, pg_major, upstream_repo,
                                         packaging_repo, *,
                                         expected_upstream_commit,
                                         expected_packaging_commit):
    """K4 check bound to the declaration pin and the packaging expectation.

    ``expected_upstream_commit`` is the pin selected from the target
    extension's declaration for this major (declared_upstream_commit);
    ``expected_packaging_commit`` is the trusted packaging-side
    expectation supplied by the caller. Entry shapes are validated
    before any Git access. Both repositories are then resolved once
    and must match their expectation (verify_pinned_commit) before a
    single blob is read, and every tree / blob lookup afterwards uses
    the resolved SHA, so a reference that moves during the comparison
    cannot change what was compared, and equal bytes from a different
    major or a different commit are rejected at the entrance.

    Returns the verified document in the verify-license-bytes.py shape
    (schemaVersion / upstreamCommit / packagingCommit / licenses),
    which scripts/windows-package.ps1 consumes directly.
    """
    entries = license_entries_for_major(license_block, pg_major)
    _validate_license_entry_shapes(entries)
    upstream_commit = _git_resolve_head(upstream_repo)
    verify_pinned_commit(expected_upstream_commit, upstream_commit)
    packaging_commit = _git_resolve_head(packaging_repo)
    verify_pinned_commit(expected_packaging_commit, packaging_commit)
    upstream_paths = {
        entry["upstreamPath"] for entry in entries
        if isinstance(entry, dict) and entry.get("origin") is None
    }
    packaging_paths = {
        entry["repositoryPath"] for entry in entries if isinstance(entry, dict)
    }
    upstream = {
        path: _git_blob(upstream_repo, upstream_commit, path, "upstream")
        for path in sorted(upstream_paths)
    }
    packaging = {
        path: _git_blob(packaging_repo, packaging_commit, path, "packaging-repository")
        for path in sorted(packaging_paths)
    }
    verified = verify_license_entries(entries, upstream, packaging)
    return {
        "schemaVersion": 1,
        "upstreamCommit": upstream_commit,
        "packagingCommit": packaging_commit,
        "licenses": verified,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pin = sub.add_parser("pin", help="compare a declared commit with the fetched HEAD")
    pin.add_argument("--declared", required=True)
    pin.add_argument("--actual", required=True)

    digest = sub.add_parser("sha256", help="print the SHA-256 of a file")
    digest.add_argument("path", type=Path)

    licenses = sub.add_parser(
        "verify-licenses",
        help="K4 check bound to the declaration pin, reading fixed commit blobs",
    )
    licenses.add_argument("--declaration-json", type=Path, required=True,
                          help="JSON file holding the central extension declaration")
    licenses.add_argument("--major", type=int, required=True)
    licenses.add_argument("--upstream-dir", type=Path, required=True,
                          help="upstream git repository (must resolve to the declared pin)")
    licenses.add_argument("--packaging-dir", type=Path, required=True,
                          help="packaging git repository (must resolve to --packaging-commit)")
    licenses.add_argument("--packaging-commit", required=True,
                          help="trusted expected commit of the packaging repository")

    args = parser.parse_args(argv)
    try:
        if args.command == "pin":
            verify_pinned_commit(args.declared, args.actual)
            print("PINNED_COMMIT_MATCH")
        elif args.command == "sha256":
            print(sha256_file(args.path))
        elif args.command == "verify-licenses":
            declaration = json.loads(args.declaration_json.read_text(encoding="utf-8"))
            if not isinstance(declaration, dict):
                raise ValueError("declaration JSON must contain a JSON object.")
            expected_upstream_commit = declared_upstream_commit(declaration, args.major)
            license_block = declaration.get("license")
            if not isinstance(license_block, dict):
                raise ValueError("declaration has no license block.")
            document = verify_declaration_licenses_from_git(
                license_block, args.major, args.upstream_dir, args.packaging_dir,
                expected_upstream_commit=expected_upstream_commit,
                expected_packaging_commit=args.packaging_commit,
            )
            print(json.dumps(document, indent=2))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        # One diagnostic shape for every CLI failure: message on stderr,
        # exit 1, no traceback, whatever the defect (missing keys,
        # malformed entries, pin mismatches, byte mismatches).
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
