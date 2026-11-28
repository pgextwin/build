#!/usr/bin/env python3
"""Convert legacy per-repository declarations to the central monorepo form
and validate ``extensions/<name>/`` trees against the F1 layout rules.

Legacy form (measured by U-01, all 26 extension repositories):
  * ``config/extension.json``  -- 7 keys: schemaVersion / name / upstream /
    postgresql / windows / license / watch
  * ``windows/ci/package.json`` -- distribution, files[], packageInfo[]

Central form (F1 DESIGN chapter 1):
  * ``extensions/<name>/extension.json`` validated by
    ``schema/central-extension.schema.json``. The two legacy layers are
    merged, ``postgresql`` is normalized to the ``majors`` array form, the
    ``adapter`` designation and declared build options are added, and the
    upstream block stays the single source of truth for source pinning
    (no duplicate ``source-lock.json`` is created).

The tree validator rejects the N-01..N-18 non-carry-in asset classes,
empty directories / files, and any signing / Publisher / authorization
material inside the adapter area (DESIGN 1.3 permission boundary).
"""

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "central-extension.schema.json"

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\Z")
SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}\Z")

BUILD_OPTION_KEYS = ("exports", "defines", "dependencies", "components")
# sqlInstallPath is deliberately not a scalar: the windows-package.ps1
# contract requires an ordered array of at least two SQL versions.
PACKAGING_SCALAR_KEYS = (
    "packageInfoFinalNewline",
    "sqlVersion",
    "sqlExtensionName",
)

# Files and directories allowed directly under extensions/<name>/ (DESIGN 1.2).
ALLOWED_FILES = {"extension.json", "adapter.ps1", "README.md"}
ALLOWED_DIRS = {"patches", "tests", "packaging", "licenses"}

# Non-carry-in asset classes (DESIGN 1.5, N-01..N-18). Each entry maps a
# predicate on the extension-relative POSIX path to the class id used in
# rejection messages. The first matching rule wins.
def _basename(path):
    return path.rsplit("/", 1)[-1]


def _carry_in_class(rel):
    base = _basename(rel)
    lower = base.lower()
    if lower == "source-lock.json":
        return "SOURCE-LOCK"
    if lower == "update-watch.yml" or lower == "update-watch.json":
        return "N-04"
    if lower.startswith("issue"):
        return "N-11" if lower.endswith((".yml", ".yaml")) else "N-12"
    if lower == "windows.yml" or lower.endswith(".yml") or lower.endswith(".yaml"):
        return "N-01"
    if lower == "build.ps1":
        return "N-02"
    if lower.startswith("install-postgresql") or lower.startswith("download-"):
        return "N-03"
    if lower.startswith("candidate-") or lower.startswith("create-candidate"):
        return "N-05"
    if lower in ("package.ps1", "make-package.ps1") or (
        lower.startswith("package-") and lower.endswith(".ps1")
    ):
        return "N-06"
    if lower.startswith("generate-sbom") or lower.startswith("sbom") or lower.startswith("sha256"):
        return "N-07"
    if lower.startswith("run-tests") or (lower.startswith("test-") and "/" not in rel):
        return "N-08"
    if lower.startswith("sign-") or lower.startswith("publish-") or lower.startswith("publisher"):
        return "N-09"
    if lower in ("versions.json", "pg-versions.json", "postgresql.json"):
        return "N-10"
    if "migration" in lower or lower.startswith("legacy-"):
        return "N-13"
    if "wrapper" in lower or lower.startswith("compat-"):
        return "N-14"
    parts = PurePosixPath(rel).parts
    # Path components are compared case-insensitively: the target
    # platform is Windows, where Source/ and source/ (or BIN/ and bin/)
    # are the same directory and must receive the same classification.
    folded = tuple(part.casefold() for part in parts)
    if any(part in ("source", "src", "upstream", "upstream-src") for part in folded):
        return "N-16"
    if "__pycache__" in folded or any(part in ("bin", "obj") for part in folded) or lower.endswith((".pyc", ".tmp", ".temp")):
        return "N-17"
    # The README exception is limited to the extension root README.md;
    # a Markdown document at any deeper level is a non-carry-in
    # operational document (N-18).
    if lower.endswith(".md") and rel != "README.md":
        return "N-18"
    return None


# Adapter privilege boundary (DESIGN 1.3): the adapter area must not carry
# signing, Publisher, authorization, or credential material.
ADAPTER_FORBIDDEN = (
    ("signing", re.compile(r"attestation|actions/attest|sigstore|cosign|id-token|oidc", re.IGNORECASE)),
    ("publisher", re.compile(r"\bpublisher\b|fleet-publish-release|publisher-candidate-intake|gh\s+(?:release|api|workflow)\b", re.IGNORECASE)),
    ("authorization", re.compile(r"local-auth|admission|local-candidate-authority", re.IGNORECASE)),
    ("credentials", re.compile(r"GITHUB_TOKEN|GH_TOKEN|secrets\.|ACTIONS_ID_TOKEN_REQUEST(?:_TOKEN|_URL)?|ACTIONS_RUNTIME(?:_TOKEN|_URL)?|PRIVATE_KEY|INSTALLATION_TOKEN", re.IGNORECASE)),
)


def load_validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def normalize_majors(postgresql):
    """Normalize the legacy postgresql block to the sorted majors array."""
    if not isinstance(postgresql, dict):
        raise ValueError("postgresql must be an object.")
    has_majors = "majors" in postgresql
    has_range = "minMajor" in postgresql or "maxMajor" in postgresql
    if has_majors and has_range:
        raise ValueError("postgresql must not declare both majors and minMajor/maxMajor.")
    if has_majors:
        majors = postgresql["majors"]
        if not isinstance(majors, list):
            raise ValueError("postgresql majors must be a list.")
    elif "minMajor" in postgresql and "maxMajor" in postgresql:
        low, high = postgresql["minMajor"], postgresql["maxMajor"]
        if (
            isinstance(low, bool) or isinstance(high, bool)
            or not isinstance(low, int) or not isinstance(high, int) or low > high
        ):
            raise ValueError("postgresql minMajor/maxMajor are invalid.")
        majors = list(range(low, high + 1))
    else:
        raise ValueError("postgresql must declare majors or minMajor/maxMajor.")
    if not majors or any(isinstance(m, bool) or not isinstance(m, int) or m < 1 for m in majors):
        raise ValueError("postgresql majors must be positive integers.")
    return sorted(set(majors))


def convert_declaration(legacy_extension, legacy_package, *, adapter=False, build_options=None):
    """Merge the two legacy declaration layers into the central form."""
    if not isinstance(legacy_extension, dict) or not isinstance(legacy_package, dict):
        raise ValueError("Legacy declarations must be JSON objects.")
    name = legacy_extension.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("Legacy extension declaration has no valid name.")

    central = {"schemaVersion": 1, "name": name}
    central["upstream"] = json.loads(json.dumps(legacy_extension["upstream"]))
    central["postgresql"] = {"majors": normalize_majors(legacy_extension["postgresql"])}
    central["windows"] = json.loads(json.dumps(legacy_extension["windows"]))

    build = {"distribution": legacy_package["distribution"]}
    if build_options is not None:
        unknown = set(build_options) - set(BUILD_OPTION_KEYS)
        if unknown:
            raise ValueError(f"Unsupported build option keys: {', '.join(sorted(unknown))}")
        options = {}
        for key in BUILD_OPTION_KEYS:
            if key in build_options:
                values = build_options[key]
                if not isinstance(values, list) or any(
                    not isinstance(v, str) or not v for v in values
                ):
                    raise ValueError(f"Build option '{key}' must be a list of nonempty strings.")
                options[key] = list(values)
        if options:
            build["options"] = options
    central["build"] = build

    if adapter:
        central["adapter"] = {"path": "adapter.ps1"}

    packaging = {
        "files": json.loads(json.dumps(legacy_package["files"])),
        "packageInfo": json.loads(json.dumps(legacy_package["packageInfo"])),
    }
    for key in PACKAGING_SCALAR_KEYS:
        if key in legacy_package:
            packaging[key] = legacy_package[key]
    if "sqlInstallPath" in legacy_package:
        # Array contract (windows-package.ps1); deep-copy like the other
        # structured packaging values.
        packaging["sqlInstallPath"] = json.loads(json.dumps(legacy_package["sqlInstallPath"]))
    if "perPostgresql" in legacy_package:
        packaging["perPostgresql"] = json.loads(json.dumps(legacy_package["perPostgresql"]))
    central["packaging"] = packaging

    # Extension-specific tests live under tests/ in the central layout; the
    # legacy locations are config/test-contract.json and
    # windows/ci/smoke-test.ps1 (U-01).
    central["tests"] = {
        "contract": "tests/test-contract.json",
        "smokeTest": "tests/smoke-test.ps1",
    }
    central["license"] = json.loads(json.dumps(legacy_extension["license"]))
    if "watch" in legacy_extension:
        central["watch"] = json.loads(json.dumps(legacy_extension["watch"]))
    return central


def validate_declaration(declaration, expected_name=None, validator=None):
    """Return a list of validation errors for one central declaration."""
    errors = []
    if not isinstance(declaration, dict):
        return ["declaration is not a JSON object"]
    validator = validator or load_validator()
    for error in sorted(validator.iter_errors(declaration), key=lambda e: list(e.path)):
        location = ".".join(str(p) for p in error.path) or "<root>"
        errors.append(f"schema: {location}: {error.message}")
    if errors:
        return errors

    name = declaration["name"]
    if expected_name is not None and name != expected_name:
        errors.append(f"name '{name}' does not match directory '{expected_name}'.")

    schema_version = declaration["schemaVersion"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        # JSON Schema's "const" treats 1.0 as equal to 1; the strict
        # integer rule (shared with the handoff records in
        # central-package.py) rejects the decimal notation.
        errors.append(
            "schemaVersion must be the integer 1; decimal notation is not accepted."
        )
        return errors

    majors = declaration["postgresql"]["majors"]
    if any(isinstance(m, bool) or not isinstance(m, int) for m in majors):
        # JSON Schema's "integer" also accepts the decimal notation
        # (17.0); the conversion path (normalize_majors) rejects it, so
        # direct validation rejects it too and both entry points share
        # the str(int) key representation for per-major dictionaries.
        errors.append(
            "postgresql.majors must be integers; decimal notation is not accepted."
        )
        return errors
    if majors != sorted(set(majors)):
        errors.append("postgresql.majors must be sorted ascending without duplicates.")

    major_set = {str(m) for m in majors}
    upstream = declaration["upstream"]
    if "perPostgresql" in upstream:
        extra = set(upstream["perPostgresql"]) - major_set
        if extra:
            errors.append(
                f"upstream.perPostgresql majors {sorted(extra)} are outside postgresql.majors."
            )
        missing = major_set - set(upstream["perPostgresql"])
        if missing:
            errors.append(
                f"upstream.perPostgresql majors {sorted(missing)} are declared in "
                "postgresql.majors but have no pinned upstream."
            )
        missing_commit = [
            m for m, entry in upstream["perPostgresql"].items()
            if not SHA40_RE.fullmatch(entry.get("commit", ""))
        ]
        if missing_commit:
            errors.append(
                f"upstream.perPostgresql majors {sorted(missing_commit)} lack a pinned commit."
            )
    license_block = declaration["license"]
    if "perPostgresql" in license_block:
        extra = set(license_block["perPostgresql"]) - major_set
        if extra:
            errors.append(
                f"license.perPostgresql majors {sorted(extra)} are outside postgresql.majors."
            )
        missing = major_set - set(license_block["perPostgresql"])
        if missing:
            errors.append(
                f"license.perPostgresql majors {sorted(missing)} are declared in "
                "postgresql.majors but have no license entries."
            )
    packaging = declaration["packaging"]
    if "perPostgresql" in packaging:
        extra = set(packaging["perPostgresql"]) - major_set
        if extra:
            errors.append(
                f"packaging.perPostgresql majors {sorted(extra)} are outside postgresql.majors."
            )
    return errors


def decode_powershell_script(data):
    """Decode a PowerShell script exactly as the PowerShell host does.

    The host (Windows PowerShell 5.1 and PowerShell 7 alike) selects
    the script encoding from its byte-order mark -- UTF-8, UTF-16
    LE/BE, or UTF-32 LE/BE when a BOM is present -- and reads BOM-less
    files as UTF-8 (PowerShell 7). The static scan and the N-15
    substance judgement use this one decoding, so the inspected text
    is the executed text: a UTF-16 (BOM) script can no longer slip
    Publisher / credential material past the scan as
    replacement-decoded garbage, and a BOM cannot make a
    comment-only script look substantive (SOL-B1-R2-02). The common
    execution entry in central-package.py enforces the same contract
    before anything runs.

    BOM-less bytes that are not valid UTF-8 are outside the
    contract: Windows PowerShell 5.1 would read them as the legacy
    ANSI code page while PowerShell 7 reads UTF-8, so no single
    inspected text corresponds to the executed text. They raise
    ValueError here and are refused at the execution entry too.
    """
    try:
        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            return data.decode("utf-32")
        if data.startswith(b"\xef\xbb\xbf"):
            return data.decode("utf-8-sig")
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            "script encoding is outside the supported contract "
            "(UTF-8, or UTF-16/UTF-32 with a byte-order mark): "
            f"{error}"
        ) from None


def _scan_adapter_text(text, rel, errors):
    for category, pattern in ADAPTER_FORBIDDEN:
        match = pattern.search(text)
        if match:
            errors.append(
                f"{rel}: adapter area contains {category} material ('{match.group(0)}'); "
                "the adapter must not carry signing, Publisher, authorization, or credential code (DESIGN 1.3)."
            )


# Executable script suffixes (compared case-insensitively). PowerShell is
# executable on Windows regardless of suffix case, so packaging/build.PS1
# must be rejected exactly like packaging/build.ps1.
EXECUTABLE_SUFFIXES = (".ps1", ".psm1", ".py", ".sh", ".bat", ".cmd")
SCRIPT_SUFFIXES = (".ps1", ".psm1")


def _powershell_effectively_empty(text):
    """True when a PowerShell script holds only blanks and comments (N-15).

    Both line comments (# ...) and block comments (<# ... #>, possibly
    spanning lines) are stripped before judging substance.
    """
    without_blocks = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    for line in without_blocks.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return False
    return True


def _readme_effectively_empty(text):
    """True when a README holds only headings / blanks / HTML comments.

    Inspection scope for content-judged assets (N-15): adapter and test
    scripts are judged after PowerShell comment stripping, JSON test
    assets after parsing (an empty object / array / string counts as
    empty), and the root README after removing heading-only lines and
    HTML comments.
    """
    without_comments = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    for line in without_comments.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return False
    return True


def _json_effectively_empty(data):
    """True when bytes parse as JSON with no content ({} / [] / "" / null)."""
    try:
        value = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False
    if isinstance(value, (dict, list, str)):
        return len(value) == 0
    return value is None


# Sentinel for "extension.json was not (successfully) parsed". A parsed
# JSON null is a declaration value like any other and must go through
# validation; it must never be confused with the pre-parse state.
_UNSET = object()


def validate_extension_dir(ext_dir, validator=None):
    """Validate one extensions/<name>/ directory. Returns error strings.

    Every file and directory is checked recursively: the N-01..N-18
    non-carry-in classification and the source-lock.json ban apply at any
    depth (including inside the allowed patches/ tests/ packaging/
    licenses/ directories), symbolic links are rejected outright
    (including at the tree root and at each extension root, so the
    inspected tree is the tree that lands in the protected commit), and
    every executable script in the adapter area (adapter.ps1 and tests/
    scripts of any suffix) is statically scanned for privilege-boundary
    violations, so the executable set stays a subset of the statically
    scanned set. The layout itself is canonical: allowed directory
    names must match the standard lowercase form exactly (a Tests/ or
    Packaging/ directory is not the standard layout, and two paths
    that differ only in case would collide on a Windows checkout, so
    both are rejected). The rejection-side classifications (N-16 /
    N-17 path components, source-lock.json, executable suffixes) stay
    case-insensitive, because on Windows those names are the same
    asset whatever their case.
    """
    errors = []
    name = ext_dir.name
    if not NAME_RE.fullmatch(name):
        errors.append(f"extensions/{name}: invalid extension directory name.")
        return errors
    if ext_dir.is_symlink():
        errors.append(
            f"extensions/{name}: the extension root must not be a symbolic "
            "link; the inspected tree must be the tree that lands in the "
            "protected commit."
        )
        return errors

    declaration = _UNSET
    seen_adapter = False
    seen_folded = {}
    for path in sorted(ext_dir.rglob("*")):
        rel = path.relative_to(ext_dir).as_posix()
        if path.is_symlink():
            errors.append(
                f"extensions/{name}/{rel}: symbolic links are not allowed "
                "inside an extension directory."
            )
            continue
        folded_rel = rel.casefold()
        if folded_rel in seen_folded and seen_folded[folded_rel] != rel:
            errors.append(
                f"extensions/{name}/{rel}: path collides with "
                f"'{seen_folded[folded_rel]}' on a case-insensitive "
                "filesystem (Windows checkout would overwrite one of them)."
            )
        else:
            seen_folded[folded_rel] = rel
        if path.is_dir():
            if not any(path.iterdir()):
                errors.append(f"extensions/{name}/{rel}: empty directory is not allowed (N-15).")
            top = rel.split("/", 1)[0]
            if "/" not in rel and top not in ALLOWED_DIRS:
                cls = _carry_in_class(rel)
                label = f" ({cls})" if cls else ""
                errors.append(
                    f"extensions/{name}/{rel}: directory is not part of the standard layout{label}."
                )
            else:
                cls = _carry_in_class(rel)
                if cls:
                    errors.append(
                        f"extensions/{name}/{rel}: directory matches a non-carry-in class ({cls})."
                    )
            continue
        try:
            data = path.read_bytes()
        except OSError as error:
            errors.append(f"extensions/{name}/{rel}: cannot read file: {error}")
            continue
        if not data.strip():
            errors.append(
                f"extensions/{name}/{rel}: empty or whitespace-only file is not allowed (N-15)."
            )
            continue
        if _basename(rel).lower() == "source-lock.json":
            errors.append(
                f"extensions/{name}/{rel}: source-lock.json duplicates the upstream "
                "block of extension.json and must not be created."
            )
            continue
        cls = _carry_in_class(rel)
        if cls:
            errors.append(
                f"extensions/{name}/{rel}: non-carry-in asset ({cls})."
            )
            continue
        top = rel.split("/", 1)[0]
        # Layout membership is strict canonical lowercase: Tests/ is
        # not tests/ in the standard layout (and the pair would
        # collide on a Windows checkout; the collision itself is
        # rejected above). This matches the execution side, where
        # adapter_script_kind also requires the literal "tests".
        suffix = path.suffix.lower()
        if "/" not in rel:
            if rel not in ALLOWED_FILES:
                errors.append(
                    f"extensions/{name}/{rel}: file is not part of the standard layout."
                )
                continue
        else:
            if top not in ALLOWED_DIRS:
                errors.append(
                    f"extensions/{name}/{rel}: path is outside the standard layout."
                )
                continue
            if top == "patches" and suffix not in (".patch", ".diff"):
                errors.append(
                    f"extensions/{name}/{rel}: patches/ may contain only .patch/.diff files."
                )
            if top in ("packaging", "licenses") and suffix in EXECUTABLE_SUFFIXES:
                errors.append(
                    f"extensions/{name}/{rel}: executable scripts must not be placed under {top}/."
                )
            if suffix in SCRIPT_SUFFIXES and top != "tests":
                errors.append(
                    f"extensions/{name}/{rel}: PowerShell code is allowed only as adapter.ps1 or under tests/."
                )
        if rel == "adapter.ps1":
            seen_adapter = True
        if rel == "adapter.ps1" or (top == "tests" and suffix in EXECUTABLE_SUFFIXES):
            # Every executable script in the adapter area is statically
            # scanned, whatever its suffix; the executable set is a
            # subset of this scanned set (DESIGN 1.3). PowerShell
            # scripts are decoded under the shared encoding contract
            # (decode_powershell_script) and that single decoding
            # feeds both the N-15 substance judgement and the
            # privilege scan, so the inspected text is the text the
            # PowerShell host executes (SOL-B1-R2-02). Other
            # executable suffixes are never run by the PowerShell
            # host; they are scanned as UTF-8 text with replacement.
            if suffix in SCRIPT_SUFFIXES:
                try:
                    text = decode_powershell_script(data)
                except ValueError as error:
                    errors.append(f"extensions/{name}/{rel}: {error}")
                    text = None
            else:
                text = data.decode("utf-8", errors="replace")
            if text is not None:
                if suffix in SCRIPT_SUFFIXES and _powershell_effectively_empty(text):
                    label = "adapter.ps1" if rel == "adapter.ps1" else "test script"
                    errors.append(
                        f"extensions/{name}/{rel}: {label} holds only comments or "
                        "blank lines and is not a substantive asset (N-15)."
                    )
                _scan_adapter_text(text, f"extensions/{name}/{rel}", errors)
        if top == "tests" and suffix == ".json" and _json_effectively_empty(data):
            errors.append(
                f"extensions/{name}/{rel}: test asset parses as empty JSON and "
                "carries no test content (N-15)."
            )
        if rel == "README.md":
            # utf-8-sig: a leading byte-order mark is not substance.
            text = data.decode("utf-8-sig", errors="replace")
            if _readme_effectively_empty(text):
                errors.append(
                    f"extensions/{name}/{rel}: README.md holds only headings or "
                    "comments and is not a substantive asset (N-15)."
                )
        if rel == "extension.json":
            try:
                declaration = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                errors.append(f"extensions/{name}/extension.json: cannot parse: {error}")

    decl_path = ext_dir / "extension.json"
    if not decl_path.is_file():
        errors.append(f"extensions/{name}: extension.json is required.")
        return errors
    if declaration is _UNSET:
        # Unparseable (the parse error is already recorded) or the file
        # was rejected above as a symbolic link.
        return errors
    if not isinstance(declaration, dict):
        # A parsed JSON null / array / scalar is a declaration failure,
        # never a pass: every parsed value goes through the object,
        # required-field, and name checks before the tree can validate.
        for error in validate_declaration(declaration, expected_name=name, validator=validator):
            errors.append(f"extensions/{name}/extension.json: {error}")
        return errors

    declaration_errors = validate_declaration(
        declaration, expected_name=name, validator=validator
    )
    for error in declaration_errors:
        errors.append(f"extensions/{name}/extension.json: {error}")

    declared_adapter = "adapter" in declaration
    if declared_adapter and not seen_adapter:
        errors.append(
            f"extensions/{name}: declaration specifies an adapter but adapter.ps1 is missing."
        )
    if seen_adapter and not declared_adapter:
        errors.append(
            f"extensions/{name}: adapter.ps1 exists but the declaration does not specify it."
        )

    # The declared-test-file check dereferences the tests block, so
    # it runs only for a declaration that itself validated: after a
    # schema failure the block may be null or otherwise malformed
    # (tests: null), and following the reference anyway turned a
    # controlled rejection into a CLI traceback (SOL-B1-R2-N2).
    if not declaration_errors:
        tests_block = declaration.get("tests")
        if isinstance(tests_block, dict):
            for key in ("contract", "smokeTest"):
                target_name = tests_block.get(key)
                if isinstance(target_name, str):
                    target = ext_dir / target_name
                    if not target.is_file():
                        errors.append(
                            f"extensions/{name}: declared tests.{key} file "
                            f"'{target_name}' is missing."
                        )
    return errors


def validate_tree(root):
    """Validate <root>/extensions/**. Returns a list of error strings."""
    root = Path(root)
    extensions_root = root / "extensions"
    if extensions_root.is_symlink():
        return [
            f"{extensions_root}: the extensions root must not be a symbolic "
            "link; the inspected tree must be the tree that lands in the "
            "protected commit."
        ]
    if not extensions_root.is_dir():
        return [f"{extensions_root}: extensions directory not found."]
    errors = []
    validator = load_validator()
    entries = sorted(extensions_root.iterdir())
    if not entries:
        errors.append("extensions/: no extension directories found.")
    # Extension roots are siblings in one directory: on a Windows
    # checkout two roots whose names differ only in case are the
    # same directory, so the tree cannot hold both. The collision
    # record inside validate_extension_dir is rebuilt per extension
    # and cannot see across roots; uniqueness is enforced here, at
    # the level of the whole extensions/ directory (SOL-B1-R2-01).
    seen_root_names = {}
    for entry in entries:
        folded = entry.name.casefold()
        if folded in seen_root_names and seen_root_names[folded] != entry.name:
            errors.append(
                f"extensions/{entry.name}: extension directory name collides "
                f"with '{seen_root_names[folded]}' on a case-insensitive "
                "filesystem (a Windows checkout cannot hold both extension roots)."
            )
        else:
            seen_root_names[folded] = entry.name
    for entry in entries:
        if entry.is_symlink():
            errors.append(
                f"extensions/{entry.name}: symbolic link extension roots are not allowed."
            )
            continue
        if not entry.is_dir():
            errors.append(f"extensions/{entry.name}: only extension directories are allowed here.")
            continue
        errors.extend(validate_extension_dir(entry, validator=validator))
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    validate_parser = sub.add_parser("validate", help="validate an extensions/ tree")
    validate_parser.add_argument("--root", type=Path, required=True)

    convert_parser = sub.add_parser("convert", help="convert legacy declarations")
    convert_parser.add_argument("--extension-json", type=Path, required=True)
    convert_parser.add_argument("--package-json", type=Path, required=True)
    convert_parser.add_argument("--adapter", action="store_true")
    convert_parser.add_argument("--build-options", type=Path)
    convert_parser.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "validate":
        errors = validate_tree(args.root)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print("CENTRAL_EXTENSION_LAYOUT_OK")
        return 0

    legacy_extension = json.loads(args.extension_json.read_text(encoding="utf-8"))
    legacy_package = json.loads(args.package_json.read_text(encoding="utf-8"))
    build_options = None
    if args.build_options:
        build_options = json.loads(args.build_options.read_text(encoding="utf-8"))
    try:
        central = convert_declaration(
            legacy_extension, legacy_package,
            adapter=args.adapter, build_options=build_options,
        )
    except (KeyError, TypeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    errors = validate_declaration(central, expected_name=central["name"])
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    args.out.write_text(json.dumps(central, indent=2) + "\n", encoding="utf-8")
    print(f"CENTRAL_DECLARATION_CONVERTED name={central['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
