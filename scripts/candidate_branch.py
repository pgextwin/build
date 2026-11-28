"""Naming contract for immutable candidate branches."""

from dataclasses import dataclass
import re


EXTENSION_RE = re.compile(r"[a-z][a-z0-9_]*")
CANDIDATE_ID_RE = re.compile(r"[0-9a-f]{20}")
WINDOWS_RESERVED_RE = re.compile(r"con|prn|aux|nul|com[0-9]|lpt[0-9]")
CENTRAL_BRANCH_RE = re.compile(r"^auto-candidate/(?P<extension>[a-z][a-z0-9_]*)/(?P<candidate_id>[0-9a-f]{20})\Z")
LEGACY_BRANCH_RE = re.compile(r"^auto-candidate/(?P<candidate_id>[0-9a-f]{20})\Z")
CENTRAL_REPOSITORY = "pgextwin/build"


@dataclass(frozen=True)
class ParsedCandidateBranch:
    style: str
    extension: str | None
    candidate_id: str
    branch: str


def validate_extension_name(name):
    if (not isinstance(name, str) or len(name) > 64
            or not EXTENSION_RE.fullmatch(name) or WINDOWS_RESERVED_RE.fullmatch(name)):
        raise ValueError("invalid candidate extension name")


def format_branch(extension, candidate_id, style):
    validate_extension_name(extension)
    if not isinstance(candidate_id, str) or not CANDIDATE_ID_RE.fullmatch(candidate_id):
        raise ValueError("invalid candidate ID")
    if style == "central":
        return f"auto-candidate/{extension}/{candidate_id}"
    if style == "legacy":
        return f"auto-candidate/{candidate_id}"
    raise ValueError("invalid candidate branch style")


def parse_branch(branch, *, expected_extension=None, allow_legacy=True, allow_central=True):
    if expected_extension is not None:
        validate_extension_name(expected_extension)
    if isinstance(branch, str):
        central = CENTRAL_BRANCH_RE.fullmatch(branch) if allow_central else None
        if central:
            extension = central["extension"]
            validate_extension_name(extension)
            if expected_extension is not None and extension != expected_extension:
                raise ValueError("candidate branch belongs to a different extension")
            return ParsedCandidateBranch("central", extension, central["candidate_id"], branch)
        legacy = LEGACY_BRANCH_RE.fullmatch(branch) if allow_legacy else None
        if legacy:
            return ParsedCandidateBranch("legacy", None, legacy["candidate_id"], branch)
    raise ValueError("invalid candidate branch")


def branch_style_for_repository(repository, extension):
    validate_extension_name(extension)
    if repository == CENTRAL_REPOSITORY:
        return "central"
    if repository == f"pgextwin/{extension}":
        return "legacy"
    raise ValueError("candidate repository does not match its extension")
