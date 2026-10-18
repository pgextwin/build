# Issue #75: one historical KB3033929 MSU actual-byte witness (read-only)

This isolated, nonpublishing experiment follows PR #125 and the original
inert Chocolatey inventory in Issue #75 comment 6235378602.

## Exactly one source-bound candidate

Package: `KB3033929` `1.0.3`, pinned original whole `.nupkg`
SHA256 `51d28a163e4c9cfab2ea94c47d7308a88d578e18f6d4e0ac5c8286ee4ae9c91b`.
The executable PowerShell source is never invoked. The original
`Tools/ChocolateyInstall.ps1` bytes must hash to
`88f28af10bb556009d17a42cc42ae7d50f8b83c55d172cb3764e23a6a9420ecb`.

Within that exact source, an adjacent, literal `Url64` /
`Checksum64` text pair selects the historical Windows 6.1 x64 client
`Windows6.1-KB3033929-x64.msu` from `download.microsoft.com`. The
literal expected SHA256 is
`5318587007edb6c8b29310ff18da479a162b486b9101a7de735f94a70dbc3b31`.
The matching filename and SHA256 source pair were observed in the
successful PR #125 Windows log job 117425172069, but that earlier run did
**not** verify actual MSU payload bytes.

## What this PR tests

An exact-name PR-only Windows job retrieves the original Chocolatey nupkg
twice, validates its whole-file SHA256 and safe archive structure, locates
the unique script and validates its SHA256 and a precise lexical pair. It
then retrieves **only the named historical Microsoft MSU** twice over HTTPS
from a narrowly approved Microsoft domain set, rejecting off-domain or
insecure redirects. Each response is bounded at 120,000,000 bytes;
independent bytes, CAB magic, size and exact SHA256 must all match.
Nothing downloaded is executed, installed, staged as an Artifact or published.

The required resolver also runs offline hostile cases for forged packages,
malformed and repeated checksum pairs, wrong URLs, byte corruption, size
caps, redirect policy and double-GET disagreement.

The result is at most `ONE_HISTORICAL_MSU_REAL_BYTES_SOURCE_ONLY`.
A source-level adjacency match does **not** prove the dynamic Windows
version branch was reached or that current hosted runners use that MSU.
Other OS/arch URLs and KBs, full runner/VS/MSVC/Action runtime byte
closure, Signer/Writer genuine credential isolation, signed Publisher
positive prewrite and schema-v2 recovery stay NOT_PROVEN. All such gaps
remain UNKNOWN/DENY.

No branch protection, signed Publisher/Signer pins, credentials, Secrets,
release tag, GitHub budget, promotion workflow or existing Release
is changed. Formal P1 stays 65/70, independent source 40/40,
plpgsql_check PG14–18 five historical DENY, GO B/G4/G5 NO-GO,
P1 BLOCKED/P2 NO-GO and formal release/distribution DENY.
