# Issue #75 — Inert EDB installer source evidence / Python offline wheel lock

**Scope: nonpublishing, no execution of untrusted PowerShell, installers or downloaded Python wheels.** Old Signer `5756b3c5136a8bf4db710016cfe97555f0a71c6d`, Publisher `455f0ccc667697f600700a6e64bcfd6c57b6a977`, `promote.yml`, PR #29, Secrets, budgets, branch protection, publication workflows and all prior source evidence unchanged.

## Chocolatey PG14–18 -> EDB x64 EXE

The [inert analyzer](../scripts/issue-75-choco-edb-nonexec.py) fetches each of the five existing nupkg sources from `https://community.chocolatey.org/api/v2/package/<name>/<version>`, compares *complete archive* SHA256 and size with immutable [original actual Run evidence](../evidence/issue-75/external-public-byte-observed-39034789275.json), and extracts `tools/chocolateyInstall.ps1` as **untrusted text only**. It does not invoke PowerShell or Chocolatey. It requires exactly one install script and simple literal `url64`, `checksum64`, `checksumType64='sha256'`, `fileType='exe'`; the static URL must match that package's PostgreSQL major/minor and `https://get.enterprisedb.com/postgresql/postgresql-<major>.<minor>-<build>-windows-x64.exe`. Untrusted dynamic URL or checksum declarations cause refusal.

It also lists directly declared nuspec `dependency` entries. The parser is **not a full PowerShell interpreter** and cannot prove there is no second download or opaque side effect; `unreviewedPowerShellBehavior=true` remains. A bounded PG14 installer *candidate* GET is attempted on an independent, read-only Windows PR job, with 420 MB maximum stream and limited redirects; if unavailable/outside budget the result is `UNAVAILABLE_OR_BOUNDED`, not a SHA256 verified claim. If bytes are retrieved, SHA256 **must** match the checksum extracted from the nupkg or the job must fail. No EXE is executed or persisted to an Artifact. Other EDB versions remain `installerBytesSHA256Verified=false` until individually acquired.

## Real EXE GET verification completed, then safely frozen

Two **independent successful** PR Runs provided original Windows job logs:

- [PG14 byte canary Run 39038000517](https://github.com/pgextwin/build/actions/runs/39038000517), head `18826c6c6938df9323b8f0086b4fef6a044357bb`, job 117411610495: **360,966,784 bytes**, SHA256 `52a51ec49c38a68a9f93f677b23e975ba709354ddab8283ef2558f3e7cb7f998`, MATCH.
- [PG15–18 bounded byte Run 39038162434](https://github.com/pgextwin/build/actions/runs/39038162434), head `0a6649933e4ad313d3f0ce7cc84510a7a5e1a04e`, job 117412082965: PG15 **362,808,024**, PG16 **404,741,880**, PG17 **410,984,080**, PG18 **414,966,472** bytes; all four real SHA256 equal nupkg `checksum64`. Their exact computed SHA256 values are in the [five-EXE machine-readable receipt](../evidence/issue-75/edb-pg14-18-exe-byte-observations-20261017.json).

Combined real retrieved EXE bytes = **1,954,467,240**, all five matching, no installer execution. The receipt's **entire content** is pinned to immutable Git Blob `cd820757fde0ae7fdd7d0e728b7076ef7d1dff10`; the offline validator rejects any drift in actual bytes, exact Run/attempt/head/job, nupkg script observation or unauthorized publication/Signer claims. The former [first PG14 evidence](../evidence/issue-75/edb-source-canary-39037699548.json) remains preserved but was from a PR Run whose *parent Run* failed unrelated CI; it is **not counted** as an accepted full Run. The two references above are successful Runs.

**Resource-conscious retry:** after proving all five in successful jobs, the PR-only EDB job was changed to `--mode inspect`; it re-downloads only the tiny five nupkg archives and matches *their* checksum/script declarations with the byte-frozen receipt. It does not download another 1.95GB of EXEs on every commit. A successful lightweight replay counts as source-consistency validation, **not** a fresh EXE-byte SHA256 check.

Even with 5/5 verified EXE bytes, the Chocolatey nuspec transitive dependencies (`chocolatey-core.extension` and `vcredist140`), installers' own bundled or post-install dependencies, runtime install output and any genuine Signer/Publisher token or signed output remain unverified. No GO B/G4/G5 acceptance upgrade.

## Frozen wheel lock candidate

[Eight-package candidate](../evidence/issue-75/python-wheel-lock-candidate-20261017.json) freezes versions and per-platform wheel filename and SHA256 from previous successful PR Run 39034789275. [Offline lock generator](../scripts/issue-75-wheel-lock-candidate.py) refuses any mismatch against that unchanged entire receipt's Git Blob ID, missing/extra dependency, wrong wheel filename/hash or false acceptance. It emits `--only-binary=:all:` pip requirements with `--hash=sha256` for each package on **each** target (CPython 3.13 x64 Linux/Windows). On independent PR-only jobs, `pip --isolated download --no-deps --only-binary=:all: --require-hashes` retrieves exactly eight wheels into an ephemeral local wheelhouse and verifies actual bytes; then `pip --isolated download --no-index --find-links <local wheelhouse> --require-hashes` proves an offline **download-only** roundtrip. Absolutely no `pip install`, package scripts, Signer or Release.

The candidate does **not** modify active Signer pip invocations. Neither its chosen `jsonschema 4.26.0` nor other dependencies is known to be the precise wheel selected during old signed Publisher runs. Their future installation/use needs an independently reviewed workflow pin migration and live signed provenance evidence.

## Gate and negatives

[Hostile offline tests](../tests/test-issue-75-edb-wheel-lock.py) run under existing required `resolver` App15368, with two independent PR-only jobs `issue75_choco_script_probe` and `issue75_wheel_lock_probe` (Windows and Ubuntu matrix). Jobs have `contents:read`, `persist-credentials:false`, no secrets or persistent Artifacts, no GitHub write scopes and no user-prompted dispatch.

Preserve P1 formal **65/70**, independent source **40/40**, historic plpgsql_check PG14–18 **five DENY**, P1 BLOCKED/P2 NO-GO, GO B/G4/G5 NO-GO, formal Release/distribution DENY. No test success in this PR proves genuine Writer identity isolation, live signed Publisher positive prewrite, all MSVC/Runner/Node/Chocolatey transitive installed executable bytes, or a publishable receipt.
