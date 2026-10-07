# Update detection automation

Step 13 adds notification-only automation for upstream extension releases and PostgreSQL release/lifecycle changes. It deliberately stops at GitHub Issues: it never changes a pinned upstream ref, creates a branch or pull request, builds an unknown candidate, publishes a Release, modifies Catalog/Website metadata, or onboards a new PostgreSQL major.

## Architecture

Extension flow:

```text
config/extension.json + config/update-watch.json
        |
        v
scheduled/manual caller (extension repository)
        |
        v
full-SHA-pinned pgextwin/build reusable workflow
        |
        +--> canonical update-watch validation
        +--> GitHub Releases/tags metadata only
        |
        v
stable candidate detector
        |
        v
machine-readable result
        |
        v
marker-scoped Issue reconciler
        |
        +--> create / update / close / no-op
        `--> dry-run: summary only
```

PostgreSQL flow:

```text
metadata/postgresql.json
        + PostgreSQL official Versioning Policy
        + PostgreSQL official Beta Information
        |
        v
scheduled/manual pgextwin/build workflow
        |
        v
minor / EOL / supported-major detector
        |
        v
machine-readable result
        |
        v
marker-scoped Issue reconciler
        |
        +--> create / update / close / no-op
        `--> dry-run: summary only
```

## Trust boundary and monitored sources

Extension watches query only GitHub metadata for the repository declared by `config/extension.json`: GitHub Releases for release-driven projects and GitHub tags for projects such as pg_repack that do not publish GitHub Releases. Candidate source trees are never checked out or executed by the watcher.

PostgreSQL state is derived only from primary PostgreSQL community sources. `https://www.postgresql.org/support/versioning/` is the production release/lifecycle authority and `https://www.postgresql.org/developer/beta/` supplies pre-release information. Beta/RC data is informational and never establishes production support.

All remote data is treated as untrusted. Tag/release names are matched against bounded declarative regular expressions, never evaluated as shell, and GitHub CLI calls use argument arrays rather than shell interpolation.

## Update Watch Contract

Each extension repository owns `config/update-watch.json`; `config/extension.json` remains the sole authority for the currently configured source ref/version. The watch file therefore contains no duplicate current-version field.

Schema version 1 supports three strategies:

- `github-releases`: one stable source series selected from non-draft, non-prerelease GitHub Releases.
- `github-tags`: one stable source series selected from tags when Releases are not authoritative.
- `github-releases-per-postgresql`: independent stable Release series for each PostgreSQL major.

The canonical schema is `schema/update-watch.schema.json` in `pgextwin/build`. It allows repository identity, strategy, stable tag patterns, a stable-only prerelease policy, and per-PostgreSQL patterns. It contains no command/script field and cannot authorize arbitrary code execution.

## Stable and prerelease policy

Schema version 1 is intentionally stable-only (`prereleases: false`). Draft Releases and Releases marked prerelease are ignored. Candidate tags containing common alpha/beta/RC/preview markers are also rejected, and each project uses a stable tag pattern narrow enough to exclude its known prerelease naming convention.

This double filter is required because not every upstream consistently uses GitHub's prerelease flag.

## Per-PostgreSQL series

`pg_hint_plan` and `pgaudit` use independent source series for PostgreSQL majors. Each configured PostgreSQL major is compared only with the Release pattern assigned to that same major. A PostgreSQL 18 tag can therefore never become the PostgreSQL 14 candidate.

A rule for a future major may be marked `informational: true`. PostgreSQL 19 candidates can then appear in the Actions summary without being treated as a production update and without modifying `config/extension.json`.

## Detection states and operational failures

The detector distinguishes:

- `up-to-date`: authoritative query succeeded and no newer stable candidate exists;
- `update-available`: authoritative query succeeded and a newer stable candidate exists;
- `indeterminate`: the upstream/official query or parsing failed.

An indeterminate result fails the workflow and skips Issue reconciliation. Rate limits, HTTP failures, malformed JSON/HTML, or parse failures are never converted into an "up-to-date" result.

## Issue-only reconciliation

Extension Issues contain a stable marker such as:

```text
<!-- pgextwin-update-watch:v1:upstream:pg_cron -->
```

The PostgreSQL watcher uses:

```text
<!-- pgextwin-update-watch:v1:postgresql -->
```

A second hidden marker records a digest of the detected candidate state. The reconciler only manages open Issues containing its exact ownership marker:

- no owned Issue + update → create;
- same candidate → no-op;
- changed candidate → update the owned Issue;
- configured state catches up → close the owned Issue;
- unrelated/human-created Issues → untouched.

Titles alone are never used as an ownership signal.

The manual gate in an extension Issue requires upstream release-note review, license verification, Windows compatibility review, PostgreSQL matrix build, Test Contract functional validation, PACKAGE-INFO/SBOM/vulnerability/attestation processing, and only then the existing Release/Catalog path. Website availability remains Catalog-derived.

## PostgreSQL release and lifecycle detection

`metadata/postgresql.json` is compared with the official Versioning Policy for every configured major. A changed current minor or EOL date creates/updates the automation-owned PostgreSQL Issue. A newly supported major that is absent from metadata is also actionable.

Chocolatey is not an authority for whether PostgreSQL itself has released. The Issue therefore records Windows package availability as requiring manual verification unless a trustworthy package query is explicitly added later. Failure to verify Chocolatey must not suppress an official PostgreSQL update.

### PostgreSQL 19

Before GA, Beta/RC state is shown in the Actions summary only. It does not create a "production onboarding required" Issue.

Once the official Versioning Policy exposes PostgreSQL 19 as a supported production release while `metadata/postgresql.json` still lacks major 19, the watcher creates/updates `PostgreSQL 19 GA detected — review production onboarding gate`. The Issue points maintainers to `docs/postgresql-19-readiness.md` and requires GA confirmation, a standard Windows x64 distribution, reproducible CI installation, official lifecycle metadata, acceptable upstream PG19 refs, and functional tests. The watcher itself never adds PostgreSQL 19 to the production matrix.

## Schedule and dry-run

Each initial extension has one daily UTC schedule, staggered across repositories to avoid concentrating scheduled load. `workflow_dispatch` defaults to dry-run. Scheduled runs are normal mode so a genuine stable update can create/update/close the automation-owned Issue.

`pgextwin/build` runs the PostgreSQL watch daily at 05:29 UTC. Its manual dispatch also defaults to dry-run.

Dry-run performs live metadata queries, detection, and Issue decision calculation, but performs no Issue mutation.

## Permissions

Extension callers and the reusable watch job use only:

```yaml
permissions:
  contents: read
  issues: write
```

The PostgreSQL watch uses the same scopes in `pgextwin/build`. No PAT, organization secret, `contents: write`, pull-request write, Actions write, OIDC, attestation write, or security-events write permission is required.

These Issue permissions do not propagate into normal Windows build workflows. Existing build/release permission separation remains unchanged.

## Testing

`tests/test-update-watch.py` is fixture-driven and does not depend on the current network state. It covers stable/no-update/prerelease/error behavior, per-PostgreSQL isolation and PG19 informational handling, Issue create/update/no-op/close decisions and human-Issue protection, PostgreSQL minor/EOL drift, pre-release behavior, and PostgreSQL 19 GA detection.

Live scheduled/manual workflows remain the end-to-end check for network/authentication behavior.

## Manual next steps after a notification

A notification is the start of review, not authorization to ship. Maintainers should review the upstream change and license, assess Windows compatibility, deliberately update the pinned source only in a separate change, run the complete maintained PostgreSQL/Test Contract matrix, and require the existing packaging/security/provenance pipeline. Only a validated pgextwin Release should lead to Catalog metadata; Website reflects Catalog separately.
