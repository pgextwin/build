# Issue #75 — dedicated Classic protection read-only GitHub App

Status: **DESIGNED / CREDENTIALS NOT CREATED / NO LIVE API PROOF** (2026-10-13 JST)
Scope: `pgextwin/plpgsql_check` only. Issue: https://github.com/pgextwin/build/issues/75

## Why a dedicated App is necessary

The connected Codex Connector is installed on all repositories but has **no
Administration** repository permission. The existing `pgextwin-catalog-proposer`
App is **catalog-only** and must not be reused or expanded. The default Actions
`GITHUB_TOKEN` cannot be granted `administration:read` through workflow
`permissions:`. GitHub's public Rulesets API is not proof of **Classic**
branch protection, and an omitted `bypass_actors` is not proof of absence.

The normal Chat connector's authenticated
`GET /repos/pgextwin/plpgsql_check/branches/main/protection` returns 403.
The GitHub admin UI confirms the saved rule, but UI snapshots / a PR-provided
JSON blob / bare `protected=true` **cannot be runtime authorization evidence**.

### Decision

| Option | Benefit | Why selected/rejected |
| --- | --- | --- |
| Dedicated org-owned GitHub App, single-repo Administration:read | Installation-limited token expires within an hour, explicit minimum permission, isolated rotation/revocation, no personal dependency | **SELECTED**, after separate explicit Work authorization |
| Fine-grained PAT, repo Administration:read | Could read Classic rules | REJECTED for ongoing production: tied to a human owner/lifetime and account lifecycle, more difficult unattended rotation/revocation |
| Existing Codex Connector | Connected GitHub operations already work | DENIED 403, and expansion would affect the connector's broad repo installation |
| Existing Catalog App | Already handles Catalog proposal | NEVER REUSE OR EXPAND: catalog-only isolation is mandatory |
| Standard GITHUB_TOKEN / public Rulesets | No new credential | Cannot establish Classic PR/admin/bypass/strict/detail at runtime |

**Proposed immutable identity (not yet created):**
- App display name: `pgextwin-classic-protection-auditor`
- Owner: `pgextwin` organization, install only on **Selected repositories → plpgsql_check**
- Repository permissions: **Administration: Read-only; Metadata: Read-only (mandatory)**
- Organization permissions: **none**; all remaining repository permissions: **No access**.
- Event subscriptions: none; webhook disabled if GitHub UI permits.
- No Actions/write/contents/PR/Checks extra permissions; no global installation.

The GitHub App's **App ID** identifies the App itself; the **Installation ID**
identifies the scoped installation. They are NOT interchangeable, and neither
one is a secret. The GitHub App's **Client ID** is another nonsecret identifier
used by the `actions/create-github-app-token@v3` action. The **private key
is a secret** and must be generated and stored only by a separate authorized
Work action. Never copy or print the key into GitHub Issues, PRs, artifacts or
Chat. The action creates and revokes a short-lived installation token.

### Credential locations after future separate authorization

`pgextwin/plpgsql_check` **repository** variables:
- `PGEXTWIN_PROTECTION_AUDITOR_APP_ID` (GitHub App ID)
- `PGEXTWIN_PROTECTION_AUDITOR_CLIENT_ID` (GitHub App Client ID)
- `PGEXTWIN_PROTECTION_AUDITOR_INSTALLATION_ID` (record/check expected installation)

`pgextwin/plpgsql_check` **repository** secret:
- `PGEXTWIN_PROTECTION_AUDITOR_PRIVATE_KEY` (entire unaltered PEM)

No Organization secret, Environment secret, or `build` / `catalog` secret.
Never commit or log the key or resulting installation token.

Future trusted-main workflow **design example only, NOT installed/activated**:

```yaml
# Trusted job only after main ref + actor/authorization-path event validated.
# Pin actions/create-github-app-token to an audited immutable commit SHA
# before enabling. The unpinned sample MUST NOT be copied into production.
- uses: actions/create-github-app-token@v3
  id: protection_read
  with:
    client-id: ${{ vars.PGEXTWIN_PROTECTION_AUDITOR_CLIENT_ID }}
    private-key: ${{ secrets.PGEXTWIN_PROTECTION_AUDITOR_PRIVATE_KEY }}
    owner: pgextwin
    repositories: plpgsql_check
    permission-administration: read
# Use steps.protection_read.outputs.installation-id to confirm exact expected ID.
# Never pass the token to a PR-head checkout, candidate test, or third-party code.
```

The token is restricted twice: the App installation has only
`plpgsql_check`, and the minted token explicitly asks for that repo and
`administration:read`. The token has no write permission. Keep the separate
default `GITHUB_TOKEN` minimal (`contents:read`) in the auditor job; a
later **separate** trusted publishing job uses its own independently gated
credentials. The auditor must not inherit publication credentials.

## Credential-free implementation available now

- `scripts/classic-protection-audit.py`: no CLI, no secret-environment
  lookup, no workflow trigger, no write methods or publisher/receipt path.
  `ClassicProtectionReader(token)` GETs only:
  `GET /repos/pgextwin/plpgsql_check/branches/main` and
  `GET /repos/pgextwin/plpgsql_check/branches/main/protection`.
- `collect_verified_classic(reader, expected_main_sha=...)` reads both
  resources **twice**, requiring unchanged exact SHA and unchanged full
  protection snapshots. It reports only nonsecret boolean evidence and
  `publishableReceipt=false`.
- Policy pins the current eight GitHub Actions required contexts (including
  `Windows required summary`) to App ID **15368**, `strict=true`,
  PR required with approval count exactly zero, explicit empty actor-bypass
  lists, admin enforced, force/delete prohibited, and unrestricted actor list.
  Unknown, duplicated or omitted fields fail closed.
- `tests/test-classic-protection-audit.py`: offline positive and negative
  mocks cover invalid/missing fields, missing bypass arrays, HTTP failures,
  wrong GitHub App, race, bad JSON and pagination, all without a real token.
- Production must have **no fallback** to UI, unauthenticated Rulesets,
  user-provided protection JSON, or `protected=true` alone.
- The GitHub REST docs do not guarantee that all **empty** bypass values
  are always explicitly present in actual API 200 payloads. Therefore, absent
  bypass array or absent rule field is treated as **UNKNOWN → DENY** until
  a real credentialed GET 200 and separately reviewed parsing contract.
  NEVER reinterpret missing values as safe just to obtain a passing test.

See GitHub's official REST contract:
https://docs.github.com/en/rest/branches/branch-protection
and GitHub's official App token action:
https://github.com/actions/create-github-app-token

## Trusted execution and race / replay limits

- The collector is not a standalone program and has no `__main__`.
  A future Actions caller must run reviewed code at an **immutable pinned
  SHA** from protected main, after it validates main-only/nonbot event,
  the one-file squash-merged authorization record and exact operator identity.
- Mint the read token only in the trusted job **after** event safety gating;
  disable shell tracing, no echo or artifact of keys/tokens/response headers.
  Do not check out the untrusted PR or candidate branch while a token is held.
- Recheck protection+main just before a future privileged operation, verify
  the same expected SHA, require independently verified candidate artifacts,
  attestations and signed outputs, and ensure tag create-only / serialized
  replay-safe execution. Two API reads cannot atomically lock settings or
  prevent a privileged admin change after the last check; this is a residual
  TOCTOU risk and must **fail closed** on changed values.
- The current strict eight-context baseline is deliberate. Any later PG-major
  lifecycle change requires a reviewed policy update (e.g., retire individual
  per-major checks only after fixed `Windows required summary` is proven).
  This preparatory patch **does not change Classic settings**.
- Reject 401/403/404/429/5xx and any ambiguous or incomplete JSON. Under no
  circumstances emit a Release-authorizing receipt from this module.
- Repo variables and secrets are absent today; a test that only mocks
  responses **does not prove live Administration:read API access**.

## Future credentialed acceptance — nonpublishing, non-Dispatch only

After the separate Work step is explicitly approved and completed:

1. Independently verify App ownership, grant and installation membership
   from GitHub admin UI; confirm credentials exist in `plpgsql_check` alone.
2. In a **separately reviewed main-only, nonpublishing** pilot workflow
   (protected PR + exact-head CI before merge), mint a token scoped to
   `plpgsql_check`/`Administration:read`, verify the installation ID,
   and GET branch/protection returning authenticated HTTP 200.
3. Run the trusted audit using the current `main` SHA; compare eight actual
   pinned contexts, PR/strict/admin/bypass/force/deletion fields. Do not expose
   raw JSON/key/token in public logs/artifacts. Output only a sanitized PASS/
   DENY and safe request metadata.
4. Demonstrate negative token scope/permission/403 and missing-field behavior
   without disclosing secrets. Verify re-read on main drift; maintain
   `DRY_RUN_CONTEXT_ONLY` / `publishableReceipt=false`.
5. Require independent code review of any deviations between actual REST 200
   shape and mocked fixture before amending the contract. Never use a
   permissive fallback to accept 403/missing fields.
6. Revoke token on job completion; verify no new Release/tag/Dispatch. Report
   run, exact main SHA, source App and installed permissions to Issue #75.

**Blockers still open:** no dedicated App, no real 200 response, no trusted
in-run identity/event proof, no same-job independent artifact/signature
verification, no replay/race-safe publisher acceptance. Keep #75 OPEN and
production `manual-dispatch` until explicitly authorized separately.
