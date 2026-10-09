# Step 20 central automation fleet policy

The sole mutable operational policy is metadata/automation-fleet.json in pgextwin/build main. Only declarative JSON is fetched dynamically; executable sources and reusable workflows remain pinned to immutable full 40-character SHAs.

OFF: do not query upstream or mutate Issues, PRs, or Releases. WATCH: stable-only discovery plus owned Issue reconciliation. BUILD: also requires extension-local config/candidate-build.json with enabled=true, releasePolicy=manual-only, workflow=windows.yml; create SHA-pinned draft candidate PR and dispatch read-only Windows CI. Formal Releases are not published by these watchers.

Change a reviewed registry entry to pause (OFF), observe (WATCH), or build (BUILD, only after documented candidate CI validation). Registry identity, strategy and local opt-in are checked at execution time. Missing, malformed, inconsistent or unavailable policy fails closed. Existing PRs, Issues, branches and artifacts are retained. An in-flight job already past the gate requires separate manual cancellation.

Each repository schedules its watch at UTC 00:00 (09:00 JST), not an execution-time guarantee. Distributed schedule avoids PAT, cross-repository Actions dispatch permission and extra GitHub App setup, but runs can be delayed/omitted. Do not mistake no recorded run for success.

Rollout starts with eight existing extensions in WATCH pending pilot and per-major artifact audits; plpgsql_check retains its prior BUILD opt-in. Do not promote to BUILD based on fixtures alone. The latest attempt and the last successful candidate must be recorded separately to avoid hiding regressions.
