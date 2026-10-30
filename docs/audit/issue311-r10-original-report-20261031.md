# R10-02 protected original audit report — 2026-10-31 JST

**Status: partial, NONPUBLISHING, R10-02 PENDING.** This is evidence retention, not acceptance, a Release instruction, a credential, or a candidate proposal.

- Original read-only GitHub Actions Run: [41141592659](https://github.com/pgextwin/build/actions/runs/41141592659) attempt 1, `source_report` job 124356913591 and independent Runner job 124357114758 SUCCESS.
- Source [Artifact 13018064547](https://github.com/pgextwin/build/actions/runs/41141592659/artifacts/13018064547), original ZIP SHA256: `8276a75966f22d5349d8246ccad92269c9d76041488381c3baae64836f5b17ef`.
- Internal exact 76,647-byte `issue311-r10-final-report.json` SHA256: `615d32b8493ee292daea971d456d08fc74ff9b309690762ff05cd9c97f089688`. The source Runner and separately authenticated no-App-key Runner independently recomputed identical bytes.
- The full report is preserved **losslessly** as `docs/audit/issue311-r10-original-report-20261031.json.gz.b64`, pinned by both gzip bytes SHA256 `67556af5d455eff262e5a719c86fe017c40b365c9effbec8716e90c8a79d3793` and original JSON SHA256.
- Restore locally without GitHub, credentials, App keys, dispatch, or writes: `python scripts/issue311-r10-protected-report.py --restore issue311-r10-restored.json`.
- Reproduce independent authenticated source Git GET and compare byte-for-byte: `GH_TOKEN=<read-only-token> python scripts/issue311-r10-final-readonly-report.py --verify --output issue311-r10-restored.json`. Do not reuse the source App token. Use a new output path for a new report, or the exact restored file for verification. The GitHub workflow performs the comparison automatically on a **new** protected main push triggered by these code/evidence paths, using `contents: read` and `actions: read`.
- Run `python tests/test-issue311-r10-protected-report.py` for offline tamper/format/privilege guards. No success Run reruns.

## Terminal evidence (not new PASS)

| Immutable checkpoint | Original source Run/attempt | State terminal | Per-target completeness |
|---|---:|---|---|
| `r-20261030-r06appauto41074138918` | 41074138918/1 | NO_UPDATE | 17 genuine original receipt ZIP SHA256 in full report |
| `r-20261030-r06appauto41014241399` | 41014241399/1 | QUARANTINED | INCOMPLETE: 17 detailed failure receipts unjoined |
| `r-20261030-r06appauto41015355922` | 41015355922/1 | QUARANTINED | INCOMPLETE: 17 detailed failure receipts unjoined |
| `r-20261029-r05eventgap17b01` | 40864238327/1 | FAILED | INCOMPLETE: 17 detailed missing-event receipts unjoined |
| `r-20261030-r06parallelcasproof12` | 41032550321/1 | QUARANTINED | INCOMPLETE: detailed per-target CAS race receipts unjoined |
| `r-20261030-r06appauto41014731356` | 41014731356/1 | NO_UPDATE | 17 genuine original receipt ZIP SHA256 in full report |

The report retains per-target status/reason/restart point, original Run/attempt/head where present, artifact IDs and actual ZIP SHA256 where authenticated, and explicit `missingEvidenceReason` for absent links. Source State blobs are separately authenticated Contents GETs. The four negative terminals are not falsely marked complete; no guessed artifact ID/SHA, successful publication, or approval is implied.

## Outstanding acceptance gates

1. Join authentic per-target failure/skip/timeout and acknowledgement-loss or CAS-race evidence, using original event/job/Run/attempt/head/artifact/SHA where actually present. Preserve an explicit missing reason for any unavailable evidence.
2. Independently prove genuine `BLOCKED_APPROVAL` receipt under the v2.1 controls, not a fabricated successful terminal.
3. Confirm new original main-push postmerge readback/required resolver and retain SHA/Run IDs in Issue #311 and parent #75. Only after all R10-02 acceptance criteria are met consider its checkbox, then parent R10.
4. Do not alter `runtimeEnabled=false`, `PUBLISH_DENY`, R09-02, R11, R12, branch rules, Secret permissions, schedules, Catalog, feed, Website Draft PR #45, tags, or Releases.

The Actions artifact expires after 30 days. This Git file preserves the exact independently verified report bytes subject to Git history retention; the retained bytes do not substitute for original evidence that was genuinely absent at source.
