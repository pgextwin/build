# R10-02 controlled negative original report — permanent lossless retention (2026-10-31 JST)

**Partial evidence, PENDING, NOT RELEASE-AUTHORIZED.** Never mark R10-02 or parent R10 PASS solely from this report.

## Provenance and original verification

- Original protected build main `fd671273d4b52066dd92e47e8ad82c7af7297221` from expected-HEAD squash merge [PR #472](https://github.com/pgextwin/build/pull/472), final PR HEAD `66c109961bcc6cc85c1d78e6c7e64829776c29e6`.
- Required PR resolver [Run 41145833095](https://github.com/pgextwin/build/actions/runs/41145833095) attempt 1 SUCCESS. Negative tests [Run 41145832807](https://github.com/pgextwin/build/actions/runs/41145832807) SUCCESS.
- Original postmerge [Run 41145936375](https://github.com/pgextwin/build/actions/runs/41145936375) attempt 1 SUCCESS. Source Job 124370927855 and separate App-keyless independent readback Job 124371082902 **both SUCCESS**.
- Original [Artifact 13021430705](https://github.com/pgextwin/build/actions/runs/41145936375/artifacts/13021430705), real **outer ZIP SHA256** `9cefe27a22f1f43db95c3d1a4ba7f55937fd0b04a132bde2f6b777d8befb46ef`.
- Exact 72,255-byte inner `issue311-r10-negative-originals.json`: SHA256 `fa1464b9e4fb9234f66a279e6e6360f610b5a933e37483c1a3b70c9f14c10910`; deterministic gzip 5,574 bytes SHA256 `f15cd41a976b79bc2df3e6eb81f472a043e8cde0c88728c53c620b237dc2a05b`.
- This file's counterpart `docs/audit/issue311-r10-negative-originals-20261031.json.gz.b64` is lossless and fixed by both byte digests; verify offline `python tests/test-issue311-r10-negative-protected.py`, restore with `python scripts/issue311-r10-negative-protected.py --restore issue311-r10-negative-restored.json`.
- The earlier protected report remains unchanged: 76,647 bytes, SHA256 `615d32b8493ee292daea971d456d08fc74ff9b309690762ff05cd9c97f089688`.

## Real negative witnesses and limits

| Case | Run / original ZIP artifact | Real outer ZIP SHA256 | Per-target result |
|---|---|---|---|
| skip | 41014241399 / 12959091676 | `c62a8cd9c186d6eb69e012b5cc519ed0924a8e95f84f8b91b6d6f6f552709b9c` | 16 original bot child Run/ZIP/SHA verified; orafce QUARANTINED without receipt |
| timeout | 41015355922 / 12958899431 | `a7920088b30517893c14fccbef4db7573dc8691fb8a6fcb43b33300b255583d0` | 16 original bot child Run/ZIP/SHA verified; orafce QUARANTINED without receipt |
| real CAS A | 41032550321 / 12965809030 | `6d5eb77f29057533dab3d644e96eb2a4cc3e59a80563cac27f41569338ee81ca` | actual HTTP409, one PUT |
| real CAS B | 41032550321 / 12965908472 | `aeb8df3dcc638f2233b0349cdbb4ff6ec724db31887cb42940d0fc73ea798b8c` | winner, one PUT |
| CAS independent | 41032550321 / 12966393631 | `374721c538e498d287f8bc1621a4b69faef3aebccb6e9b70cd21fa47d7e3c0ce` | separate keyless readback; token revoke 401 |
| event-gap source | 40864238327 / 12893455362 | `f2dbaafd1803a4536e134d99e60d9fd79d83daeb581997d2e53eed3b87a62d3b` | 17 protected targets; no child event receipt |

- Independent corroboration: true orafce control skip original Run 41014360341 / Job 123927212548 SKIPPED; true timeout original Run 41015468625 / Job 123930702453 FAILURE (timeout step FAILURE). **Both have zero original child artifacts**. Original dispatch inputs cannot be proven merely from Run GET and time range: this limitation is explicitly carried as `NO_DISPATCH_INPUT_BINDING_OR_ORIGINAL_CHILD_ZIP`; the apparent candidate Run is not promoted to a receipt.
- 4 negative State checkpoints; 68 target rows; exactly 32 authenticated successful child Run/ZIP receipts across two cases. Shared CAS/transport negative evidence is not fabricated into individual child receipts. 2 NO_UPDATE normal cases are already in the separate original report.
- Original terminal States remain **QUARANTINED** or **FAILED**, with last succeeded stage and safe restart point. No credential, privileged writer, public release, Catalog/feed or Website mutation is performed.

## Remaining gates

- R10-02: genuine `BLOCKED_APPROVAL` receipt plus full v2.1 per-target terminal, reason and original artifact coverage where mandatory. Missing facts remain INCOMPLETE; R10-02/parent R10 stay unchecked.
- R11-01/02: do not delete existing hourly cron until the substitute nonpublishing normal/negative path and old queued/in-progress Writer conflict have been independently accepted; hypopg additionally uses 41-minute recovery schedule. Preserve PR/push checks.
- R12-02: one Chat instruction to 17 target nonpublishing true terminals and operational handoff, after dependencies.
- R09-02: future eligible stable + separate human formal PUBLISH approval; Website Draft PR #45 unmerged.
- Keep `runtimeEnabled=false`, `PUBLISH_DENY`, required CI, all protected branches, and #311/#75 OPEN. Neither previous successes nor approvals are reclassified.
