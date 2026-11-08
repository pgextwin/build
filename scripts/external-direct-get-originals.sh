#!/usr/bin/env bash
# Exact source-specific private binary preflight for the original Build owner Run.
# Not a publisher; never uploads, modifies provider ZIPs or writes Catalog.
set -euo pipefail
extension="${1:-}"
test "$GITHUB_ACTIONS" = true
test "$GITHUB_REPOSITORY" = "pgextwin/build"
test "$GITHUB_EVENT_NAME" = "workflow_dispatch"
test "$GITHUB_REF" = "refs/heads/main"
test "$GITHUB_ACTOR" = "ShutenOishi"
test "$GITHUB_RUN_ATTEMPT" = "1"
test -d "$RUNNER_TEMP"
get_exact() {
  local url="$1" file="$2" size="$3" sha="$4"
  test ! -e "$file" && test ! -L "$file"
  curl --fail --silent --show-error --location --max-redirs 3 --max-time 150 \
    --proto '=https' --proto-redir '=https' --retry 0 --output "$file" "$url"
  test "$(stat -c %s "$file")" = "$size"
  test "$(sha256sum "$file" | cut -d' ' -f1)" = "$sha"
}
case "$extension" in
  pg_trickle)
    get_exact \
      "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/pg_trickle-0.108.3-pg18-windows-amd64.zip" \
      "$RUNNER_TEMP/original-pg-trickle.zip" 7029107 \
      "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b"
    ;;
  hypopg)
    mkdir "$RUNNER_TEMP/original-hypopg"
    while read -r pg size sha; do
      get_exact \
        "https://github.com/HypoPG/hypopg/releases/download/1.4.1/hypopg-1.4.1-pg${pg}-x64.zip" \
        "$RUNNER_TEMP/original-hypopg/hypopg-pg${pg}.zip" "$size" "$sha"
    done < <(printf '%s\n' \
      '14 23115 ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634' \
      '15 23123 d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec' \
      '16 22997 7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7')
    ;;
  *)
    echo 'Unknown reviewed original provider; fail-closed' >&2
    exit 1
    ;;
esac
echo "ORIGINAL_SOURCE_PRIVATE_BYTES=PASS SOURCE=$extension RELEASE=NONE MIRROR=DENY"
