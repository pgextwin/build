#!/usr/bin/env bash
# Exact source-specific private binary preflight for the original Build owner Run.
# Not a publisher; never uploads, modifies provider ZIPs or writes Catalog.
set -euo pipefail
extension="$1"
test "$GITHUB_ACTIONS" = true
test "$GITHUB_REPOSITORY" = "pgextwin/build"
test "$GITHUB_EVENT_NAME" = "workflow_dispatch"
test "$GITHUB_REF" = "refs/heads/main"
test "$GITHUB_ACTOR" = "ShutenOishi"
test "$GITHUB_RUN_ATTEMPT" = "1"
test -d "$RUNNER_TEMP"

get_exact() {
  local url="$1" file="$2" size="$3" sha="$4" label="$5"
  local part="$file.partial" attempt=1 rc=0 http=""
  test ! -e "$file" && test ! -L "$file"
  test ! -e "$part" && test ! -L "$part"
  # The only GET target is the previously reviewed immutable provider release URL.
  # No API fallback, mirrors, authentication, altered pins or cross-source endpoints.
  while (( attempt <= 3 )); do
    echo "ORIGINAL_GET_BEGIN source=$label attempt=$attempt/3"
    rc=0
    http="$(curl --fail --silent --show-error --location --max-redirs 3 \
      --connect-timeout 15 --max-time 80 --proto '=https' --proto-redir '=https' \
      --retry 0 --write-out '%{http_code}' --output "$part" "$url" 2>/dev/null)" || rc=$?
    if (( rc == 0 )) && [[ "$http" == "200" ]]; then
      if [[ ! -f "$part" || -L "$part" ]] ||
         [[ "$(stat -c %s "$part")" != "$size" ]] ||
         [[ "$(sha256sum "$part" | cut -d' ' -f1)" != "$sha" ]] ||
         [[ "$(head -c 4 "$part" | od -An -tx1 | tr -d ' \n')" != "504b0304" ]] ||
         ! unzip -tqq "$part" >/dev/null 2>&1; then
        rm -f -- "$part"
        echo "ORIGINAL_GET_DENY source=$label class=BYTE_OR_ZIP_MISMATCH" >&2
        return 1
      fi
      test ! -e "$file" && test ! -L "$file"
      mv -- "$part" "$file"
      echo "ORIGINAL_GET_PASS source=$label bytes=$size sha256=$sha zip=CRC_PASS"
      return 0
    fi
    rm -f -- "$part"
    case "$rc:$http" in
      22:502|22:503|22:504|6:*|7:*|18:*|28:*|35:*|52:*|55:*|56:*|92:*)
        echo "ORIGINAL_GET_TRANSIENT source=$label attempt=$attempt/3 curl_exit=$rc http=$http" >&2
        ;;
      *)
        echo "ORIGINAL_GET_DENY source=$label class=NON_RETRYABLE curl_exit=$rc http=$http" >&2
        return 1
        ;;
    esac
    if (( attempt == 3 )); then
      echo "ORIGINAL_GET_DENY source=$label class=RETRY_EXHAUSTED" >&2
      return 1
    fi
    if (( attempt == 1 )); then sleep 3; else sleep 7; fi
    attempt=$(( attempt + 1 ))
  done
  return 1
}
case "$extension" in
  pg_trickle)
    get_exact \
      "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/pg_trickle-0.108.3-pg18-windows-amd64.zip" \
      "$RUNNER_TEMP/original-pg-trickle.zip" 7029107 \
      "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b" \
      "pg_trickle PG18 asset=616203967"
    ;;
  hypopg)
    mkdir "$RUNNER_TEMP/original-hypopg"
    while read -r pg asset size sha; do
      get_exact \
        "https://github.com/HypoPG/hypopg/releases/download/1.4.1/hypopg-1.4.1-pg$pg-x64.zip" \
        "$RUNNER_TEMP/original-hypopg/hypopg-pg$pg.zip" "$size" "$sha" \
        "hypopg PG$pg asset=$asset"
    done < <(printf '%s\n' \
      '14 164673161 23115 ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634' \
      '15 164673166 23123 d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec' \
      '16 164673171 22997 7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7')
    ;;
  *)
    echo 'Unknown reviewed original provider; fail-closed' >&2
    exit 1
    ;;
esac
echo "ORIGINAL_SOURCE_PRIVATE_BYTES=PASS SOURCE=$extension RELEASE=NONE MIRROR=DENY"
