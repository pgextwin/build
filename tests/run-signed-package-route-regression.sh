#!/usr/bin/env bash
set -u
result=0
for test in \
    test-signed-package-routes \
    test-chat-signed-main-source \
    test-publisher-owner-source-admission \
    test-automatic-signed-candidate-audit \
    test-audit-merged-scheduled-signed-candidate \
    test-join-merged-scheduled-oidc-audits \
    test-verify-completed-signed-source \
    test-fleet-publish-release \
    test-owner-source-formal-publisher; do
    printf '\n%s\n' "$test"
    python -B -u "tests/$test.py" -v
    code=$?
    printf '%s exit=%d\n' "$test" "$code"
    if (( code != 0 )); then result=1; fi
done
exit "$result"
