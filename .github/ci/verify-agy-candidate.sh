#!/usr/bin/env bash
set -euo pipefail

candidate_log="$RUNNER_TEMP/agy-candidate.log"
if python3 fast_patch_update.py build-candidate \
    --source "$RUNNER_TEMP/upstream-agy" --out "$RUNNER_TEMP/agy-candidate" \
    2>&1 | tee "$candidate_log"; then
  exit 0
else
  status=$?
fi

failure=other
if grep -Fq 'Stopped: Permission-mode pattern changed or ambiguous' "$candidate_log"; then
  failure=strict_pattern
fi
printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
exit "$status"
