#!/usr/bin/env bash
set -euo pipefail

case_dir="$RUNNER_TEMP/agy-candidate"
candidate_log="$RUNNER_TEMP/agy-candidate.log"

if python3 fast_patch_update.py build-candidate \
    --source "$RUNNER_TEMP/upstream-agy" --out "$case_dir" \
    2>&1 | tee "$candidate_log"; then
  exit 0
fi

failure=other
pattern_failure=false
for marker in \
  'Permission-mode pattern changed or ambiguous' \
  'Permission-mode prologue changed' \
  'Permission-mode site is not a block entry' \
  'Auto-approve path changed' \
  'Auto-approve calls changed'; do
  if grep -Fq "$marker" "$candidate_log"; then
    pattern_failure=true
  fi
done

if [[ "$pattern_failure" == true ]]; then
  failure=strict_pattern
  if bash .github/ci/propose-agy-recipe.sh "$candidate_log"; then
    if python3 fast_patch_update.py build-candidate \
        --source "$RUNNER_TEMP/upstream-agy" --out "$case_dir" \
        --recipe "$case_dir/recipe.proposed.json" \
        2>&1 | tee -a "$candidate_log"; then
      exit 0
    fi
    failure=llm_recipe_rejected
  else
    failure=llm_no_proposal
  fi
fi

printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
exit 1
