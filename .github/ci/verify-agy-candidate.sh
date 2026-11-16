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
if grep -Fq 'Stopped: Permission-mode pattern changed;' "$candidate_log"; then
  failure=strict_pattern
elif grep -Fq 'Stopped: Permission-mode pattern ambiguous;' "$candidate_log"; then
  failure=pattern_ambiguous
fi
if [[ "$failure" != strict_pattern ]]; then
  printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
  exit "$status"
fi

case_dir="$RUNNER_TEMP/agy-candidate"
evidence="$RUNNER_TEMP/agy-mode-profile-input.txt"
response="$RUNNER_TEMP/agy-mode-profile-response.txt"
{
  printf 'Source SHA-256: %s\n\n' "$(shasum -a 256 "$RUNNER_TEMP/upstream-agy" | cut -d ' ' -f 1)"
  printf 'Known version instruction window:\n'
  python3 -c 'import fast_patch_update as f; print(" ".join(f"{word:08x}" for word in f.MODE_CHECK))'
  printf '\n\nAnalysis plan:\n'
  cat "$case_dir/analysis-plan.json"
  printf '\n\nTarget functions:\n'
  cat "$case_dir/targets.json"
  printf '\n\nFlag registration disassembly:\n'
  cat "$case_dir/init.disasm"
  printf '\n\nConfirmation handler disassembly:\n'
  cat "$case_dir/confirmation.disasm"
} > "$evidence"

if ! env -u GITHUB_TOKEN npm install --global --prefix "$RUNNER_TEMP/copilot-cli" @github/copilot@1.0.109; then
  printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
  exit 1
fi

prompt="$(cat .github/ci/agy-mode-profile.prompt.md)"
if ! COPILOT_HOME="$RUNNER_TEMP/copilot-home" \
  "$RUNNER_TEMP/copilot-cli/bin/copilot" --silent --no-ask-user \
    --no-auto-update --no-custom-instructions --disable-builtin-mcps \
    --available-tools=view --deny-tool=read \
    -p "$prompt"$'\n\n' "$(cat "$evidence")" > "$response"; then
  printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
  exit 1
fi

if ! python3 fast_patch_update.py build-candidate \
    --source "$RUNNER_TEMP/upstream-agy" --out "$case_dir" \
    --mode-profile "$response" 2>&1 | tee -a "$candidate_log"; then
  if grep -Fq 'Stopped: Permission-mode pattern ambiguous;' "$candidate_log"; then
    failure=pattern_ambiguous
  fi
  printf 'candidate_failure=%s\n' "$failure" >> "$GITHUB_OUTPUT"
  exit 1
fi
