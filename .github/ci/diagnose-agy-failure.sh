#!/usr/bin/env bash
set -euo pipefail

run_id="$GITHUB_RUN_ID"
run_attempt="$GITHUB_RUN_ATTEMPT"
if [[ -n "${DIAGNOSE_RUN_ID:-}" ]]; then
  if [[ ! "$DIAGNOSE_RUN_ID" =~ ^[0-9]+$ ]]; then
    printf 'The run ID must be numeric.\n' >&2
    exit 1
  fi
  run_id="$DIAGNOSE_RUN_ID"
  run_attempt="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id" \
    --jq 'select(.status == "completed" and .conclusion == "failure") | .run_attempt')"
  if [[ -z "$run_attempt" ]]; then
    printf 'The selected run must be completed with a failure.\n' >&2
    exit 1
  fi
fi
jobs="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/attempts/$run_attempt/jobs")"

if [[ "$run_id" != "$GITHUB_RUN_ID" ]]; then
  build_id="$(jq -r '.jobs[] | select(.name == "build" and .conclusion == "failure") | .id' <<< "$jobs")"
  if [[ -n "$build_id" ]]; then
    failed_log="$(gh run view "$run_id" --repo "$GITHUB_REPOSITORY" \
      --attempt "$run_attempt" --job "$build_id" --log-failed)"
    if grep -Fq 'Permission-mode pattern changed or ambiguous' <<< "$failed_log" \
       || grep -Fq 'Permission-mode prologue changed' <<< "$failed_log" \
       || grep -Fq 'Auto-approve path changed' <<< "$failed_log"; then
      CANDIDATE_FAILURE=strict_pattern
    fi
  fi
fi

evidence="$(jq -c --arg tag "$UPSTREAM_TAG" --arg candidate_failure "$CANDIDATE_FAILURE" '{
  upstream_tag: $tag,
  candidate_failure: (if $candidate_failure == "" then null else $candidate_failure end),
  jobs: [.jobs[] | select(.name == "check" or .name == "build" or .name == "publish")
    | {name, conclusion, steps: [(.steps // [])[] | {name, conclusion}]}]
}' <<< "$jobs")"

{
  printf '### Workflow failure\n\n'
  printf 'Run: %s/%s/actions/runs/%s/attempts/%s\n\n' \
    "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$run_id" "$run_attempt"
  jq -r '.jobs[] | select(.conclusion == "failure")
    | .name as $job | ([.steps[] | select(.conclusion == "failure") | .name] | join(", ")) as $steps
    | if $steps == "" then "- " + $job else "- " + $job + " / " + $steps end' <<< "$evidence"
  case "$CANDIDATE_FAILURE" in
    strict_pattern)
      printf '\nThe deterministic locator stopped on a changed semantic pattern.\n' ;;
    llm_recipe_rejected)
      printf '\nThe opencode proposal was rejected by the strict validator.\n' ;;
    llm_no_proposal)
      printf '\nNo usable opencode proposal was produced.\n' ;;
  esac
} >> "$GITHUB_STEP_SUMMARY"

prompt="$(cat "$(dirname -- "${BASH_SOURCE[0]}")/agy-ci-failure.prompt.md")"
cd "$RUNNER_TEMP"
summary="$(env -u GITHUB_TOKEN -u OPENCODE_CONSOLE_TOKEN \
  opencode run --pure -m opencode/deepseek-v4.1-flash-free \
  "$prompt"$'\n\n'"$evidence" 2>/dev/null)"
test -n "$summary"
{
  printf '\n### opencode CI summary\n\n'
  printf '%s\n' "$summary" | sed 's/^/> /'
} >> "$GITHUB_STEP_SUMMARY"
