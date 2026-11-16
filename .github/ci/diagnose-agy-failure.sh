#!/usr/bin/env bash
set -euo pipefail

jobs="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs")"
build_id="$(jq -r '.jobs[] | select(.name == "build" and .conclusion == "failure") | .id' <<< "$jobs")"
pattern_error=false
if [[ -n "$build_id" ]] && gh run view "$GITHUB_RUN_ID" --repo "$GITHUB_REPOSITORY" \
    --attempt "$GITHUB_RUN_ATTEMPT" --job "$build_id" --log-failed \
    | grep -F 'Stopped: Permission-mode pattern changed or ambiguous' > /dev/null; then
  pattern_error=true
fi

evidence="$(jq -c --arg tag "$UPSTREAM_TAG" --argjson pattern_error "$pattern_error" '{
  upstream_tag: $tag,
  pattern_error_seen: $pattern_error,
  jobs: [.jobs[] | select(.name == "check" or .name == "build" or .name == "publish")
    | {name, conclusion, steps: [(.steps // [])[] | {name, conclusion}]}]
}' <<< "$jobs")"

{
  printf '### Workflow failure\n\n'
  printf 'Run: %s/%s/actions/runs/%s/attempts/%s\n\n' \
    "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
  jq -r '.jobs[] | select(.conclusion == "failure")
    | .name as $job | ([.steps[] | select(.conclusion == "failure") | .name] | join(", ")) as $steps
    | if $steps == "" then "- " + $job else "- " + $job + " / " + $steps end' <<< "$evidence"
} >> "$GITHUB_STEP_SUMMARY"

prompt="$(cat "$(dirname -- "${BASH_SOURCE[0]}")/agy-ci-failure.prompt.md")"
cd "$RUNNER_TEMP"
env -u GITHUB_TOKEN npm install --global --prefix "$RUNNER_TEMP/copilot-cli" @github/copilot@1.0.109
summary="$(COPILOT_HOME="$RUNNER_TEMP/copilot-home" \
  "$RUNNER_TEMP/copilot-cli/bin/copilot" --silent --no-ask-user \
  --no-auto-update --no-custom-instructions --disable-builtin-mcps \
  --available-tools=view --deny-tool=read -p "$prompt"$'\n\n'"$evidence")"
test -n "$summary"
{
  printf '\n### Copilot CI summary\n\n'
  printf '%s\n' "$summary" | awk 'NR <= 25 { print "    " substr($0, 1, 400) }'
} >> "$GITHUB_STEP_SUMMARY"
