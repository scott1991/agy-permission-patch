#!/usr/bin/env bash
set -euo pipefail

case_dir="$RUNNER_TEMP/agy-candidate"
proposal="$case_dir/recipe.proposed.json"
log="${1:-$RUNNER_TEMP/agy-candidate.log}"

if [[ ! -f "$case_dir/analysis-plan.json" || ! -f "$case_dir/input/agy" ]]; then
  echo "No prepared case to analyze; skipping the proposal." >&2
  exit 1
fi

cp "$log" "$case_dir/failure.log" 2>/dev/null || true

IFS= read -r -d '' prompt <<'PROMPT' || true
You are proposing a patch recipe for the macOS ARM64 agy binary so that its
--dangerously-skip-permissions flag auto-approves tool confirmations.

Read these files in the current directory:
- analysis-plan.json (source SHA-256, target functions, padding candidates)
- targets.json (target function address ranges)
- init.disasm (main.init.1 disassembly)
- confirmation.disasm (handleToolConfirmation disassembly)
- recovered/functions.tsv (function name table)
- failure.log (why the deterministic locator stopped)

Propose one JSON object with exactly these keys:
  expected_sha256, site, resume, approve, flag, cave, original_hex

Rules:
- site: address of the first instruction of the permission-mode compare
  sequence (the LDR x3,[x0] that loads the settings struct).
- resume: site + 4.
- approve: address on the auto-approve path that returns "approved" after
  the permission-mode compare.
- flag: address of the 28-byte "dangerously-skip-permissions" string binding.
- cave: an address from padding_candidates (at least 24 bytes of zero padding).
- original_hex: the four little-endian bytes at site, as hex without 0x.
Addresses are hex strings such as "0x1030f3038".
If you cannot determine a value with confidence, output
{"error":"reason"} instead of guessing.
Output only one fenced ```json block. Do not modify any file.
PROMPT

raw="$(env -u GITHUB_TOKEN -u OPENCODE_CONSOLE_TOKEN \
  opencode run --pure --dir "$case_dir" -m opencode/deepseek-v4.1-flash-free \
  "$prompt" 2>/dev/null)" || {
  echo "opencode did not return a proposal." >&2
  exit 1
}

python3 - "$raw" "$proposal" <<'PY'
import json
import re
import sys

text, out = sys.argv[1], sys.argv[2]
blocks = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.S)
candidate = blocks[-1] if blocks else text
start, end = candidate.find('{'), candidate.rfind('}')
if start < 0 or end < start:
    raise SystemExit('No JSON object in the model response.')
try:
    obj = json.loads(candidate[start:end + 1])
except json.JSONDecodeError as error:
    raise SystemExit(f'Invalid JSON: {error}')
if 'error' in obj:
    raise SystemExit('Model declined: ' + str(obj['error']))
required = {'expected_sha256', 'site', 'resume', 'approve', 'flag', 'cave', 'original_hex'}
missing = required - obj.keys()
if missing:
    raise SystemExit('Missing keys: ' + ', '.join(sorted(missing)))
with open(out, 'w') as stream:
    json.dump(obj, stream, indent=2)
    stream.write('\n')
PY

echo "Wrote $proposal"
