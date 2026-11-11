#!/usr/bin/env python3
"""Validate observed live CLI logs and the version-locked installed candidate."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
v = root/'verification'
expected = {
    'print-skip.log': ('Print mode: --dangerously-skip-permissions set',
                      'Always-proceed: auto-approving tool confirmation "RunCommand"'),
    'interactive-skip.log': ('Launching CLI mode', '--dangerously-skip-permissions: auto-approving',
                            'Always-proceed: auto-approving tool confirmation "RunCommand"'),
    'outside-read-skip.log': ('Print mode: --dangerously-skip-permissions set',
                             'Always-proceed: auto-approving tool confirmation "ViewFile"'),
    'print-no-skip.log': ('Print mode: soft-denying tool confirmation "RunCommand"',),
    'original-print-skip.log': ('Print mode: --dangerously-skip-permissions set',
                               'Enforcing ToolPermission = request-review',
                               'Print mode: soft-denying tool confirmation "RunCommand"'),
}
results = []
for name, markers in expected.items():
    log = (v/name).read_text()
    for marker in markers:
        assert marker in log, (name, marker)
    if name in ('print-skip.log', 'interactive-skip.log', 'outside-read-skip.log'):
        assert 'soft-denying tool confirmation' not in log, name
        assert 'FILE_ACCESS_POLICY_ALWAYS_ASK' in log, name
        assert 'TERMINAL_COMMAND_AUTO_EXECUTION_POLICY_REQUIRE_REVIEW' in log, name
    results.append(dict(log=name, result='pass', matched=list(markers)))
assert (v/'interactive-command-output.txt').read_text() == 'AGY_PATCH_INTERACTIVE_OK'
m = json.loads((root/'patched/manifest.json').read_text())
binary = (root/'patched/agy').read_bytes()
assert hashlib.sha256(binary).hexdigest() == m['signed_sha256']
assert binary[m['patch_offset']:m['patch_offset']+4].hex() == m['patched_hex']
trampoline = bytes.fromhex(m['trampoline_hex'])
assert binary[m['trampoline_offset']:m['trampoline_offset']+len(trampoline)] == trampoline
summary = dict(results=results, interactive_command_output='AGY_PATCH_INTERACTIVE_OK',
    observed_print_stdout='AGY_PATCH_PRINT_OK', observed_outside_read_stdout='AGY_PATCH_OUTSIDE_READ_OK',
    stdout_evidence='Observed completed tool process outputs in this conversation.',
    signed_sha256=m['signed_sha256'], startup_trust='One initial workspace trust prompt was accepted; no tool confirmation was entered.',
    result='pass')
(v/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS: interactive and print approvals, outside-workspace read, flag-off control, original-binary control, and candidate identity.')
