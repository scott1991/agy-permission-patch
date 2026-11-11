#!/usr/bin/env python3
"""Prepare an agy patch review, build a static candidate, or test and install locally.

Unknown instruction layouts fail closed and use PATCH-UPDATE.md instead.
The --reviewed switch records the operator's code review, not user approval.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

from patch_skip_permissions import locate, read_layout

ROOT = Path(__file__).resolve().parent
DEFAULT_TARGET = Path('/Users/scott/.local/bin/agy')
OBJDUMP = Path('/opt/homebrew/opt/llvm/bin/llvm-objdump')
# Reviewed 1.3.5 permission-mode check, including all relative branch offsets.
# No absolute code/data addresses occur in this block. Do not relax this pattern
# to make a changed release pass; review that release through the full workflow.
MODE_CHECK = tuple(int(word, 16) for word in '''
f9400803 a9439464 a94f1863 b5000066 aa0503e6 aa0403e3 f10038df
54000cc1 f9400064 d28d8c25 f2ac2ee5 f2ce6f25 f2ee05a5 eb05009f
54000be1 b9400864 d28dee45 f2acac65 6b05009f 54000b41 79401863
d28c8ca4 6b04007f 54000ac1 b27b03e0
'''.split())
FLAG_REGISTRAR = 'google3/base/go/flag.(*FlagSet).declareFlag'
APPROVAL_CALLS = (
    'runtime.mallocgcSmallScanNoHeaderSC4', 'runtime.convTstring',
    'runtime.gcWriteBarrier2', 'runtime.convT64',
    'runtime.gcWriteBarrier2', 'google3/base/go/log.ctxlogf',
)
# The reviewed path from allocation to the auto-approval log, including
# the two forward branches around Go's write barriers.
APPROVAL_MNEMONICS = '''
orr adrp add orr bl str ldr ldp bl adrp add ldr str adrp ldr cbz ldr bl
stp str ldr ldr bl adrp add ldr str adrp ldr cbz ldr bl stp str nop mov
mov orr mov mov mov adrp add orr mov mov bl
'''.split()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, **kwargs)


def pair_address(words, index, pc, register):
    """Decode only ADRP Xn; ADD Xn, Xn, #imm12 (no shifted ADD)."""
    first, second = words[index:index + 2]
    require(first & 0x9f00001f == 0x90000000 | register, 'Expected ADRP')
    require(second & 0xffc003ff == 0x91000000 | register << 5 | register,
            'Expected unshifted ADD')
    pages = ((first >> 29 & 3) | (first >> 5 & 0x7ffff) << 2)
    if pages & (1 << 20):
        pages -= 1 << 21
    return (pc & ~4095) + pages * 4096 + (second >> 10 & 4095)


def disassemble(binary, target, output, complete=False):
    options = ['--disassemble', '--disassemble-zeroes'] if complete else ['--disassemble']
    result = run([OBJDUMP, *options, '--start-address=' + target['address'],
                  '--stop-address=' + target['end'], binary], capture_output=True, text=True)
    output.write_text(result.stdout)
    instructions = []
    for line in result.stdout.splitlines():
        match = re.match(r'^([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$', line)
        if match:
            instructions.append((int(match[1], 16), int(match[2], 16), match[3]))
    require(instructions, 'No instructions returned by llvm-objdump')
    return instructions


def verify_disassembly(raw, target, instructions):
    start, end = (int(target[key], 16) for key in ('address', 'end'))
    require(end > start and start % 4 == end % 4 == 0 and
            [pc for pc, _, _ in instructions] == list(range(start, end, 4)),
            'Incomplete disassembly of ' + target['name'])
    require(all('<unknown>' not in asm for _, _, asm in instructions),
            'Undecoded instruction in ' + target['name'])
    segments, _ = read_layout(raw)
    offset = locate(segments, start, end - start, 4)
    decoded = struct.pack(f'<{len(instructions)}I', *(word for _, word, _ in instructions))
    require(raw[offset:offset + len(decoded)] == decoded,
            'Disassembly bytes differ from the snapshot for ' + target['name'])


def direct_call_name(row, function_names):
    pc, word, _ = row
    require(word & 0xfc000000 == 0x94000000, 'Expected a direct BL call')
    displacement = word & 0x03ffffff
    if displacement & (1 << 25):
        displacement -= 1 << 26
    return function_names.get(pc + displacement * 4)


def locate_recipe(raw, plan, init, handler, function_names=None):
    segments, _ = read_layout(raw)
    binding = []
    words = [row[1] for row in init]
    for index in range(len(words) - 8):
        if words[index + 4] not in (0xb27e0be4, 0xd2800384):
            continue  # x4 = 28, the exact flag name length
        try:
            flag = pair_address(words, index, init[index][0], 2)
            name = pair_address(words, index + 2, init[index + 2][0], 3)
            offset = locate(segments, name, 28, 1)
            if raw[offset:offset + 28] != b'dangerously-skip-permissions':
                continue
            require(words[index + 8] & 0xfc000000 == 0x94000000, 'Expected flag registration BL')
            locate(segments, flag, 1, 2, file_backed=False)
            binding.append((flag, index))
        except ValueError:
            continue
    require(len(binding) == 1, 'Flag binding not unique; use full analysis')
    handler_words = [row[1] for row in handler]
    sites = [i for i in range(len(handler_words) - len(MODE_CHECK) + 1)
             if tuple(handler_words[i:i + len(MODE_CHECK)]) == MODE_CHECK]
    require(len(sites) == 1, 'Permission-mode pattern changed or ambiguous; use full analysis')
    index = sites[0]
    site = handler[index][0]
    approve = handler[index + len(MODE_CHECK) - 1][0]
    # x16 must not be read later on either path. A stricter ban on any use is
    # deliberately inexpensive and conservative; a changed layout falls back.
    require(not any(re.search(r'\b[wx]16\b', row[2]) for row in handler[index:]),
            'x16 use after patch site; use full analysis')
    log_marker = b'Always-proceed: auto-approving tool confirmation %q at step %d'
    log_refs = []
    for j in range(index + len(MODE_CHECK), min(index + 100, len(handler_words) - 1)):
        try:
            address = pair_address(handler_words, j, handler[j][0], 6)
            offset = locate(segments, address, len(log_marker), 1)
            if raw[offset:offset + len(log_marker)] == log_marker:
                log_refs.append(j)
        except ValueError:
            pass
    require(len(log_refs) == 1, 'Auto-approve log reference changed; use full analysis')
    require(plan['padding_candidates'], 'No executable padding; use full analysis')
    flag, binding_index = binding[0]
    automated = function_names is not None
    if automated:
        # Between the flag arguments and BL, only x5 and x6 are initialized.
        description = binding_index + 5
        pair_address(words, description, init[description][0], 5)
        require(words[binding_index + 7] == 0xd2800766 and
                direct_call_name(init[binding_index + 8], function_names) == FLAG_REGISTRAR,
                'Flag registration call changed; use full analysis')
        approval = handler[index + len(MODE_CHECK) - 1:log_refs[0] + 6]
        require([asm.split()[0] for _, _, asm in approval] == APPROVAL_MNEMONICS and
                [word for _, word, asm in approval if asm.split()[0] == 'cbz']
                == [0x34000083, 0x34000081],
                'Auto-approve path changed; use full analysis')
        require(tuple(direct_call_name(row, function_names) for row in approval
                      if row[2].split()[0] == 'bl') == APPROVAL_CALLS,
                'Auto-approve calls changed; use full analysis')
    note = ('Automated static review passed for the source SHA256 and known ARM64 paths.'
            if automated else 'Strict 1.3.5 instruction pattern matched; read review.md before --reviewed.')
    recipe = dict(expected_sha256=hashlib.sha256(raw).hexdigest(), site=hex(site),
                  resume=hex(site + 4), approve=hex(approve), flag=hex(flag),
                  cave=plan['padding_candidates'][0]['address'], original_hex='030840f9',
                  review=dict(flag_binding_verified=automated, approve_branch_verified=automated,
                              x16_dead_verified=automated, note=note))
    snippet = ['Flag registration (x2 = bool, x3 = exact flag name):']
    snippet += [f'{pc:#x}: {word:08x}  {asm}'
                for pc, word, asm in init[max(0, binding_index - 5):binding_index + 9]]
    snippet += ['', 'Permission check, allocation and auto-approve log path:']
    snippet += [f'{pc:#x}: {word:08x}  {asm}'
                for pc, word, asm in handler[max(0, index - 3):log_refs[0] + 6]]
    return recipe, '\n'.join(snippet)


def already_installed(target, toolkit=None):
    toolkit = toolkit or ROOT
    digest = sha(target)
    for receipt_path in (toolkit / 'updates').glob('*/install-receipt.json'):
        receipt = json.loads(receipt_path.read_text())
        if receipt.get('signed_sha256') == digest:
            print('Already patched:', target, '\nReceipt:', receipt_path)
            return True
    return False


def prepare(source):
    if already_installed(source):
        return
    digest = sha(source)
    case = ROOT / 'updates' / digest[:12]
    if not case.exists():
        run([sys.executable, ROOT / 'prepare_patch_update.py', '--source', source])
    plan = json.loads((case / 'analysis-plan.json').read_text())
    require(plan['sha256'] == digest, 'Case/source hash mismatch')
    # A previous cleanup may have removed the rebuildable snapshot.
    binary = case / 'input/agy'
    if not binary.exists():
        binary.parent.mkdir(exist_ok=True)
        shutil.copy2(source, binary)
    require(sha(binary) == digest, 'Snapshot hash mismatch')
    review_snapshot(case, binary, plan)
    print('Static preparation complete. Read:', case / 'review.md')
    print('After code review: python3 fast_patch_update.py apply --case', case, '--reviewed')


def review_snapshot(case, binary, plan, automated=False):
    targets = json.loads((case / 'targets.json').read_text())
    init = [t for t in targets if t['name'] == 'main.init.1']
    handler = [t for t in targets if t['name'].endswith('.handleToolConfirmation')]
    require(len(init) == len(handler) == 1, 'Target functions changed')
    init_rows = disassemble(binary, init[0], case / 'init.disasm', complete=automated)
    handler_rows = disassemble(binary, handler[0], case / 'confirmation.disasm', complete=automated)
    raw = binary.read_bytes()
    function_names = None
    if automated:
        verify_disassembly(raw, init[0], init_rows)
        verify_disassembly(raw, handler[0], handler_rows)
        reviewed_names = {FLAG_REGISTRAR, *APPROVAL_CALLS}
        with (case / 'recovered/functions.tsv').open() as stream:
            function_names = {int(row['address'], 16): row['name']
                              for row in csv.DictReader(stream, delimiter='\t')
                              if row['name'] in reviewed_names}
    recipe, snippet = locate_recipe(raw, plan, init_rows, handler_rows, function_names)
    require(recipe['expected_sha256'] == plan['sha256'], 'Snapshot hash mismatch')
    recipe_path = case / ('recipe.verified.json' if automated else 'recipe.proposed.json')
    write_json(recipe_path, recipe)
    summary = ('Automated static review passed. Candidate requires a local behavior test.'
               if automated else
               'Strict 1.3.5 pattern matched. Confirm the flag binding and branch entry below before applying.')
    (case / 'review.md').write_text(
        '# Fast patch review\n\nSHA256: `' + recipe['expected_sha256'] + '`\n\n'
        + summary + ' x16 has no later uses. The patcher separately '
        'checks protections, zero padding, original bytes and branch ranges.\n\n'
        '```json\n' + json.dumps(recipe, indent=2) + '\n```\n\n```asm\n'
        + snippet + '\n```\n')
    return recipe_path


def patch_and_sign(source, recipe_path, candidate):
    run([sys.executable, ROOT / 'patch_skip_permissions.py', '--source', source,
         '--recipe', recipe_path, '--output', candidate], stdout=subprocess.DEVNULL)
    run(['codesign', '--force', '--sign', '-', '--preserve-metadata=entitlements,flags,identifier', candidate])
    run(['codesign', '--verify', '--strict', candidate])


def build_candidate(source, case):
    run([sys.executable, ROOT / 'prepare_patch_update.py', '--source', source, '--out', case])
    plan = json.loads((case / 'analysis-plan.json').read_text())
    snapshot = case / 'input/agy'
    recipe_path = review_snapshot(case, snapshot, plan, automated=True)
    candidate = case / 'candidate/agy'
    patch_and_sign(snapshot, recipe_path, candidate)
    manifest_path = candidate.with_name('manifest.json')
    manifest = json.loads(manifest_path.read_text())
    manifest.update(recipe_sha256=sha(recipe_path), signed_sha256=sha(candidate),
                    test_profile='static-only', smoke_tested=False)
    write_json(manifest_path, manifest)
    print('Signed ARM64 candidate:', candidate, '\nValidation: static-only; test behavior locally before use.')


def smoke(binary, case, name, skip=True, outside=None):
    marker = 'AGY_FAST_PATCH_OK'
    prompt = 'Use RunCommand exactly once to execute: printf ' + marker + '. Reply only with the command output.'
    if outside:
        prompt = f'Use ViewFile to read {outside}. Reply only with its content.'
    start = time.monotonic()
    command = [str(binary), '--log-file', str(case / (name + '.log')),
               '--print-timeout', '35s', '-p', prompt]
    if skip:
        command.insert(1, '--dangerously-skip-permissions')
    with (case / (name + '.stdout')).open('w') as out, (case / (name + '.stderr')).open('w') as err:
        result = subprocess.run(command, stdout=out, stderr=err, timeout=50, cwd=ROOT)
    output = (case / (name + '.stdout')).read_text()
    errors = (case / (name + '.stderr')).read_text()
    log = (case / (name + '.log')).read_text()
    tool = 'ViewFile' if outside else 'RunCommand'
    approved = f'Always-proceed: auto-approving tool confirmation "{tool}"' in log
    denied = 'soft-denying tool confirmation' in log
    passed = (result.returncode == 0 and output.strip() == marker and not errors
              and approved and not denied) if skip else (result.returncode == 0 and denied
                                                        and not approved and not output.strip())
    row = dict(name=name, passed=passed, exit_code=result.returncode,
               elapsed_seconds=round(time.monotonic() - start, 2),
               stdout=output, stderr=errors, auto_approved=approved, soft_denied=denied)
    write_json(case / (name + '.result.json'), row)
    print(f'{name}: {"PASS" if passed else "FAIL"} ({row["elapsed_seconds"]}s)', flush=True)
    require(passed, 'Smoke test failed; installed binary and old backups left intact. See ' + str(case))
    return row


def install(candidate, target, source_digest, case):
    require(sha(target) == source_digest, 'Installed version changed since preparation; stop')
    run(['codesign', '--verify', '--strict', candidate])
    signed_digest = sha(candidate)
    backup = target.with_name('agy.original-' + source_digest[:12])
    if not backup.exists():
        # Exclusive creation prevents overwriting another process's backup.
        with backup.open('xb') as out, target.open('rb') as original:
            shutil.copyfileobj(original, out)
        shutil.copystat(target, backup)
    require(sha(backup) == source_digest, 'Backup hash mismatch; stop')
    temporary = target.with_name('agy.new-' + signed_digest[:12])
    require(not temporary.exists(), 'Temporary install file exists; stop')
    try:
        with temporary.open('xb') as out, candidate.open('rb') as src:
            shutil.copyfileobj(src, out)
        shutil.copystat(candidate, temporary)
        require(sha(temporary) == signed_digest, 'Temporary copy hash mismatch')
        require(sha(target) == source_digest, 'Installed binary changed during copy; stop')
        os.replace(temporary, target)
        run(['codesign', '--verify', '--strict', target])
        require(sha(target) == signed_digest, 'Installed hash mismatch')
    finally:
        temporary.unlink(missing_ok=True)
    receipt = dict(installed=str(target), backup=str(backup), source_sha256=source_digest,
                   signed_sha256=signed_digest, result='installed; candidate smoke, installed hash and signature passed')
    write_json(case / 'install-receipt.json', receipt)
    return receipt


def cleanup(receipt, case, toolkit=None):
    toolkit = toolkit or ROOT
    target, backup = Path(receipt['installed']), Path(receipt['backup'])
    require(backup == target.with_name('agy.original-' + receipt['source_sha256'][:12]),
            'Unexpected backup path; no cleanup')
    require(sha(target) == receipt['signed_sha256'], 'Installed hash changed; no cleanup')
    require(sha(backup) == receipt['source_sha256'], 'Current backup invalid; no cleanup')
    removed = []
    # Only remove original backups whose exact names agree with their content.
    for path in sorted(backup.parent.glob('agy.original-*')):
        if path == backup or path.is_symlink() or not re.fullmatch(r'agy\.original-[0-9a-f]{12}', path.name):
            continue
        if sha(path).startswith(path.name.removeprefix('agy.original-')):
            removed.append(dict(path=str(path), bytes=path.stat().st_size))
            path.unlink()
    # Retain reports and recipes. Delete only recognized duplicate binaries,
    # verified against their manifests, never arbitrary files or analysis tools.
    manifests = list((toolkit / 'updates').glob('*/candidate/manifest.json'))
    manifests += list((toolkit / 'updates').glob('*/fast-*/manifest.json'))
    for manifest_path in manifests:
        old_case = manifest_path.parent.parent
        if old_case.resolve() == case.resolve():
            continue
        manifest = json.loads(manifest_path.read_text())
        for path, allowed in [(manifest_path.parent / 'agy', {manifest.get('signed_sha256'), manifest.get('unsigned_sha256')}),
                              (old_case / 'input/agy', {manifest['source_sha256']})]:
            if path.is_file() and not path.is_symlink() and sha(path) in allowed:
                removed.append(dict(path=str(path), bytes=path.stat().st_size))
                path.unlink()
    # The installed file is byte-identical to the tested candidate. The original
    # backup is the only executable copy needed for recovery.
    candidate = Path(receipt.get('candidate', case / 'missing-candidate'))
    if (candidate.parent.parent == case and candidate.parent.name.startswith('fast-')
            and candidate.is_file() and not candidate.is_symlink()
            and sha(candidate) == receipt['signed_sha256']):
        removed.append(dict(path=str(candidate), bytes=candidate.stat().st_size))
        candidate.unlink()
    snapshot = case / 'input/agy'
    if snapshot.is_file() and not snapshot.is_symlink() and sha(snapshot) == receipt['source_sha256']:
        removed.append(dict(path=str(snapshot), bytes=snapshot.stat().st_size))
        snapshot.unlink()
    result = dict(removed=removed, removed_bytes=sum(row['bytes'] for row in removed),
                  preserved_backup=str(backup))
    write_json(case / 'cleanup-receipt.json', result)
    return result


def apply(case, reviewed, full_tests):
    require(reviewed, 'Read review.md, then pass --reviewed to record code review')
    case = case.resolve()
    require(case.parent == ROOT / 'updates', 'Case must be directly inside toolkit updates/')
    recipe = json.loads((case / 'recipe.proposed.json').read_text())
    plan = json.loads((case / 'analysis-plan.json').read_text())
    target = Path(plan['source'])
    if already_installed(target):
        return
    require(sha(target) == recipe['expected_sha256'] == plan['sha256'], 'Target version changed; prepare again')
    for key in ('flag_binding_verified', 'approve_branch_verified', 'x16_dead_verified'):
        recipe['review'][key] = True
    recipe['review']['note'] = 'Strict 1.3.5 pattern matched; operator reviewed review.md before apply.'
    recipe_path = case / 'recipe.fast.json'
    write_json(recipe_path, recipe)
    # Each retry gets fresh output/logs; no existing patch evidence is overwritten.
    attempt = case / ('fast-' + str(time.time_ns()))
    attempt.mkdir()
    candidate = attempt / 'agy'
    start = time.monotonic()
    patch_and_sign(target, recipe_path, candidate)
    version = run([candidate, '--version'], capture_output=True, text=True).stdout.strip()
    manifest_path = attempt / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['signed_sha256'] = sha(candidate)
    write_json(manifest_path, manifest)
    tests = [smoke(candidate, attempt, 'print-skip')]
    if full_tests:
        tests.append(smoke(candidate, attempt, 'print-no-flag', skip=False))
        import tempfile
        with tempfile.TemporaryDirectory(prefix='agy-fast-') as tmp:
            outside = Path(tmp) / 'outside.txt'
            outside.write_text('AGY_FAST_PATCH_OK\n')
            tests.append(smoke(candidate, attempt, 'outside-skip', outside=outside))
    receipt = install(candidate, target, recipe['expected_sha256'], case)
    receipt.update(version=version, test_profile='headless-expanded' if full_tests else 'fast-one-smoke',
                   tests=tests, candidate=str(candidate),
                   elapsed_seconds=round(time.monotonic() - start, 2))
    write_json(case / 'install-receipt.json', receipt)
    cleanup_result = cleanup(receipt, case)
    write_json(ROOT / 'recipes' / ('agy-' + recipe['expected_sha256'][:12] + '.json'), recipe)
    (case / 'FAST-RESULT.md').write_text(
        f'# agy {version} patch\n\nInstalled: `{target}`\n\n'
        f'Original backup: `{receipt["backup"]}`\n\n'
        f'Tests: `{receipt["test_profile"]}`; candidate smoke passed. '
        'Installed bytes match the tested candidate; signature verified. '
        'Interactive mode was not rerun by this command.\n\n'
        f'Elapsed: {receipt["elapsed_seconds"]}s before cleanup. '
        f'Removed: {cleanup_result["removed_bytes"]} bytes.\n')
    print('Installed:', version, '\nBackup:', receipt['backup'], '\nReport:', case / 'FAST-RESULT.md')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare', help='static discovery only; no Ghidra, network or install')
    prep.add_argument('--source', type=Path, default=DEFAULT_TARGET)
    build = commands.add_parser('build-candidate', help='automatically review, patch and sign a fresh candidate')
    build.add_argument('--source', type=Path, required=True)
    build.add_argument('--out', type=Path, required=True)
    action = commands.add_parser('apply', help='sign, smoke-test, back up, install and prune old backups')
    action.add_argument('--case', type=Path, required=True)
    action.add_argument('--reviewed', action='store_true')
    action.add_argument('--extended-tests', action='store_true', help='also test no-flag and outside-workspace headless paths')
    args = parser.parse_args()
    start = time.monotonic()
    try:
        if args.command == 'prepare':
            prepare(args.source.resolve())
        elif args.command == 'build-candidate':
            build_candidate(args.source.resolve(), args.out.resolve())
        else:
            apply(args.case, args.reviewed, args.extended_tests)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'Stopped: {exc}\nFor changed layouts, follow PATCH-UPDATE.md.\n')
    print(f'Total: {time.monotonic() - start:.2f}s')


if __name__ == '__main__':
    main()
