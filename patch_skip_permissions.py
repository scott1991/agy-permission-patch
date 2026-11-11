#!/usr/bin/env python3
"""Create a version-locked agy test copy with a flag-gated auto-approval branch.

Only the shared CLI confirmation handler is changed. Without the explicit flag,
the original instruction and control flow are preserved. Does not install it.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

DEFAULT_RECIPE = Path(__file__).resolve().parent/'recipes/agy-1.2.14-a33fdf084ecd.json'

def require(condition, message):
    if not condition: raise ValueError(message)

def read_layout(raw):
    require(raw[:4] == bytes.fromhex('cffaedfe'), 'Expected little-endian Mach-O 64.')
    require(struct.unpack_from('<I', raw, 4)[0] == 0x0100000c, 'Expected ARM64.')
    segments, sections = [], []
    cursor = 32
    for _ in range(struct.unpack_from('<I', raw, 16)[0]):
        cmd, size = struct.unpack_from('<II', raw, cursor)
        require(size >= 8 and cursor+size <= len(raw), 'Invalid load command.')
        if cmd == 0x19:
            addr, vm_size, offset, length, _, prot, count = struct.unpack_from('<QQQQiiI', raw, cursor+24)
            segments.append(dict(address=addr, size=vm_size, offset=offset, length=length, prot=prot))
            for i in range(count):
                p = cursor+72+i*80
                a, n = struct.unpack_from('<QQ', raw, p+32)
                sections.append((a,a+n))
        cursor += size
    return segments, sections

def locate(segments, address, length, protection, file_backed=True):
    for segment in segments:
        delta = address-segment['address']
        bound = segment['length'] if file_backed else segment['size']
        if 0 <= delta and delta+length <= bound:
            require(segment['prot'] & protection, 'Address has incompatible memory protection.')
            return segment['offset']+delta if file_backed else None
    raise ValueError('Address is not in a file-backed Mach-O segment.')

def branch(pc, target):
    delta = target-pc
    require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'Branch out of range or unaligned.')
    return 0x14000000 | ((delta//4) & 0x3ffffff)

def adrp(pc, target, reg):
    pages = ((target & ~4095)-(pc & ~4095))//4096
    require(-(1 << 20) <= pages < (1 << 20), 'ADRP target out of range.')
    imm = pages & 0x1fffff
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | reg

def make_trampoline(site, resume, approve, flag, cave, original):
    # x16 is a scratch register, dead at this point of the original handler.
    # None of these instructions changes SP, LR, other registers, or NZCV.
    words = [
        adrp(cave, flag, 16),
        0x39400000 | ((flag & 4095) << 10) | (16 << 5) | 16,
        0x34000000 | (2 << 5) | 16,  # cbz w16, cave+16
        branch(cave+12, approve),
        struct.unpack('<I', original)[0],
        branch(cave+20, resume),
    ]
    return struct.pack('<6I', *words)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', default='/Users/scott/.local/bin/agy')
    parser.add_argument('--output', default='patched/agy')
    parser.add_argument('--recipe', type=Path, default=DEFAULT_RECIPE)
    args = parser.parse_args()
    src = Path(args.source)
    raw = src.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    recipe = json.loads(args.recipe.read_text())
    if actual != recipe['expected_sha256']: raise SystemExit('Unsupported binary SHA256; refusing to patch.')
    for key in ('flag_binding_verified', 'approve_branch_verified', 'x16_dead_verified'):
        require(recipe.get('review', {}).get(key) is True, 'Recipe needs code review: '+key)
    site, resume, approve, flag, cave = [int(recipe[k],0) for k in ('site','resume','approve','flag','cave')]
    original = bytes.fromhex(recipe['original_hex'])
    require(len(original)==4 and resume==site+4, 'Recipe must replay exactly one instruction.')
    instruction = int.from_bytes(original,'little')
    require(instruction & 0xffc00000 == 0xf9400000, 'Only a non-PC-relative LDR X instruction is supported.')
    require(((instruction >> 5) & 31) != 16 and (instruction & 31) != 16, 'Displaced instruction must not use scratch x16.')
    segments, sections = read_layout(raw)
    patch_offset = locate(segments,site,4,4)
    locate(segments,approve,4,4)
    locate(segments,flag,1,2,file_backed=False)
    require(raw[patch_offset:patch_offset+4] == original, 'Original instruction mismatch.')
    trampoline = make_trampoline(site,resume,approve,flag,cave,original)
    cave_offset = locate(segments,cave,len(trampoline),4)
    require(all(cave+len(trampoline)<=a or cave>=z for a,z in sections), 'Cave overlaps an existing section.')
    require(raw[cave_offset:cave_offset+len(trampoline)] == bytes(len(trampoline)), 'Cave is not empty.')
    changed = bytearray(raw)
    changed[patch_offset:patch_offset+4] = struct.pack('<I', branch(site,cave))
    changed[cave_offset:cave_offset+len(trampoline)] = trampoline
    output = Path(args.output)
    require(not output.exists() and not output.with_name('manifest.json').exists(), 'Output or manifest already exists; use a fresh directory.')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(changed)
    output.chmod(0o755)
    manifest = dict(source=str(src), output=str(output), source_sha256=actual,
        unsigned_sha256=hashlib.sha256(changed).hexdigest(),
        scope='Shared CLI store.Manager.handleToolConfirmation; both interactive and print modes',
        recipe=str(args.recipe),
        flag_address=hex(flag), patch_address=hex(site), patch_offset=patch_offset,
        original_hex=original.hex(), patched_hex=changed[patch_offset:patch_offset+4].hex(),
        trampoline_address=hex(cave), trampoline_offset=cave_offset,
        trampoline_hex=trampoline.hex(), flag_false_resume=hex(resume),
        flag_true_approve=hex(approve),
        note='Requires ad-hoc codesigning before execution on Apple Silicon; runtime tests pending.')
    output.with_name('manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))

if __name__ == '__main__': main()
