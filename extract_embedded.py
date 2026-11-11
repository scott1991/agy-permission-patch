#!/usr/bin/env python3
"""Recover embedded files from structurally validated Go embed.FS descriptors.

Google's build stores a 16-byte build hash that is not the standard Go SHA256
prefix. Preserve it separately; compute a fresh SHA256 for extracted content.
"""
import hashlib
import json
import struct
import re
from pathlib import Path, PurePosixPath

b = Path('/Users/scott/.local/bin/agy').read_bytes()
meta = json.loads(Path('recovered/metadata.json').read_text())
sections = [s for s in meta['sections'] if s['offset'] and s['size']]
def locate(addr, length):
    for s in sections:
        delta = addr - s['address']
        if 0 <= delta and delta + length <= s['size']:
            return s['offset'] + delta
    return None
dest = Path('recovered/embedded')
dest.mkdir(exist_ok=True)
manifest_path = Path('recovered/embedded_manifest.json')
# Replace only outputs listed in our previous extraction manifest.
if manifest_path.exists():
    for old in json.loads(manifest_path.read_text()):
        old_path = Path(old['file'])
        if old_path.is_relative_to(dest) and old_path.is_file(): old_path.unlink()
found = []
seen = set()
for s in sections:
    if s['name'] not in ('__rodata', '__noptrdata', '__const'): continue
    start = (s['offset']+7)//8*8
    for pos in range(start, s['offset']+s['size']-48, 8):
        np, nl, dp, dl = struct.unpack_from('<4Q', b, pos)
        if not (1 <= nl <= 300 and 1 <= dl <= 30_000_000): continue
        no = locate(np, nl)
        if no is None: continue
        raw = b[no:no+nl]
        if b'\0' in raw or b'.' not in raw: continue
        try: name = raw.decode('utf-8')
        except UnicodeDecodeError: continue
        if not name.startswith(('assets/', 'embedded/')): continue
        if not re.fullmatch(r'[A-Za-z0-9_./@+\-]+\.[A-Za-z0-9_\-]+', name): continue
        if '/' not in name: continue
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts: continue
        do = locate(dp, dl)
        if do is None: continue
        data = b[do:do+dl]
        if name.startswith('embedded/') and not data.lstrip().startswith(b'<'): continue
        digest = hashlib.sha256(data).digest()
        build_hash = b[pos+32:pos+48]
        if not any(build_hash): continue
        # Require an adjacent descriptor in the same 48-byte embed file table.
        adjacent = False
        for other in (pos-48, pos+48):
            op, ol = struct.unpack_from('<2Q', b, other)
            oo = locate(op, ol) if 1 <= ol <= 300 else None
            if oo is not None:
                try: other_name = b[oo:oo+ol].decode('ascii')
                except UnicodeDecodeError: continue
                if re.fullmatch(r'[A-Za-z0-9_./@+\-]+', other_name): adjacent = True
        if not adjacent: continue
        key = (name, digest.hex())
        if key in seen: continue
        seen.add(key)
        target = dest/path
        if target.exists() and target.read_bytes() != data:
            target = target.with_name(target.name+'.'+digest.hex()[:12])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        found.append(dict(name=name, file=str(target), bytes=dl, offset=do,
                          sha256=digest.hex(), stored_build_hash=build_hash.hex(),
                          validation='structural descriptor and adjacent file entry'))
Path('recovered/embedded_manifest.json').write_text(json.dumps(found, indent=2)+'\n')
print('Recovered structurally validated embedded files:', len(found))
for f in found[:25]: print(f['bytes'],f['name'])
