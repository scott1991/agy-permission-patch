#!/usr/bin/env python3
"""Static extraction of Mach-O Go pclntab metadata. Does not execute the target."""
import argparse
import collections
import csv
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('binary', nargs='?', default='/Users/scott/.local/bin/agy')
parser.add_argument('--out', default='recovered')
args = parser.parse_args()
b = Path(args.binary).read_bytes()
out = Path(args.out)
out.mkdir(parents=True, exist_ok=True)
assert b[:4] == bytes.fromhex('cffaedfe'), 'Expected little-endian Mach-O 64'
sections = []
cursor = 32
for _ in range(struct.unpack_from('<I', b, 16)[0]):
    cmd, size = struct.unpack_from('<II', b, cursor)
    if cmd == 0x19:
        for j in range(struct.unpack_from('<I', b, cursor + 64)[0]):
            s = cursor + 72 + 80 * j
            name = b[s:s+16].split(b'\0')[0].decode()
            segment = b[s+16:s+32].split(b'\0')[0].decode()
            addr, length, offset = struct.unpack_from('<QQI', b, s+32)
            sections.append(dict(name=name, segment=segment, address=addr, size=length, offset=offset))
    cursor += size
def cstr(offset):
    return b[offset:b.index(b'\0', offset)].decode('utf-8', 'replace')
def sec(name):
    return next(s for s in sections if s['name'] == name)
p = sec('__lrodata_gopcln')['offset']
assert struct.unpack_from('<I', b, p)[0] == 0xfffffff1
nfunc, nfile, text, names, cu, files, pc, table = struct.unpack_from('<8Q', b, p+8)
# cgo external linking leaves pcHeader.textStart zero; moduledata carries relocated text.
module = sec('__go_module')['offset']
text = text or struct.unpack_from('<Q', b, module+22*8)[0]
source_files = []
pos = p + files
for _ in range(nfile):
    source_files.append(cstr(pos))
    pos = b.index(b'\0', pos)+1
records = []
for i in range(nfunc):
    entry, funcoff = struct.unpack_from('<II', b, p+table+i*8)
    end = struct.unpack_from('<I', b, p+table+(i+1)*8)[0]
    f = p+table+funcoff
    nameoff = struct.unpack_from('<i', b, f+4)[0]
    name = cstr(p+names+nameoff)
    records.append(dict(address=text+entry, end=text+end, size=end-entry, name=name))
def write_tsv(path, rows):
    with path.open('w') as stream:
        writer = csv.writer(stream, delimiter='\t')
        writer.writerow(['address', 'end', 'size', 'name'])
        for r in rows:
            writer.writerow([hex(r['address']), hex(r['end']), r['size'], r['name']])
write_tsv(out/'functions.tsv', records)
app = [r for r in records if r['name'].startswith(('main.', 'google3/third_party/jetski/cli/'))]
write_tsv(out/'app_functions.tsv', app)
(out/'source_files.txt').write_text('\n'.join(source_files)+'\n')
(out/'app_source_files.txt').write_text('\n'.join(f for f in source_files if 'third_party/jetski/cli/' in f)+'\n')
info = sec('__go_buildinfo')['offset']+32
def uvarint(pos):
    value = shift = 0
    while True:
        byte = b[pos]; pos += 1
        value |= (byte & 127) << shift
        if byte < 128: return value, pos
        shift += 7
length, info = uvarint(info)
version = b[info:info+length].decode('utf-8', 'replace')
summary = dict(binary=args.binary, sha256=hashlib.sha256(b).hexdigest(), bytes=len(b),
               go_version=version, text_address=hex(text), functions=nfunc, source_files=nfile,
               app_functions=len(app), sections=sections)
(out/'metadata.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k != 'sections'}, indent=2))
print('Application function examples:')
for r in app[:20]: print(hex(r['address']), r['name'])
