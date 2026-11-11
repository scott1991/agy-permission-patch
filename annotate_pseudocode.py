#!/usr/bin/env python3
"""Resolve unnamed direct call addresses in Ghidra output using Go pclntab."""
import csv
import re
from pathlib import Path

rows = list(csv.DictReader(open('recovered/functions.tsv'), delimiter='\t'))
names = {int(r['address'], 16): re.sub(r'[^A-Za-z0-9_$]', '_', r['name']) for r in rows}
count = 0
for file in Path('recovered/decompiled').glob('*.c'):
    text = file.read_text()
    def replace(match):
        global count
        name = names.get(int(match[1], 16))
        if name: count += 1; return name
        return match[0]
    text = re.sub(r'func_0x([0-9a-fA-F]+)', replace, text)
    file.write_text(text)
print('Resolved direct call names:', count)
