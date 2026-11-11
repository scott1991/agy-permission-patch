#!/usr/bin/env python3
"""Snapshot an agy update and prepare static analysis. Never patches or installs."""
import argparse
import csv
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from patch_skip_permissions import read_layout

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, default=Path('/Users/scott/.local/bin/agy'))
parser.add_argument('--out', type=Path)
args = parser.parse_args()
toolkit = Path(__file__).resolve().parent
raw = args.source.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
segments, sections = read_layout(raw)
trial = (args.out or toolkit/'updates'/digest[:12]).resolve()
if trial.exists(): raise SystemExit('Analysis directory already exists; choose a fresh --out.')
(trial/'input').mkdir(parents=True)
binary = trial/'input/agy'
binary.write_bytes(raw)
binary.chmod(0o755)
subprocess.run([sys.executable,str(toolkit/'extract_agy.py'),str(binary),
                '--out',str(trial/'recovered')],check=True,stdout=subprocess.DEVNULL)
rows = list(csv.DictReader((trial/'recovered/functions.tsv').open(),delimiter='\t'))
selected = [r for r in rows if r['name']=='main.init.1' or r['name'].endswith('.handleToolConfirmation') or r['name'].endswith('.MaybeLaunchCLI')]
(trial/'targets.json').write_text(json.dumps(selected,indent=2)+'\n')
caves = []
for s in segments:
    if not s['prot'] & 4 or not s['length']: continue
    ends = [z for a,z in sections if s['address'] <= a < s['address']+s['size']]
    begin = max(ends) if ends else s['address']
    begin = (begin+3)//4*4
    limit = s['address']+s['length']
    if begin+24 <= limit:
        offset = s['offset']+begin-s['address']
        if raw[offset:offset+24]==bytes(24):
            caves.append(dict(address=hex(begin),offset=offset,available_bytes=limit-begin))
report = dict(source=str(args.source.resolve()), snapshot=str(binary), sha256=digest,
              targets=selected, padding_candidates=caves,
              warning='Padding is only a candidate. Flag address, branch semantics, and scratch register liveness need fresh review.')
(trial/'analysis-plan.json').write_text(json.dumps(report,indent=2)+'\n')
recipe = dict(expected_sha256=digest,site='TODO',resume='TODO',approve='TODO',flag='TODO',
              cave=caves[0]['address'] if caves else 'TODO',original_hex='TODO',
              review=dict(flag_binding_verified=False,approve_branch_verified=False,x16_dead_verified=False,
                          note='Fill from this version after disassembly review; never copy old offsets blindly.'))
(trial/'recipe.template.json').write_text(json.dumps(recipe,indent=2)+'\n')
ghidra = toolkit/'tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless'
java = Path('/Users/scott/.sdkman/candidates/java/21.0.9-amzn')
q = shlex.quote
(trial/'projects').mkdir()
(trial/'java-home').mkdir()
regex = r'.*(main\.init\.1|\.handleToolConfirmation|\.MaybeLaunchCLI)$'
script = '\n'.join([
    '#!/bin/zsh', 'set -eu',
    'export JAVA_HOME='+q(str(java)), 'export PATH="$JAVA_HOME/bin:$PATH"',
    'export JAVA_TOOL_OPTIONS='+q('-Duser.home='+str(trial/'java-home')),
    ' '.join(map(q,[str(ghidra),str(trial/'projects'),'agy-new','-import',str(binary),
        '-noanalysis','-scriptPath',str(toolkit),'-postScript','ExportAgy.java',str(trial),
        regex,'recovered/analysis','-max-cpu','4']))+' > '+q(str(trial/'ghidra.log'))+' 2>&1',
    'echo '+q('Analysis saved in '+str(trial/'recovered/analysis')), ''
])
(trial/'analyze.sh').write_text(script)
(trial/'analyze.sh').chmod(0o755)
print('Prepared:',trial)
print('SHA256:',digest)
print('Recovered target functions:',len(selected))
print('Next: run',trial/'analyze.sh')
print('Then review targets, fill recipe.template.json, and patch a fresh candidate directory.')
