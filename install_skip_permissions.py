#!/usr/bin/env python3
"""Install the verified candidate atomically and retain an exact original backup."""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent
subprocess.run(['python3', str(root/'verify_skip_permissions.py')], check=True)
manifest = json.loads((root/'patched/manifest.json').read_text())
target = Path('/Users/scott/.local/bin/agy')
candidate = root/'patched/agy'
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(target) == manifest['source_sha256'], 'Installed source changed; refusing to overwrite.'
assert sha(candidate) == manifest['signed_sha256']
subprocess.run(['codesign','--verify','--strict',str(candidate)], check=True)
backup = target.with_name('agy.original-'+manifest['source_sha256'][:12])
if backup.exists():
    assert sha(backup) == manifest['source_sha256'], 'Existing backup has different content.'
else:
    shutil.copy2(target, backup)
assert sha(backup) == manifest['source_sha256']
temporary = target.with_name('agy.patched-install-'+manifest['signed_sha256'][:12])
if temporary.exists(): raise SystemExit('Temporary install path already exists; refusing to overwrite.')
try:
    shutil.copy2(candidate, temporary)
    assert sha(temporary) == manifest['signed_sha256']
    os.replace(temporary, target)
finally:
    if temporary.exists(): temporary.unlink()
assert sha(target) == manifest['signed_sha256']
subprocess.run(['codesign','--verify','--strict',str(target)],check=True)
receipt = dict(installed=str(target), backup=str(backup), sha256=sha(target),
               original_sha256=sha(backup), result='installed and verified')
(root/'patched/install-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
