# Reapply the patch after updating agy

## Start with the fast workflow

```sh
python3 fast_patch_update.py prepare
# Read updates/<hash>/review.md and verify the new instructions and flag binding.
python3 fast_patch_update.py apply --case updates/<hash> --reviewed
```

`prepare` uses the Go function table and LLVM to find the patch location again. It runs without Ghidra, LLM calls, or installation. It requires an exact match to the verified 1.3.5 permission check instructions, a unique flag name and binding, a reference to the auto-approval log, and no subsequent use of x16. It resolves the addresses for the current build. `review.md` lists the instructions to review manually. `--reviewed` records that the operator completed the code review.

`apply` builds and signs a copy, runs **one** RunCommand smoke test, backs up the original binary for that version, installs atomically, verifies the installed SHA-256 and signature, and removes older backups. The installed bytes are identical to the tested copy, so the default profile uses one LLM call. Each attempt has its own log. A failed test stops installation and preserves earlier backups.

The default profile runs a short smoke test. Use `--extended-tests` to add a test without the flag and a read outside the workspace, for three LLM calls total. If the instruction pattern changes or behavior differs, use the full workflow below. Keep the strict checks and verify offsets from the new build.

The case directory contains `updates/<hash>/FAST-RESULT.md`, `install-receipt.json`, and `cleanup-receipt.json`, with test logs in `fast-<attempt>/`. The current original backup is `~/.local/bin/agy.original-<hash>`. Installation removes duplicate candidate and input copies. If the installed version is already patched, `prepare` reports the existing receipt.

Run `python3 -m unittest discover -s tests -v` to verify the maintenance scripts offline. Use the full analysis below if the instruction pattern changes.

The existing approach routes the skip flag to the auto-approval branch in the shared tool confirmation handler. Resolve the patch location again for every release. Each recipe's addresses apply only to the matching SHA-256.

The patch generator writes a copy in the working directory. It leaves upstream updates and the installed version alone.

## GitHub Actions

The [agy update workflow](.github/workflows/agy-update.yml) checks the official macOS ARM64 manifest daily at about 11:17 a.m. Taiwan time. To run it manually on the default branch of the private repository, select **Actions → agy update (macOS ARM64) → Run workflow**.

This project's patch tooling and releases support Apple Silicon (ARM64). Google also distributes a separate macOS Intel (x86_64) build. [Official Intel build manifest](https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/darwin_amd64.json)

1. The workflow stops after the check if a release already has the same version and upstream archive SHA-512 prefix. A different upstream build with the same version gets a different tag.
2. For a new build, an Apple Silicon runner runs the offline tests, downloads and verifies the upstream archive, builds the patch with `build-candidate`, and verifies the ad hoc signature. If the instruction pattern changes or a check fails, use the run log and review artifact to continue with the full workflow. Only verified builds are published.
3. The private repository's Releases page provides `agy-darwin-arm64.tar.gz`, `SHA256SUMS`, `recipe.verified.json`, `review.md`, and `manifest.json`. Run `shasum -a 256 -c SHA256SUMS` after downloading to verify the files. The manifest records `static-only` validation. Section 4 describes how to test behavior on a local machine where you are signed in.

## 1. Save the updated version and prepare the analysis

Let agy update through its normal process, then run these commands in this project directory.

```sh
cd /Users/scott/Documents/agy-permission-patch
python3 prepare_patch_update.py
```

By default the script reads `~/.local/bin/agy`. It uses the first 12 characters of the SHA-256 to create `updates/<hash>/` and save a version-specific copy, the Go function index, an analysis script, and a recipe template. It stops if the directory already exists. Use `--out updates/another-name` to choose a new analysis directory.

Replace `<hash>` with the directory name printed by the script.

```sh
export AGY_CASE_DIR="$PWD/updates/<hash>"
"$AGY_CASE_DIR/analyze.sh"
```

The script uses the retained Ghidra installation and Java 21 to decompile `main.init.1`, `handleToolConfirmation`, and `MaybeLaunchCLI`. The results are in `$AGY_CASE_DIR/recovered/analysis/`, the log is in `$AGY_CASE_DIR/ghidra.log`, and `targets.json` contains the function addresses.

The preparer supports little-endian ARM64 Mach-O. The extractor relies on the Go pclntab and moduledata layouts observed in these builds. Changes to the format, function names, or inlining may cause this step to fail or omit targets. Update the analysis tools and verify offsets before continuing.

## 2. Find the patch location in the updated version

Locate the relevant logic in the pseudocode and verify it against the original ARM64 instructions. The decompiler may misidentify types and arguments.

| Recipe field | What to verify in the updated build |
| --- | --- |
| `expected_sha256` | SHA-256 of `input/agy`, populated by the preparer |
| `flag` | Address of the bool bound when `main.init.1` registers `dangerously-skip-permissions` |
| `site` | Branch insertion point in the shared `handleToolConfirmation` function, before it checks the effective permission mode |
| `original_hex` | The four original bytes at `site` in the file's little-endian order |
| `resume` | `site + 4`, where execution resumes after replaying the original instruction when the flag is absent |
| `approve` | Entry to the existing `always-proceed` branch in the same function, before that branch initializes and configures its objects |
| `cave` | At least 24 bytes of zero padding outside all existing sections in a file-backed executable segment |

`analysis-plan.json` lists possible padding at the end of a segment. Verify branch range and memory protection before choosing a location. The three `review` fields in `recipe.template.json` default to false. Set them to true only after verifying the flag binding, the auto-approval branch, and that x16 holds no live value at the insertion point.

For this disassembly command, substitute the function's new start and end addresses from `targets.json`.

```sh
/opt/homebrew/opt/llvm/bin/llvm-objdump --disassemble \
  --start-address=0xNEW_START --stop-address=0xNEW_END \
  "$AGY_CASE_DIR/input/agy"
```

The patcher can replay one **LDR X register, [register, immediate]** instruction that does not use x16. An ADRP, PC-relative load, branch, other instruction, or live x16 at the insertion point requires a different approach.

Save the completed template as `$AGY_CASE_DIR/recipe.json`. The verified example at `recipes/agy-1.2.14-a33fdf084ecd.json` applies only to its recorded SHA-256.

## 3. Build and sign a copy

```sh
python3 patch_skip_permissions.py \
  --source "$AGY_CASE_DIR/input/agy" \
  --recipe "$AGY_CASE_DIR/recipe.json" \
  --output "$AGY_CASE_DIR/candidate/agy"

codesign --force --sign - --preserve-metadata=entitlements,flags,identifier \
  "$AGY_CASE_DIR/candidate/agy"
codesign --verify --strict --verbose=2 "$AGY_CASE_DIR/candidate/agy"
```

The patcher checks the SHA-256, ARM64 format, original instruction, segment protection, padding location, and branch range. It calculates file offsets from the Mach-O segments for each build. It preserves existing output and manifest files. Use a new output directory for each retry.

These checks catch common wrong-build errors. Step 2 still requires review of the control flow. Signing changes the SHA-256 again, so record the output of `shasum -a 256 "$AGY_CASE_DIR/candidate/agy"`. The candidate uses a local ad hoc signature.

## 4. Verify both modes

First run `"$AGY_CASE_DIR/candidate/agy" --help`. Then test each mode with a harmless command.

```sh
"$AGY_CASE_DIR/candidate/agy" \
  --log-file "$AGY_CASE_DIR/print-skip.log" \
  --dangerously-skip-permissions --print-timeout 45s \
  --print 'Use RunCommand exactly once to execute: printf AGY_PATCH_OK. Reply only with the command output.'

"$AGY_CASE_DIR/candidate/agy" \
  --log-file "$AGY_CASE_DIR/interactive-skip.log" \
  --dangerously-skip-permissions \
  --prompt-interactive 'Use RunCommand exactly once to execute: printf AGY_PATCH_OK. Reply only with the command output.'
```

Run the interactive test in a real terminal. First-run workspace trust and sign-in prompts are part of normal startup. Verify that the tool request proceeds without a yes response and that the command actually returns the marker.

Both logs should contain `Always-proceed: auto-approving tool confirmation "RunCommand"` and no soft denial for that command. If a newer release changes the log wording, inspect the current confirmation behavior and actual command result.

Read a test file you created in `/private/tmp` to check whether `ViewFile` is approved automatically outside the workspace. Then run two control tests.

1. Run the updated original at `input/agy` with the skip flag. If upstream has fixed the original issue, skip the patch.
2. Run the patched copy without the skip flag and verify that normal confirmation and denial still work. Use a request that ordinarily prompts for confirmation, since an allow rule can mask the behavior.

## 5. Install after verification and keep a backup of that version

Exit all agy sessions so background updates and other agy processes cannot write to the executable during installation. Confirm that the installed SHA-256 matches `input/agy` exactly before replacing it. If agy has updated again, repeat the analysis for that version.

Run this Python installation example only after the manual verification above. It keeps a full copy of the matching original, replaces the executable atomically, and verifies the installed bytes and signature.

```sh
python3 - "$AGY_CASE_DIR" <<'PY'
import hashlib, os, shutil, subprocess, sys
from pathlib import Path
case = Path(sys.argv[1])
source, candidate = case/'input/agy', case/'candidate/agy'
installed = Path('/Users/scott/.local/bin/agy')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
digest, patched_digest = sha(source), sha(candidate)
if sha(installed) != digest:
    raise SystemExit('Installed agy changed since analysis; stop and analyze that version.')
subprocess.run(['codesign','--verify','--strict',str(candidate)],check=True)
backup = installed.with_name('agy.original-'+digest[:12])
if backup.exists():
    if sha(backup) != digest: raise SystemExit('Backup conflict; stop.')
else:
    shutil.copy2(installed,backup)
if sha(backup) != digest: raise SystemExit('Backup verification failed; stop.')
temporary = installed.with_name('agy.new-'+patched_digest[:12])
if temporary.exists(): raise SystemExit('Temporary install file exists; stop.')
shutil.copy2(candidate,temporary)
if sha(temporary) != patched_digest: raise SystemExit('Copy verification failed; stop.')
os.replace(temporary,installed)
if sha(installed) != patched_digest: raise SystemExit('Installed hash mismatch.')
subprocess.run(['codesign','--verify','--strict',str(installed)],check=True)
print('Installed:',installed)
print('Restore source:',backup)
PY
```

If the patch misbehaves, exit agy, copy the saved `agy.original-<hash>` back to `~/.local/bin/agy`, and verify its SHA-256 and signature. This backup restores the original for the updated version you patched.

`install_skip_permissions.py` and `verify_skip_permissions.py` document the installation and verification of 1.2.14. Use fresh test results for later builds.

## Initial validation

The preparer, Ghidra analysis script, and recipe patcher were first rerun against the original 1.2.14 binary. The generated unsigned binary had the same SHA-256 as the previously tested copy. A recipe with a different SHA-256 was rejected without writing output. For later releases, use the checks in Sections 2 and 4 to decide whether the method still applies.
