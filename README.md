# agy static decompilation results

**For the next update, start with** `python3 fast_patch_update.py prepare`. Read the generated `review.md`, then run `python3 fast_patch_update.py apply --case updates/<hash> --reviewed`. The usual flow needs one LLM smoke test and handles backup, installation, and cleanup in one pass. Use the [fast workflow](PATCH-UPDATE.md#start-with-the-fast-workflow) unless the instruction pattern changes and requires a full analysis.

The latest local installation recorded here is the patch for **1.4.2 (build `74935642426b`, October 20, 2026)**. One RunCommand smoke test passed, and the installed binary's SHA-256 and signature were verified. The only original binary backup is `~/.local/bin/agy.original-74935642426b`. See the [local test record](updates/74935642426b/FAST-RESULT.md). Older original backups and verified duplicate binaries were removed. Other backup paths below and in older update directories are historical.

The earlier patch for **1.3.0 (October 7, 2026)** passed interactive and print mode tests, a read outside the workspace, and a control test without the flag. See the [1.3.0 record](updates/0e895226cb31/README.md). The records for 1.2.17 and 1.2.16 are in `updates/132ef8e1c0cb/` and `updates/7dca095cfc1d/`. The original analysis below and the `patched/` directory document version 1.2.14.

The analysis of `/Users/scott/.local/bin/agy` recovered a function index, partial CLI pseudocode, and embedded documents and examples. The results cover only part of the executable and do not form a buildable Go project.

The skip-permissions patch for 1.2.14 passed interactive and print mode tests. See the [historical patch report](patched/README.md). The original SHA-256 and decompilation data below refer to that version's original binary. Its backup has been removed.

The [patch update guide](PATCH-UPDATE.md) explains how to locate and reapply the patch with `prepare_patch_update.py` and a version-specific JSON recipe.

## Local storage and retained files

During the 1.3.5 update, old binaries and duplicate analysis projects were removed, leaving about 1.5 GB in the local workspace. The file list and sizes are in `updates/ebd71c4db14f/cleanup-receipt.json`. The Ghidra download ZIP and duplicate workflow test output had already been removed. Smaller records and pseudocode remain in `verification/update-workflow-summary/`. Links to these local files require the original workspace.

| Retained item | Approximate size | Purpose |
| --- | --- | --- |
| `tools/ghidra_12.1.4_PUBLIC` | 887 MB | Ghidra with a native ARM64 decompiler for analyzing future versions |
| `tools/projects` | 298 MB | Main Ghidra project with recovered function labels |
| `updates` | 277 MB | Patched binary and historical analysis and verification records |
| `patched` | 12 KB | Historical report and installation details for 1.2.14 |
| `recovered` | 26 MB | Function indexes, pseudocode, and embedded documents |
| `verification` | 224 KB | Test logs, results, and workflow test summaries |

For a smaller backup, move Ghidra and the main project out of this directory. The analysis workflow needs those tools and the imported original binary to run `analyze.sh`, so keep them available for future analysis and patch relocation.

## Executable

- Format is Mach-O 64-bit for Apple Silicon (ARM64).
- Size is 187,281,024 bytes.
- SHA-256 is `a33fdf084ecd199df00694f35a243200a3efacb1f4f3adf04ca19d76f7f714c4`.
- The binary reports Go build info `go1.28-20260721-RC03 cl/951519500 +3ebc191975 X:fieldtrack,boringcrypto,simd,mapsplitgroup`. This string comes directly from the executable and does not identify a public Go release.
- The analysis ran without executing agy or modifying the original binary.

## Analysis output

| Output | Contents |
| --- | --- |
| [CLI entry point](recovered/decompiled/0x102696e10_main_main.c) | Decompiled C-like pseudocode for `main.main` |
| [Decompilation index](recovered/decompiled/index.tsv) | Addresses, original Go names, and pseudocode files for 335 functions |
| [All functions](recovered/functions.tsv) | Addresses and lengths for 151,297 Go functions |
| [CLI functions](recovered/app_functions.tsv) | 5,285 functions under `main` and `third_party/jetski/cli` |
| [Source file paths](recovered/source_files.txt) | 6,237 original source paths recovered as names |
| [CLI source paths](recovered/app_source_files.txt) | 384 CLI source paths |
| [Embedded file index](recovered/embedded_manifest.json) | Source offsets, lengths, SHA-256 hashes, and descriptors for 305 files |
| [Validation record](recovered/validation.json) | Output counts and parsing exceptions in the original lexer XML |
| [Executable metadata](recovered/metadata.json) | Mach-O sections, Go build info, and SHA-256 |

Decompilation covers `main.*`, `cli/entrypoints`, `cli/printmode`, `cli/modelresolver`, and `cli/remotecontrol`. It includes functions for MCP add/remove/list, daemon start/stop/status, CLI settings, model backend selection, headless execution, and remote control. The other modules are indexed and only partially decompiled.

Ghidra produced about 1.85 MB of pseudocode across 335 functions. The Go function index supplied names for 3,235 unnamed direct calls in the pseudocode.

## Embedded content

The 27 documents and example files in `recovered/embedded/assets` include the following groups.

- `assets/external/skills/agy-customizations` covers hooks, JSON settings, MCP, plugins, rules, and skills.
- `assets/external/skills/antigravity_guide` documents the app, CLI, IDE, and SDK.
- `assets/external/skills/ui-extension` contains UI extension documentation and examples in `main.mjs`, `app.js`, HTML, CSS, and JSON.
- `assets/shared/skills` includes documentation for automation, generative_ui, and plugins.

The extraction also recovered 278 syntax highlighting lexer files under `embedded/*.xml`.

Extraction used the paths, pointers, lengths, and content structure in adjacent Go embed descriptors. The original 16-byte build hash does not match the standard Go SHA-256 prefix, so the original build hash remains unverified. Each output has a separate SHA-256 and was compared with the corresponding byte range in the original executable. The JSON examples parse successfully. A strict XML parser rejects some original lexer files because they contain duplicate attributes. The validation record lists those cases, and the extracted bytes are preserved as found.

## Limitations

The pseudocode may misrepresent types, arguments, Go multiple return values, and stack growth. Some functions contain Ghidra markers such as `BADSPACEBASE` and `undefined`. Check the original instructions when interpreting the pseudocode. The embedded JS, HTML, CSS, and documentation are direct extracts.

## Reproduce the extraction

Run the following from the project directory.

```sh
python3 extract_agy.py
python3 extract_embedded.py
```

The Ghidra project is stored at `tools/projects/agy.gpr`. The analysis used [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra) with a native ARM64 decompiler built locally. The tools are in `tools/`, and the analysis log is at `tools/ghidra-analysis.log`.

To export the pseudocode again, run the following commands.

```sh
JAVA_HOME=/Users/scott/.sdkman/candidates/java/21.0.9-amzn \
PATH=/Users/scott/.sdkman/candidates/java/21.0.9-amzn/bin:$PATH \
JAVA_TOOL_OPTIONS="-Duser.home=$PWD/tools/java-home" \
tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless tools/projects agy \
  -process agy -noanalysis -scriptPath "$PWD" \
  -postScript ExportAgy.java "$PWD" -max-cpu 4
python3 annotate_pseudocode.py
```

These commands use the retained Ghidra project and a local Java installation. `ExportAgy.java` defines which functions to export and how to write the output.
