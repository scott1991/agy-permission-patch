# agy 更新後重新套 patch 的流程

## 優先使用快速流程

```sh
python3 fast_patch_update.py prepare
# 閱讀輸出的 updates/<hash>/review.md，核對新版指令與旗標綁定
python3 fast_patch_update.py apply --case updates/<hash> --reviewed
```

`prepare` 不啟動 Ghidra、不呼叫 LLM、不安裝；以 Go 函式表與 LLVM 重新定位。它要求與已核對的 1.3.5 權限判斷指令完全吻合，且 flag 名稱／綁定唯一、自動批准日誌參照存在、x16 沒有後續使用；不沿用舊版絕對位址。`review.md` 集中列出需要人工判讀的指令；`--reviewed` 是操作者完成程式碼核對的紀錄，不是額外的使用者批准流程。

`apply` 一次完成產生副本、簽章、**一次** RunCommand 實測、同版原檔備份、原子安裝、已安裝 SHA256／簽章核對及舊備份清理。安裝內容和已測副本完全相同，所以預設不再呼叫 LLM 重測一次。每次嘗試有獨立日誌，失敗不會刪除舊備份；測試不通過時不安裝。

預設是快速 smoke profile，沒有重跑互動模式或完整回歸。需要時加 `--extended-tests`，額外測未帶旗標與 workspace 外讀取（共三次 LLM 呼叫）。若指令模式改變或行為異常，回到下方完整流程；不能放寬比對或猜 offset。

結果在 `updates/<hash>/FAST-RESULT.md`、`install-receipt.json`、`cleanup-receipt.json`，測試日誌在 `fast-<attempt>/`。目前版原檔備份保留於 `~/.local/bin/agy.original-<hash>`；已安裝後不再保留相同的候選執行檔與 input 副本。已經 patch 的版本再次 `prepare` 會直接回報現有收據。

維護腳本的離線驗證：`python3 -m unittest discover -s tests -v`。下方為模式改變時的完整分析流程。

可以沿用「skip 旗標直接進入共用工具確認器的既有自動批准分支」這個方法。每個新版要重新定位一次；不能只改舊設定檔的 SHA256，繼續使用舊位址。

工具只產生工作目錄中的副本，不會更新 agy、關閉自動更新，或自動取代已安裝版本。

## GitHub Actions

將 [agy update workflow](.github/workflows/agy-update.yml) 放到 GitHub 儲存庫的預設分支。第一次上傳可包含 workflow、`fast_patch_update.py`、`prepare_patch_update.py`、`extract_agy.py`、`patch_skip_permissions.py`、`tests/test_fast_patch_update.py` 和本說明。歷史執行檔、反編譯資料和 Ghidra 工具保存在本機。

1. 在 **Actions → agy candidate (macOS ARM64) → Run workflow** 啟動。`macos-15` 是 ARM64 runner，會執行離線測試、取得上游執行檔，再用 `build-candidate` 驗證並簽章。指令或呼叫路徑變更時，從 run log 和分析檔接續完整流程。
2. 如果要定期檢查，把 Actions 的 repository variable `AGY_STATIC_REVIEW_SCHEDULE` 設成 `true`。每天約在台灣時間 11:17 檢查當時的最新版，同一版仍會重新檢查。
3. 私有儲存庫的成功 run 提供含 `agy` 的 tar.gz、`recipe.verified.json`、`review.md` 和 `manifest.json`。Manifest 記錄原檔、recipe 和簽章後候選檔的 SHA256，驗證範圍為 `static-only`。下載後可核對 `signed_sha256`，用下方第 4 節的 print mode 指令在已登入的本機測試該候選檔。本機安裝可依前面的 `prepare` / `apply` 快速流程執行。

`build-candidate` 會以新快照核對完整反組譯及原始 bytes、旗標註冊的呼叫目標、自動批准路徑、x16 和補丁範圍。Actions 的候選檔流程只需官方安裝程式的下載連線，審查、產生補丁及簽章均在 runner 上執行。若要補 Intel 版，需先對上游 `x86_64` 執行檔另外分析和驗證。

## 1. 保存更新後的版本並準備分析

先讓 agy 正常更新，再到本工具目錄執行：

```sh
cd /Users/scott/Documents/agy-permission-patch
python3 prepare_patch_update.py
```

它預設讀取 `~/.local/bin/agy`，以 SHA256 前 12 碼建立 `updates/<hash>/`，保存不可混淆的新版本副本、Go 函式索引、分析腳本與 recipe 模板。如果該目錄已存在，會停止；可以用 `--out updates/another-name` 指定新的分析目錄。

請將下列變數中的 `<hash>` 換成工具輸出的實際目錄名稱：

```sh
export AGY_CASE_DIR="$PWD/updates/<hash>"
"$AGY_CASE_DIR/analyze.sh"
```

這會使用本次保留的 Ghidra 與 Java 21，反編譯 `main.init.1`、`handleToolConfirmation`、`MaybeLaunchCLI`。結果在 `$AGY_CASE_DIR/recovered/analysis/`；log 為 `$AGY_CASE_DIR/ghidra.log`，函式位址在 `targets.json`。

目前 preparer 只支援 ARM64、little-endian Mach-O，extractor 使用本次觀察到的 Go pclntab 與 moduledata layout。若新版格式變了、函式改名或被內聯，可能在這一步失敗或缺少 targets，需要先調整分析工具。失敗時不要猜 offset。

## 2. 找出新版的 patch 位置

用偽碼找邏輯，再用原始 ARM64 指令核對。偽碼中的型別與參數不一定準確。

| Recipe 欄位 | 新版中要確認的內容 |
| --- | --- |
| `expected_sha256` | `input/agy` 的 SHA256；preparer 已填入 |
| `flag` | `main.init.1` 註冊 `dangerously-skip-permissions` 時綁定的 bool 變數位址 |
| `site` | 共用 `handleToolConfirmation` 中、檢查 effective permission mode 前的跳轉插入點 |
| `original_hex` | `site` 上原本的 4 bytes，以檔案中的 little-endian 順序填入 |
| `resume` | `site + 4`，未帶旗標時重播原指令後返回的位置 |
| `approve` | 同一函式內既有 `always-proceed` 自動批准分支的入口；必須在其初始化與配置物件之前 |
| `cave` | file-backed、可執行 segment 中，所有既有 section 之外的至少 24 bytes 零值 padding |

`analysis-plan.json` 會列出尾端 padding 候選，但不能只根據零值就確定它可用。需核對 branch 距離與記憶體保護。`recipe.template.json` 的 `review` 三個欄位預設 false，必須完成確認後才改為 true：旗標綁定、自動批准分支，以及 x16 在插入點沒有需要保留的值。

核對指令的範例，請將位址換成 `targets.json` 中該函式的新版起訖位址：

```sh
/opt/homebrew/opt/llvm/bin/llvm-objdump --disassemble \
  --start-address=0xNEW_START --stop-address=0xNEW_END \
  "$AGY_CASE_DIR/input/agy"
```

本工具目前只支援重播一個 **LDR X register, [register, immediate]** 指令，且不能使用 x16。若新版插入點是 ADRP、PC-relative load、branch、其他指令，或 x16 仍有存活值，不能直接使用這個 trampoline；需要修改 patch 方法。

將填好的模板另存成 `$AGY_CASE_DIR/recipe.json`。`recipes/agy-1.2.14-a33fdf084ecd.json` 可以作為本次已驗證的範例，但它只適用於該 SHA256。

## 3. 產生副本並簽章

```sh
python3 patch_skip_permissions.py \
  --source "$AGY_CASE_DIR/input/agy" \
  --recipe "$AGY_CASE_DIR/recipe.json" \
  --output "$AGY_CASE_DIR/candidate/agy"

codesign --force --sign - --preserve-metadata=entitlements,flags,identifier \
  "$AGY_CASE_DIR/candidate/agy"
codesign --verify --strict --verbose=2 "$AGY_CASE_DIR/candidate/agy"
```

工具會檢查 SHA256、ARM64 格式、原始指令、segment 保護、空白區位置及跳轉距離。它根據 Mach-O segment 換算檔案 offset，沒有假定新版的虛擬位址與檔案 offset 差值不變。既有 output 或 manifest 不會被覆寫；重試請用新的輸出目錄。

這些機械檢查能避免常見套錯版本問題，不能代替第 2 步的邏輯判讀。簽章後 SHA256 會再變一次，記錄 `shasum -a 256 "$AGY_CASE_DIR/candidate/agy"` 的結果。簽章後的副本使用本機 ad-hoc 簽章。

## 4. 驗證兩種模式

先啟動 `"$AGY_CASE_DIR/candidate/agy" --help`。再用无害命令測試：

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

互動式必須在真正的終端執行。首次 workspace trust、登入提示仍屬正常啟動流程；驗證重點是工具 permission 不再需要 yes。確認命令實際執行且得到 marker，不能只看模型口頭說成功。

兩種模式的 log 都應看到 `Always-proceed: auto-approving tool confirmation "RunCommand"`，且不應看到該命令的 soft-deny。若新版改了 log 文案，應以新版的確認處理與實際命令結果重新判讀。

再讀取自己在 `/private/tmp` 建立的測試檔，檢查 workspace 外 `ViewFile` 是否自動批准。最後跑兩個對照：

1. 新版原檔 `input/agy` 帶 skip，確認原問題是否仍存在。若原廠已修好，就不用 patch。
2. patch 副本不帶 skip，確認正常確認／拒絕流程仍保留。對照應使用本來確實會要求確認的工具請求，避免已允許的命令規則讓結果失去意義。

## 5. 通過後安裝，保留該新版的回復檔

請先退出所有 agy sessions，避免更新或其他 agy process 同時寫入執行檔。確認 installed SHA256 與 `input/agy` 完全相同後再替換；若又更新了，就重新分析。

下面的 Python 安裝範例只在你完成上面的人工驗證後執行。它會保存這個新版的完整原檔，再原子取代，並核對安裝內容與簽章：

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

若新 patch 行為不正常，退出 agy，將這一步保留的 `agy.original-<hash>` 複製回 `~/.local/bin/agy`，再核對 SHA256 與簽章即可。此處的備份是更新後、尚未 patch 的新版，不是永遠退回 1.2.14。

原先的 `install_skip_permissions.py`、`verify_skip_permissions.py` 是本次 1.2.14 的安裝與驗證紀錄工具，不應拿舊日誌當作新版已通過測試的證据。

## 本流程目前的驗證範圍

已用 1.2.14 原版回跑 preparer、Ghidra 分析腳本與 recipe patcher；生成的 unsigned binary 與先前成功執行的版本 SHA256 完全一致。不同 SHA256 的 recipe 會被拒絕且不產生輸出。尚無真正的未來版本可測，因此新版能否延用這個方法，要依第 2 與第 4 步的結果決定。
