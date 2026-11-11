# agy 靜態反編譯結果

**下次更新先跑：** `python3 fast_patch_update.py prepare`，閱讀產生的 `review.md` 後執行 `python3 fast_patch_update.py apply --case updates/<hash> --reviewed`。正常情況不需 Ghidra，只跑一次 LLM smoke test，備份／安裝／清理整合完成。詳見 [快速流程](PATCH-UPDATE.md#優先使用快速流程)；模式變更時才使用完整分析。

最新已安裝 **1.4.2（build `74935642426b`，2026-10-20）** 的 patch。快速模式的一次 RunCommand smoke test 通過，已安裝內容的 SHA256 與簽章均核對成功。唯一原檔備份：`~/.local/bin/agy.original-74935642426b`。詳見 [最新紀錄](updates/74935642426b/FAST-RESULT.md)。更早版本的原檔備份與已核實的重複執行檔已刪除。下方及各舊版目錄中的備份路徑均為歷史紀錄。

先前 **1.3.0（2026-10-07）** 的 patch 曾通過互動式、print mode、workspace 外讀取及未帶旗標的對照；詳見 [1.3.0 紀錄](updates/0e895226cb31/README.md)。1.2.17、1.2.16 的紀錄分別保留於 `updates/132ef8e1c0cb/`、`updates/7dca095cfc1d/`；以下原始分析內容與根目錄 `patched/` 仍是先前 1.2.14 的歷史資料。

已找到並分析 `/Users/scott/.local/bin/agy`。成功恢復函式索引、部分 CLI 偽碼，以及內嵌文件與範例。這是部分反編譯結果，並非完整、可重新編譯的 Go 專案。

1.2.14 當時已製作並通過互動式與 print mode 的 skip-permissions patch 測試，詳見 [歷史 patch 報告](patched/README.md)。本報告下方的原版 SHA256 與反編譯資料仍對應當時的原始執行檔；該版執行檔備份已刪除。

更新後重新定位與套用的方法在 [重新套 patch 操作流程](PATCH-UPDATE.md)，使用 `prepare_patch_update.py` 與版本專用的 recipe JSON。

## 空間使用與保留內容

1.3.5 更新時已清理舊版執行檔及重複分析專案，目前專案約 1.5 GB；清單與移除大小保存在 `updates/ebd71c4db14f/cleanup-receipt.json`。先前另已移除 Ghidra 下載 ZIP 與重複的 update-workflow 測試產物；小型紀錄與偽碼保留在 `verification/update-workflow-summary/`。

| 保留項目 | 約略大小 | 用途 |
| --- | --- | --- |
| `tools/ghidra_12.1.4_PUBLIC` | 887 MB | 直接分析未來版本，含本機 ARM64 decompiler |
| `tools/projects` | 298 MB | 已還原函式標籤的主 Ghidra 專案，方便繼續研究 |
| `updates` | 277 MB | 本版 patch 執行檔與歷次分析、驗證紀錄 |
| `patched` | 12 KB | 1.2.14 歷史報告與安裝資訊 |
| `recovered` | 26 MB | 函式索引、偽碼與內嵌文件 |
| `verification` | 224 KB | 實測日誌、結果與流程測試摘要 |

若要改成最小的備份用途，可以再將 Ghidra 與主專案移出本資料夾；但現有分析流程會需要重新安裝工具／匯入原始執行檔，不能直接刪除後期待 `analyze.sh` 照常執行。当前保留的是可以繼續研究與重新定位 patch 的配置。

## 執行檔

- 格式：Mach-O 64-bit，Apple Silicon / ARM64。
- 大小：187,281,024 bytes。
- SHA256：`a33fdf084ecd199df00694f35a243200a3efacb1f4f3adf04ca19d76f7f714c4`。
- Go build info：`go1.28-20260721-RC03 cl/951519500 +3ebc191975 X:fieldtrack,boringcrypto,simd,mapsplitgroup`。此字串直接來自執行檔，不代表公開 Go 發行版本。
- 分析全程沒有執行 agy，也沒有修改原執行檔。

## 可閱讀的產物

| 產物 | 內容 |
| --- | --- |
| [CLI 主入口](recovered/decompiled/0x102696e10_main_main.c) | `main.main` 的 C 風格反編譯偽碼 |
| [反編譯索引](recovered/decompiled/index.tsv) | 335 個函式的位址、原始 Go 名稱及偽碼檔案 |
| [全部函式](recovered/functions.tsv) | 151,297 個 Go 函式及其位址、長度 |
| [CLI 函式](recovered/app_functions.tsv) | `main` 與 `third_party/jetski/cli` 下的 5,285 個函式 |
| [來源檔路徑](recovered/source_files.txt) | 6,237 個原始來源路徑；這些是名稱，不是抽出的 Go 原始碼 |
| [CLI 來源路徑](recovered/app_source_files.txt) | 384 個 CLI 來源路徑 |
| [內嵌檔案索引](recovered/embedded_manifest.json) | 305 個檔案的來源 offset、長度、SHA256 及 descriptor 資訊 |
| [驗證紀錄](recovered/validation.json) | 輸出數量及原始 lexer XML 的解析例外 |
| [執行檔中繼資料](recovered/metadata.json) | Mach-O sections、Go build info、SHA256 |

反編譯涵蓋 `main.*`、`cli/entrypoints`、`cli/printmode`、`cli/modelresolver` 及 `cli/remotecontrol`。可查看 MCP add/remove/list、daemon start/stop/status、CLI 設定、模型後端選擇、headless 執行與 remote control 的函式。其餘模組目前提供函式索引，尚未全部反編譯。

335 個函式都由 Ghidra 成功輸出偽碼，共約 1.85 MB。另將偽碼中的 3,235 個未命名直接呼叫，以 Go 函式索引還原名稱。

## 內嵌內容

`recovered/embedded/assets` 有 27 個文件與範例檔案，包括：

- `assets/external/skills/agy-customizations`：hooks、JSON 設定、MCP、plugins、rules、skills 文件。
- `assets/external/skills/antigravity_guide`：app、CLI、IDE、SDK 文件。
- `assets/external/skills/ui-extension`：UI extension 文件，以及 `main.mjs`、`app.js`、HTML、CSS、JSON 範例。
- `assets/shared/skills`：automation、generative_ui、plugin 等文件。

另有 278 個 `embedded/*.xml`，屬於語法高亮 lexer 資料。

檔案是根據相鄰 Go embed descriptor 的路徑、指標、長度與內容結構抽出；原始 16-byte build hash 不符合標準 Go 的 SHA256 前綴，因此未聲稱通過原 build hash 驗證。每個輸出另計算 SHA256，並與原執行檔的對應 byte slice 比對。JSON 範例可解析。部分 lexer XML 本身含重複屬性，嚴格 XML parser 會拒絕；詳見驗證紀錄，抽出內容保持原始 bytes。

## 限制

偽碼中的型別、參數、Go 多值回傳及 stack growth 可能不準確，部分內容出現 `BADSPACEBASE`、`undefined` 等 Ghidra 標記。應搭配原始指令核對，不能將偽碼直接當作可編譯 C 或正確 Go 程式。內嵌 JS／HTML／CSS／文件則是直接抽出的內容。

## 重現方式

在此目錄執行：

```sh
python3 extract_agy.py
python3 extract_embedded.py
```

Ghidra 產物保存在 `tools/projects/agy.gpr`。使用 [官方 Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.1.4；為本機編譯了 ARM64 native decompiler，工具檔案均放在 `tools/`。分析 log 為 `tools/ghidra-analysis.log`。

重新輸出偽碼：

```sh
JAVA_HOME=/Users/scott/.sdkman/candidates/java/21.0.9-amzn \
PATH=/Users/scott/.sdkman/candidates/java/21.0.9-amzn/bin:$PATH \
JAVA_TOOL_OPTIONS="-Duser.home=$PWD/tools/java-home" \
tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless tools/projects agy \
  -process agy -noanalysis -scriptPath "$PWD" \
  -postScript ExportAgy.java "$PWD" -max-cpu 4
python3 annotate_pseudocode.py
```

上述命令依賴本次留下的 Ghidra project 與本機 Java 路徑。`ExportAgy.java` 保存選取範圍與輸出流程。
