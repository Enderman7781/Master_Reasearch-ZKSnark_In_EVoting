# No-Merkle 選票繫結修補 v1

## 放置與執行

將這個壓縮檔中的 4 個程式檔與本說明解壓縮到原專案根目錄，也就是與 zk_normal.py、zk_no_merkle.py、commitment.js、node_modules、circom.exe 並列。不要只把整個資料夾放在專案裡的下一層。

原有檔案不必覆寫。本模組沿用原本的 User、Election、Ballot 與 No-Merkle 的註冊/計票結構，覆寫需要修補的方法；請保留原本兩個 Python 模組。

在專案根目錄的 PowerShell 執行：

```powershell
python .\build_no_merkle_bound.py
python .\test_no_merkle_bound.py
```

第一個指令使用本機 circom.exe、node 與 snarkjs，依序編譯 O1 R1CS/WASM/SYM、印出約束資訊、Groth16 setup、本地 contribution、核對 zkey 與輸出驗證金鑰。需要現有 pot12_final.ptau；這是本地模擬 setup，不能稱為獨立多方可信設定儀式。

成功標記分別為 BOUND_BUILD_OK 與 REAL_BOUND_SMOKE_OK。

產物統一放在 research_results/no_merkle_bound_v1，原有金鑰不會覆寫。若目錄已存在，建置會停止；要重建時先將該目錄改名保留，包含失敗的建置。新電路不能使用舊版 final.zkey 或 vkey。

## 此次修補

原本的 C = Poseidon(voter_id, secret) 不變。

新增：

- h = SHA256(domain || length || encrypted_vote 的 UTF-8 位元組) mod BN254 scalar field。
- B = Poseidon(secret, h)，由電路約束計算。
- 公開訊號固定順序為 [C, B, h]。

SHA-256 在電路外運算；收票端對實際收到的封包重算 h，然後比對公開 C 與名冊、檢查 h、驗證 Groth16，最後才更新投票狀態與寫入票匭。C 比對直接取 public_signals[0]，不信任可被另外修改的 ballot.commitment 欄位。

h 實際參與第二個 Poseidon，B 使用與 C 同一個秘密。沒有採用未受約束的公開輸入、或把 h 原樣輸出來聲稱已繫結。本設計不是唯一可能的修法；代價是新增第二個 Poseidon，不能沿用「只多一條約束」或原有耗時結論。實際約束数以 compile_O1.log 與 r1cs_info_O1.log 為準。

## 資料格式與範圍

目前 benchmark 是 Base64 模擬票，不是 AES 加密。本修補先繫結 encrypted_vote 的完整字串，沒有實作 AES。日後若用 AES，IV、密文與影響解密的其他欄位都要放入這個被繫結的封包，使用一致序列化。不能把 IV 放在未繫結的外部欄位。

保障限定：在秘密未洩漏、密碼學假設及設定成立時，通過收票檢查的證明對應該封包。它不證明票面合法、不提供票匭完整性或 recorded-as-cast、不阻止具解密權限者讀取選票，也不解決收票端可見身分的問題。

重新加密產生不同封包時，舊證明應被拒絕；這正是本修補預期行為。知道選民秘密者仍能為另一封包生成新證明，不能將本機制描述為對所有人都不可替換。此版本沒有加入 election_id 跨選舉繫結。

Merkle 版本尚未套用此修補，不能直接把新 No-Merkle 的效能與舊 Merkle 當作同等保障的正式比較。先完成其餘核心修補，再統一量測。

## 功能驗證

本次已在助理環境執行 Python 語法檢查與 5 個後端單元測試，測試中替代了密碼驗證回傳值；不等同真實 ZKP 測試。可自行重跑：

```powershell
python .\test_no_merkle_bound.py --unit
```

真實測試（不帶 --unit）使用合成身分與隨機秘密，依序檢查：

1. 原始真實證明可驗證，公開 C 與註冊承諾一致。
2. 只替換封包會拒絕，且狀態不變。
3. 同時替換封包及公開 h，舊 Groth16 證明會拒絕，且狀態不變。
4. 修改公開 B 後，舊證明會拒絕。
5. 原始選票只收一次，重投拒絕。

助理環境沒有可執行的 Circom 2 編譯器，尚未編譯此電路或完成真實證明測試。請以 Windows 的實際結果確認；不要把此包當成已完成安全稽核的投票協定。

## 後續接入 benchmark（現在先不用跑）

新介面：

```python
from zk_no_merkle_bound import ZKVotingSystem
system = ZKVotingSystem()  # 自動使用新產物；不傳舊 vkey_path
zk_data = system.generateVoteProof(voter, secret, encrypted_vote)
ballot = Ballot(encrypted_vote, zk_data['proof'], zk_data['public_signals'])
system.castVote(election, voter, ballot)
```

目前 Notebook 仍在使用舊版，不會因解壓縮而自動切換。待功能測試通過與 Merkle 比較範圍確定後再接入；本次不執行 benchmark。
