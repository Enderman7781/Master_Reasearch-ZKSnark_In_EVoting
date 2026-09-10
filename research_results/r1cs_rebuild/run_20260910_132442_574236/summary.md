# R1CS 約束數實驗

資料為本次執行結果；不是歷史數據。非線性與線性約束分開記錄，總數由 snarkjs 讀取 R1CS。

## 執行條件

```json
{
  "status": "completed",
  "started_utc": "2026-09-10T05:24:42.575252+00:00",
  "platform": "Windows-11-10.0.26200-SP0",
  "python": "3.12.10",
  "optimization": "O1",
  "requested_depths": [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16
  ],
  "setup_requested": false,
  "packages": {
    "snarkjs": "0.7.6",
    "circomlib": "2.0.5",
    "circomlibjs": "0.1.7"
  },
  "source_sha256": {
    "build_circuit.py": "3680bcc23f5535a63dd6d256bd0bfe2cfa7f3a95925d087321568d3baf975c0b",
    "no_merkle_vote.circom": "bcc8bd26247fc1cf70c422f95482c47d56fa392efe6d62379605800103049c00",
    "package-lock.json": "6face790935be676a9c3b6ce243db318535465e97d68ed25b8623b1b9e299ce7"
  },
  "circom": "circom compiler 2.2.3",
  "node": "v24.19.0",
  "circomlib_circuits_sha256": "f0384ee3f57a2271ad97f5df1860ddd8902e09ae9342187ddf597dcd4e063663"
}
```

## 已完成結果

| 電路 | 樹深 | 非線性約束 | 線性約束 | R1CS 總約束 | Wires |
|---|---:|---:|---:|---:|---:|
| no_merkle | - | 243 | 274 | 517 | 520 |
| merkle_d1 | 1 | 490 | 548 | 1038 | 1041 |
| merkle_d2 | 2 | 737 | 822 | 1559 | 1562 |
| merkle_d3 | 3 | 984 | 1096 | 2080 | 2083 |
| merkle_d4 | 4 | 1231 | 1370 | 2601 | 2604 |
| merkle_d5 | 5 | 1478 | 1644 | 3122 | 3125 |
| merkle_d6 | 6 | 1725 | 1918 | 3643 | 3646 |
| merkle_d7 | 7 | 1972 | 2192 | 4164 | 4167 |
| merkle_d8 | 8 | 2219 | 2466 | 4685 | 4688 |
| merkle_d9 | 9 | 2466 | 2740 | 5206 | 5209 |
| merkle_d10 | 10 | 2713 | 3014 | 5727 | 5730 |
| merkle_d11 | 11 | 2960 | 3288 | 6248 | 6251 |
| merkle_d12 | 12 | 3207 | 3562 | 6769 | 6772 |
| merkle_d13 | 13 | 3454 | 3836 | 7290 | 7293 |
| merkle_d14 | 14 | 3701 | 4110 | 7811 | 7814 |
| merkle_d15 | 15 | 3948 | 4384 | 8332 | 8335 |
| merkle_d16 | 16 | 4195 | 4658 | 8853 | 8856 |

此表不代表證明時間或驗證時間；不同電路的驗證關係與公開資訊不同。
各子目錄保留原始電路副本、R1CS、WASM、SYM、compile.log 與 r1cs_info.log。
若執行中途失敗，本表僅列出已完成項目，請查 run_error.txt。
加上 --setup 時產生的金鑰僅供本機實驗，不能作為正式可信設定完成的證據。
