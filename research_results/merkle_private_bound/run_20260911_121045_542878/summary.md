# R1CS 約束數實驗

資料為本次執行結果；不是歷史數據。非線性與線性約束分開記錄，總數由 snarkjs 讀取 R1CS。

## 執行條件

```json
{
  "status": "completed",
  "started_utc": "2026-09-11T04:10:45.542878+00:00",
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
  "setup_requested": true,
  "functional_tests_requested": true,
  "circuit_schema": "merkle-private-packet-binding-v1",
  "merkle_public_signals": [
    "binding",
    "root",
    "voteHash"
  ],
  "packages": {
    "snarkjs": "0.7.6",
    "circomlib": "2.0.5",
    "circomlibjs": "0.1.7"
  },
  "source_sha256": {
    "build_circuit.py": "7659726c7792d9ff182603662afe684147bd2bcd5a7f3322d3d0b24c05c4e1c1",
    "no_merkle_bound.circom": "85ef5e87c0694bca7bc32c28556e05514dd9403910c8a9fcaab4a4c15c26b93c",
    "zk_merkle.py": "6b98a90a7bb69e3d8664929444d2536893923b348d5d528a344a5af4d49776e7",
    "test_merkle_binding.py": "fcf9d5fb1bbf85027b36b5ebf8bed855b17fb8b90bb7b744dcbc68e4ddb082bf",
    "package-lock.json": "9b80b16630bbe874d00291f099ae0de08d292c788da2551f9f0e7aa8ab7e7641"
  },
  "circom": "circom compiler 2.2.3",
  "node": "v24.19.0",
  "circomlib_circuits_sha256": "f0384ee3f57a2271ad97f5df1860ddd8902e09ae9342187ddf597dcd4e063663",
  "functional_tests_passed": true
}
```

## 已完成結果

| 電路 | 樹深 | 非線性約束 | 線性約束 | R1CS 總約束 | Wires |
|---|---:|---:|---:|---:|---:|
| merkle_d1 | 1 | 733 | 822 | 1555 | 1559 |
| merkle_d2 | 2 | 980 | 1096 | 2076 | 2080 |
| merkle_d3 | 3 | 1227 | 1370 | 2597 | 2601 |
| merkle_d4 | 4 | 1474 | 1644 | 3118 | 3122 |
| merkle_d5 | 5 | 1721 | 1918 | 3639 | 3643 |
| merkle_d6 | 6 | 1968 | 2192 | 4160 | 4164 |
| merkle_d7 | 7 | 2215 | 2466 | 4681 | 4685 |
| merkle_d8 | 8 | 2462 | 2740 | 5202 | 5206 |
| merkle_d9 | 9 | 2709 | 3014 | 5723 | 5727 |
| merkle_d10 | 10 | 2956 | 3288 | 6244 | 6248 |
| merkle_d11 | 11 | 3203 | 3562 | 6765 | 6769 |
| merkle_d12 | 12 | 3450 | 3836 | 7286 | 7290 |
| merkle_d13 | 13 | 3697 | 4110 | 7807 | 7811 |
| merkle_d14 | 14 | 3944 | 4384 | 8328 | 8332 |
| merkle_d15 | 15 | 4191 | 4658 | 8849 | 8853 |
| merkle_d16 | 16 | 4438 | 4932 | 9370 | 9374 |

此表不代表證明時間或驗證時間；不同電路的驗證關係與公開資訊不同。
Merkle 公開訊號為 [binding, root, voteHash]；身分、C 與成員路徑不公開。
本版是成員資格與封包繫結證明元件，不包含匿名防重投或完整投票流程。
各子目錄保留原始電路副本、R1CS、WASM、SYM、compile.log 與 r1cs_info.log。
若執行中途失敗，本表僅列出已完成項目，請查 run_error.txt。
加上 --setup 時產生的金鑰僅供本機實驗，不能作為正式可信設定完成的證據。
