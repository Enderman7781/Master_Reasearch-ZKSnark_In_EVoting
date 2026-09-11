# 論文主張、核心問題與程式修正對照

> 本文件依投稿原稿、目前交付的修補程式，以及本次對話回報的執行結果整理。用途是固定全文研究範圍、撰寫方法與限制，並追溯修補依據。不是形式化安全證明，也不是宣告完整投票系統已達到所有安全性質。
>
> 狀態截點：No-Merkle 的 `REAL_BOUND_SMOKE_OK` 已回報；Merkle 批次建置與真實功能檢查成功標記已由研究者確認。新版 `benchmark.ipynb` 已交付，但尚未收到其真實整合執行結果。API 比較尚未修補。

## 1. 目前論文究竟主張什麼

### 1.1 核心定位

**本研究以 No-Merkle 為主，研究在明確信任條件下，公開個別承諾的假名制資格驗證，與隱藏個別成員的 Merkle 成員資格證明之間，公開資訊、資格查核責任與運算成本的取捨。兩種元件均加入證明與封包的繫結。**

這不是在宣稱「移除 Merkle 後仍取得相同匿名保障」，也不是宣稱「現有 Merkle 元件已構成完整強匿名投票方案」。本次比較刻意保留兩者的公開資訊差異。

若全文保留 CLI 與常駐 API 的效能分析，應列為另一項工程層研究問題；目前仍待重新實作、驗證與量測，不能當成已完成成果。

可考慮的題目範圍：**電子投票情境下基於 Groth16 的假名制與匿名成員資格證明之成本比較**。其中「匿名成員」只描述證明與驗證介面的身分隱藏範圍，不能自動延伸為整個系統匿名。

### 1.2 可放進全文的研究定位草稿

本研究以電子投票的資格驗證需求為背景，探討公開個別承諾的 No-Merkle 方法與隱藏個別成員的 Merkle 成員資格證明之設計取捨。No-Merkle 方法以個別承諾作為假名識別資訊，將註冊資格查核交由驗證端依據認可的承諾集合執行；Merkle 方法則在零知識電路內驗證成員路徑，使驗證端可依據認可的根確認成員資格，而不需取得個別身分或承諾。

為避免資格證明與提交封包彼此獨立，本研究在兩種電路中加入以選民秘密及封包雜湊計算的繫結關係，並由驗證端對收到的封包重算雜湊。此機制的保障限定為通過檢查的證明對應該封包，不包含票面合法性、票匭完整性或端到端可驗證性。

本研究在模擬環境中建置兩種證明元件，以不同 Merkle 樹高分析 R1CS 約束數，並以一致的計時範圍量測證明生成、證明驗證與完整資格檢查的耗時。研究重點在於量化不同公開資訊與查核責任配置下的成本差異，而非認定較少約束即可全面取代具有不同隱私需求的方案。

目前實作與測試不涵蓋完整匿名防重投協定。實驗程序使用合成資料與模擬封包，測試結果不得直接等同於真實選舉部署、瀏覽器實測、高併發能力或整體系統安全性證明。

### 1.3 主張與完成狀態

| 主張 | 目前能支持的範圍 | 狀態 |
|---|---|---|
| No-Merkle 使用固定大小的資格證明電路 | 固定電路設計的約束數不隨名冊人數增加；新增繫結後仍為固定設計 | 電路已編譯，O1 總約束為 1034 |
| Merkle 隱藏個別成員 | 新電路與驗證介面不公開 voter_id、C 或路徑 | 新版 h=1～16 批次測試成功由研究者確認 |
| 證明對應提交封包 | 相同舊證明搭配被替換的封包／公開雜湊，在功能測試中遭拒絕 | 兩組已進行真實證明功能檢查 |
| 假名制與隱藏成員之成本取捨可被量化 | 比較公開資訊、外部查核及電路成本；不能宣稱相同保障下全面優越 | 方法與程式已整理，正式效能資料待量測 |
| CLI 與常駐 API 有不同工程成本 | 必須固定電路、金鑰、輸入、計時範圍及載入方式再比較 | 尚未完成新版 API 實作與量測 |
| 全程不可連結、完整匿名投票、防重投皆已完成 | 現有元件與測試不能支持 | 不作目前論文結論 |

## 2. 符號、公開資訊與信任條件

### 2.1 修補後的證明關係

令 `id` 為送入電路的身分數值、`s` 為選民秘密、`E` 為完整封包字串。現有程式以 `hashId` 的十六進位值轉成整數作為身分輸入；電路運算位於有限域。這不是把 SHA-256 身分雜湊當作匿名通訊機制。

$$C = \operatorname{Poseidon}(id,s)$$

$$h = \operatorname{SHA256}(\mathrm{domain}\;\Vert\;\mathrm{length}(E)\;\Vert\;\mathrm{UTF8}(E)) \bmod p$$

$$B = \operatorname{Poseidon}(s,h)$$

其中長度是 UTF-8 位元組長度，以 8 bytes 大端序編碼；`p` 為程式使用的 BN254 scalar field 模數。SHA-256 在電路外計算，封包雜湊由驗證端重算比對；電路內約束的是上述 Poseidon 關係。

| 項目 | No-Merkle 修補版 | Merkle 修補版 |
|---|---|---|
| 私密輸入 | id、s | id、s、路徑元素與方向 |
| 個別承諾 C | 公開輸出 | 電路內部訊號，不公開 |
| 公開訊號順序 | `[C, B, h]` | `[B, root, h]` |
| 資格查核 | 外部確認 C 在認可集合內，再驗證承諾關係 | 電路確認成員路徑，外部確認 root 為認可的根 |
| 封包查核 | 外部重算 h，再驗證電路繫結 | 相同 |
| 本次比較的防重投 | 不執行 | 不執行 |

No-Merkle 的既有收票方法仍有身分名冊與 `has_voted` 檢查，但新版 Notebook **不呼叫它**。這是為了把兩組比較固定在資格證明元件層級，不是宣稱 No-Merkle 原型從未具有防重投功能。

### 2.2 必須寫清楚的信任條件

| 條件 | 支持什麼 | 不支持什麼 |
|---|---|---|
| 註冊程序正確審核資格、同一身分不得覆寫 C | 已註冊資料不因再次註冊而重設 | 不證明外部登入或真實身分審核已安全完成 |
| 驗證端使用可信設定選定的承諾集合或 root | 防止提交者自行指定任意資格集合 | 不能信任提交者自帶的 root 而不另行比對 |
| 秘密由證明者保管，未交給驗證者 | 使資格關係與繫結關係具有知識證明意義 | 若同一服務取得私密 witness，就不能再聲稱對該服務隱藏 witness |
| 模擬程序可同時控制證明端與驗證端 | 方便量測及功能檢查 | 不等於模擬程序本身不知道身分或秘密 |
| 原型伺服器約定不記錄身分與封包對照 | 限定條件下的資料處理政策 | 不是對惡意伺服器、請求觀察者或日誌分析者的密碼學不可連結保證 |
| 伺服器約定選舉結束後才解密 | 流程上的開票時機限制 | 若伺服器持有可用金鑰，不能只由此推導密碼學上無法提前解密 |

「註冊端與驗證端職權分立、不共謀」可以作為未來完整架構的明確假設，但目前不能因為類別或函式分開，就宣稱已驗證角色隔離。

## 3. 原本八項問題與處理總覽

| 編號 | 原本問題 | 採取的處理 | 解決程度 |
|---|---|---|---|
| 1 | 密碼學不可連結主張超出架構 | 改成公開資訊與資格證明層級的取捨，撤回全程 Decoupling 結論 | 以縮小論述範圍處理，非新增不可連結協定 |
| 2 | 信任假設與攻擊者能力不一致 | 明列可信註冊、可信 root、秘密可見範圍與不記錄／不提前解密約定 | 論文仍需同步改寫；不能宣稱對任意半可信觀察者安全 |
| 3 | 電路只證承諾，卻被描述成完整資格／選票保障 | 加入封包繫結；逐項區分電路與後端責任；保留不可覆寫註冊 | 核心功能修補已測試；票面合法性不在 ZKP 範圍 |
| 4 | Merkle 對照組混用身分收票、mock、未認可根 | 移除 mock 捷徑、檢查 root；停用帶身分的收票，改成私密成員證明元件 | 元件範圍修補完成；完整匿名收票與防重投未實作 |
| 5 | 兩組做的工作不同，卻直接宣稱全面優越 | 保留不同公開資訊，兩組加入相同封包繫結，於相同層級計時 | 比較方法已調整，正式結果尚待收集 |
| 6 | 論文描述、程式及量測不一致 | 修復 CLI 呼叫、拆分計時、逐筆／輪次紀錄、保存版本；撤回模擬等於真實部署的說法 | 新 Notebook 已交付，整合執行待確認；API 尚待修補 |
| 7 | O(1)、效能與安全成果被過度推論 | 分開電路規模與系統成本；區分非線性／總約束與功能／效能證據 | 已有新的數值與論述規則，全文仍需修正 |
| 8 | 文稿、名詞與表格不一致 | 本階段先不全面修訂；只修正會直接影響核心主張的定義 | 參考文獻、票別與排版等仍待文稿整理 |

## 4. 問題一、二：不可連結主張與信任模型

### 4.1 原稿的問題

原稿摘要、3.2 節、3.3 節、3.4 節與結論，把銷毀身分／承諾和選票之間的記憶體參照，描述成密碼學 Decoupling。原本 `castVote(election, voter, ballot)` 卻在同一呼叫收到身分與封包；收票端可在接收當下觀察其對應。

不把身分欄位寫入票匭，最多直接支持「票匭未明列身分欄位」。請求順序、名冊投票狀態、日誌、時間等仍可能提供關聯。是否能讀取票面又是另一個問題，取決於加密與金鑰權限。

### 4.2 怎麼處理

本次沒有用程式假裝消除這個問題，而是修正研究主張：No-Merkle 出示個別 C，屬於假名制資格驗證；Merkle 元件不出示身分與 C。對原型伺服器不保存關聯的要求，必須寫為信任條件，不能寫成已由密碼學保證。

對應的介面調整見第 6 節。這是「限制宣稱＋重新界定驗證介面」，不是完成匿名通訊、混票或不共謀架構。

### 4.3 必須保留的限制

公開的 `B = Poseidon(s,h)` 在同一秘密與同一封包下相同，因此重複提交可能具有可辨識標記；相同秘密及封包跨兩組使用也可能得到相同 B。B 並非選舉限定 nullifier，不提供一人一票，也不能支持跨提交不可連結。

## 5. 問題三：ZKP 實際保證什麼，以及封包繫結修補

### 5.1 原本缺口

原本證明輸入只有 `voter_id` 與 `secret`，選票另外放進 Ballot。更換 `encrypted_vote` 不會改變原有證明所驗證的承諾關係。

此外，知道承諾的開啟秘密不等於承諾已註冊；防重投也不是原本電路的工作。應逐項交代責任：

| 性質 | 實際機制 |
|---|---|
| 知道 id、secret 且符合 C | No-Merkle 電路 |
| 知道集合成員的開啟秘密與路徑 | Merkle 電路 |
| C 已被認可 | No-Merkle 外部集合查核 |
| root 已被認可 | Merkle 外部可信 context 比對 |
| 證明對應封包 | 新增 B 關係＋外部 h 重算＋Groth16 驗證 |
| 同身分不重複註冊／覆寫 | 後端名冊檢查 |
| 原 No-Merkle 原型不重投 | 後端 has_voted；不在目前元件效能比較內 |
| 候選人編號合法 | 原計票函式解碼後分類；不是電路保證 |

在這個研究中，ZKP 增加的具體作用是：驗證者不用取得 secret 本身，也可檢查提交者是否知道滿足指定承諾／成員關係的秘密。外部登入與名冊查核仍有各自責任；目前未比較簽章等其他憑證方法，因此不能再延伸成「已有登入的場景一定需要 ZKP」或「ZKP 是成本最低的資格認證方式」。

### 5.2 封包雜湊：完整字串而非明文票面

來源：`zk_no_merkle_bound.py` 的 `packet_hash()`；新版 `zk_merkle.py` 使用相同算法。

```python
def packet_hash(encrypted_vote):
    """Hash exact UTF-8 packet string; not plaintext or decoded Base64.

    All decryption metadata (e.g. IV) must be inside this string if used.
    SHA-256 is computed outside the circuit and reduced to the scalar field.
    """
    if not isinstance(encrypted_vote, str) or not encrypted_vote:
        raise ValueError("INVALID_VOTE_PACKET")
    raw = encrypted_vote.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).digest()
    return str(int.from_bytes(digest, "big") % FIELD)
```

此函式將 domain、長度及 UTF-8 封包共同雜湊，再轉成電路使用的 field element。兩組須使用完全相同的序列化與定義。

目前 Notebook 的封包是 Base64 模擬資料，**不是 AES 密文**。研究者曾回憶原設計為 AES-128/CBC，但本次未取得相應加密實作加以確認；全文不可把現在這段 Base64 程式描述為 AES 實驗。若日後採用 AES，IV、密文等解密必要欄位都應納入同一被繫結封包。

### 5.3 No-Merkle 電路：使用同一個秘密繫結封包

來源：`no_merkle_bound.circom`，完整電路如下。

```circom
pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";

// C retains the existing registration meaning. Binding uses the same secret.
template VoteCommitmentBound() {
    signal input voter_id;
    signal input secret;
    signal input voteHash;
    signal output commitment;
    signal output binding;

    component identity = Poseidon(2);
    identity.inputs[0] <== voter_id;
    identity.inputs[1] <== secret;
    commitment <== identity.out;

    component ballotBinding = Poseidon(2);
    ballotBinding.inputs[0] <== secret;
    ballotBinding.inputs[1] <== voteHash;
    binding <== ballotBinding.out;
}
// Public signals, in order: commitment, binding, voteHash.
component main {public [voteHash]} = VoteCommitmentBound();
```

此版本公開訊號為 `[commitment, binding, voteHash]`。既有 C 的註冊意義不變，新增第二個 Poseidon 有效連接私密 secret 與公開 voteHash。

這不是單純宣告一個未受約束的公開輸入，也不是已證明只需增加一條約束的最小化方案。本次已實測增加 517 條 O1 總約束；詳細數據見第 9 節。

### 5.4 證明生成端把封包雜湊送入 witness

來源：`zk_no_merkle_bound.py` 的 `generateVoteProof()`，節錄輸入準備部分；後續沿用新電路對應的 WASM 與 zkey。

```python
def generateVoteProof(self, voter, secret, encrypted_vote):
    vote_hash = packet_hash(encrypted_vote)
    with tempfile.TemporaryDirectory(prefix="nm_bound_") as tmp:
        tmp = Path(tmp)
        input_path, witness = tmp / "input.json", tmp / "witness.wtns"
        proof_path, public_path = tmp / "proof.json", tmp / "public.json"
        input_path.write_text(json.dumps({
            "voter_id": str(int(voter.hashId, 16)),
            "secret": str(int(secret, 16)), "voteHash": vote_hash
        }), encoding="utf-8")
```

`encrypted_vote` 是這次新增的必要參數。呼叫者必須用同一封包建立證明與封包物件；舊呼叫 `generateVoteProof(voter, secret)` 不適用新版。

### 5.5 驗證端必須重算雜湊，不能只信任提交者填的 h

來源：新版 `benchmark.ipynb` 的 `validate_no_merkle()`。這是目前元件比較用的假名制資格檢查，不會收票或更新狀態。

```python
def validate_no_merkle(system, approved_commitments, packet):
    # 比較用的假名制資格驗證介面；不使用具身分參數的 castVote。
    signals = packet.public_signals
    if not nm_module.valid_signals(signals):
        raise ValueError('INVALID_PUBLIC_SIGNALS')
    if signals[0] not in approved_commitments:
        raise ValueError('COMMITMENT_NOT_REGISTERED')
    if signals[2] != nm_module.packet_hash(packet.encrypted_vote):
        raise ValueError('VOTE_HASH_MISMATCH')
    if not system.verifyZKProof(packet.proof, signals):
        raise ValueError('ZK_VERIFICATION_FAILED')
    return True
```

順序為格式檢查、C 是否在認可集合、封包雜湊是否相符、真實證明驗證。提交者即使同時更換封包與 h，也不能只憑相同比對值通過；舊證明還必須能驗證新的公開訊號。

### 5.6 註冊資料不可覆寫

來源：`zk_no_merkle_bound.py` 的 `registerVoterCommitment()`。

```python
def registerVoterCommitment(self, election, voter_id_hash, commitment):
    if voter_id_hash in election.voter_registry:
        raise ValueError("VOTER_ALREADY_REGISTERED")
    return super().registerVoterCommitment(election, voter_id_hash, commitment)
```

這個 guard 避免同一身分再次註冊時，覆寫 C 或重新初始化已投票狀態。新 Merkle 註冊工具也保留重複註冊拒絕與 root 設定後關閉註冊的檢查。

這不是多執行緒或資料庫交易的並發安全證明；目前記憶體名冊測試只驗證循序呼叫情境。也不能藉此宣稱應用層已完成真實身分驗證。

### 5.7 這項修補到底換到什麼

可寫：「通過資格與封包檢查的證明對應該封包。」測試支持舊證明搭配修改封包／h 時被拒絕。

不可寫：「證明保證票面合法」「伺服器無法刪除或增補票匭」「已達 recorded-as-cast」。掌握選民秘密者仍能為另一封包產生新的證明；掌握解密金鑰者仍可能讀取票面。重新加密產生不同封包後，舊證明被拒絕是預期行為，而非這項繫結失效。

此版本亦未加入明確的 election_id 繫結。若跨選舉重用同一認可 C 或 root，不能假設封包繫結本身就排除跨選舉重放；這項保障未在本次元件範圍內完成。

## 6. 問題四：Merkle 對照組不應公開身分

### 6.1 原本的三個缺口

原先版本曾存在 mock 證明直接通過的捷徑、未比對選舉認可 root，以及匿名成員證明搭配具名 `castVote()` 的不一致。

最後一項的例子是：使用 A 的有效成員證明，請求卻帶 B 的身分，舊流程可能把 B 標成已投票。只驗證 root 無法把證明成員與 B 建立對應。

### 6.2 本次採用的處理，而非曾提過但已撤回的方案

曾提出把 C 或 voter_id 公開來對應名冊，但這會改變使用者要比較的身分隱藏差異，**此方案已撤回，未採用**。

目前採用的範圍是匿名成員資格證明元件：保留私密成員；驗證端不再接收 voter，也不扣除某個具名身分的投票資格。此處是移除不適用的具名收票操作，不是把原漏洞修成完整匿名一人一票協定。

### 6.3 Merkle 電路關鍵片段

來源：`build_circuit.py` 的 `merkle_source(depth)` 所生成電路，以下摘錄主要關係，省略原版路徑迴圈內容。

```circom
signal input root;
signal input voteHash;
signal output binding;
signal input voter_id;
signal input secret;
signal input path_elements[levels];
signal input path_indices[levels];

component leafHasher = Poseidon(2);
leafHasher.inputs[0] <== voter_id;
leafHasher.inputs[1] <== secret;
signal leaf <== leafHasher.out;

component packetBinding = Poseidon(2);
packetBinding.inputs[0] <== secret;
packetBinding.inputs[1] <== voteHash;
binding <== packetBinding.out;

// 中間使用原版 DualMux 與 hashers 計算 levelHashes。
root === levelHashes[levels];

// main 宣告位於 template 外；此處以 h=3 示意，實際由腳本生成 h=1～16。
component main {public [root, voteHash]} = MerkleVote(3);
```

上述為關鍵位置節錄，不是可獨立編譯的完整檔案。正式來源是每次建置產物中的 `merkle_dh.circom`。

### 6.4 驗證介面只接受可信 context 與封包

來源：`zk_merkle.py`。

```python
@dataclass(frozen=True)
class MerkleContext:
    root: str
    depth: int

    def __post_init__(self):
        check_depth(self.depth)
        if not valid_field(self.root):
            raise ValueError("INVALID_MERKLE_ROOT")

@dataclass(frozen=True)
class MerkleProofPacket:
    encrypted_vote: str
    proof: dict
    public_signals: list
```

```python
def verifyBallotProof(self, context, packet):
    """Identity-free, stateless verification; NOT ballot acceptance or deduplication."""
    if not isinstance(context, MerkleContext):
        raise TypeError("TRUSTED_MERKLE_CONTEXT_REQUIRED")
    if not isinstance(packet, MerkleProofPacket):
        raise TypeError("MERKLE_PROOF_PACKET_REQUIRED")
    signals = packet.public_signals
    if not valid_signals(signals):
        raise ValueError("INVALID_PUBLIC_SIGNALS")
    if signals[1] != context.root:
        raise ValueError("MERKLE_ROOT_MISMATCH")
    if signals[2] != packet_hash(packet.encrypted_vote):
        raise ValueError("VOTE_HASH_MISMATCH")
    if not self.verifyZKProof(packet.proof, signals, context.depth):
        raise ValueError("ZK_VERIFICATION_FAILED")
    return True
```

`MerkleContext` 的 root 必須由可信實驗設定選定，而不是照抄提交者任選的 root。`frozen=True` 防止一般欄位覆寫，但不是可信來源的密碼學認證；外部部署仍需明確保護設定來源。

封包類別沒有身分、C、路徑或 leaf index。舊 `Ballot` 把 `public_signals[0]` 當成 commitment，而新版 Merkle 的第一個訊號是 B，因此不得混用欄位語義。

### 6.5 明確停用舊的具名收票

來源：`zk_merkle.py`。

```python
def castVote(self, *args, **kwargs):
    raise NotImplementedError(
        "Identity-based castVote is disabled. Use verifyBallotProof(context, packet); "
        "this component does not implement anonymous double-vote prevention."
    )
```

`verifyZKProof()` 已沒有 mock 直接成功的捷徑；它會使用指定新版本與樹高的驗證金鑰執行真正的 CLI 驗證。

這個元件允許同一證明重複驗證成功，而且不改動票匭或 `has_voted`。這是無狀態驗證的定義，不應寫成已實作匿名防重投。若未來要比較完整匿名投票協定，必須另外設計選舉限定的 nullifier 等機制，且重新評估成本與安全主張。

## 7. 問題五：比較條件不同，應量化取捨而非宣稱全面勝出

### 7.1 原本推論的不足

No-Merkle 不在電路內驗證成員路徑；Merkle 需要驗證路徑。前者較少工作而更快，不能獨立證明它在所有需求下更好。原稿把「不需要某項工作」與「同等保障下全面優越」混在一起。

### 7.2 現在如何對齊

兩組都加入相同形式的封包繫結；使用同一組合成使用者、秘密與封包作為同一輪的配對輸入；量測都停在資格驗證元件層級，不混入 No-Merkle 的完整 castVote。

No-Merkle 比對認可的 C 集合；Merkle 比對認可 root 並驗證成員關係。差異仍然存在，而且必須作為研究主題清楚揭露，不能稱為兩組提供完全相同的公開資訊或匿名保障。

### 7.3 準備成本另行記錄

來源：新版 Notebook `run_experiment()` 節錄。

```python
started = time.perf_counter()
commitments = [nm.computeIdentityCommitment(voter, secret)
               for voter, secret, _ in samples]
commitments_s = time.perf_counter() - started

started = time.perf_counter()
approved = frozenset(commitments)
nm_registry_s = time.perf_counter() - started

started = time.perf_counter()
tree = ZKMerkleTree(commitments, depth)
context = MerkleContext(tree.get_root(), depth)
tree_s = time.perf_counter() - started
```

建立一次完整 Merkle 樹後，才開始該輪兩組的逐筆量測，並不是每張票都重建整棵樹。現有完整建樹使用逐次 Node.js Poseidon 呼叫；其成本只代表這個實作，不能推廣成所有 Merkle 系統都必須支付相同成本。未實作增量更新，亦不以功能測試的稀疏測試樹取代 benchmark 的完整建樹。

No-Merkle 承諾集合與 Merkle 樹的註冊／維護成本都應與電路內成本分開說明。`tree.get_path()` 目前在證明生成計時外，這個排除也必須寫入量測定義。

## 8. 問題六：量測、版本及模擬範圍

### 8.1 舊計時其實包含完整收票

原 Notebook 把 `castVote()` 的耗時存成 Avg Verify，包含查名冊、重投檢查、驗證與狀態更新。後來雖拆成 Verify call／Cast total，仍不能將 CLI 包裝函式當成純密碼學運算。

新版計時如下：

| 指標 | 計時範圍 | 明確不代表 |
|---|---|---|
| `prove_call_s` | generateVoteProof：輸入準備、witness、暫存檔及 CLI 證明生成 | 瀏覽器量測、純 prover 核心耗時 |
| `verify_call_s` | verifyZKProof：驗證資料處理、CLI 啟動及證明驗證 | 純 pairing 計時 |
| `validation_call_s` | 資格資訊比對、封包雜湊檢查及 verifyZKProof | 完整投票接收或防重投耗時 |

`validation_call_s` 包含 `verify_call_s`，兩者不能相加。證明驗證仍只執行一次。

### 8.2 同一次驗證內拆分計時

來源：新版 `benchmark.ipynb` 的 `timed_validation()`。

```python
def timed_validation(system, validate):
    # 在實際那次驗證外加計時；無論成功失敗都還原物件方法。
    original = system.verifyZKProof
    previous_instance_value = system.__dict__.get('verifyZKProof')
    had_instance_value = 'verifyZKProof' in system.__dict__
    durations = []
    def measured(*args, **kwargs):
        start = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            durations.append(time.perf_counter() - start)
    system.verifyZKProof = measured
    try:
        start = time.perf_counter()
        accepted = validate()
        total = time.perf_counter() - start
    finally:
        if had_instance_value:
            system.verifyZKProof = previous_instance_value
        else:
            del system.verifyZKProof
    if accepted is not True or len(durations) != 1:
        raise RuntimeError('資格驗證未成功，或密碼驗證呼叫次數不是一次')
    return durations[0], total
```

此處暫時包住原驗證方法，成功或例外都還原；時間包含 Python 包裝的少量成本。No-Merkle 與 Merkle 都套用同一計時方式，並檢查每次只呼叫一次驗證。

### 8.3 逐筆、輪次與執行順序

來源：新版 Notebook，節錄。

```python
TEST_AMOUNTS = [8]
ROUNDS = 2

# run_experiment() 中：
for round_no in range(1, ROUNDS + 1):
    order = ['NM', 'M'] if round_no % 2 else ['M', 'NM']
    # 每組每筆保存 prove_call_s、verify_call_s、validation_call_s。
    # 每輪依序執行 TEST_AMOUNTS；實際逐筆迴圈見 Notebook。
```

8 個樣本、2 輪只是整合確認預設。先前建議的 6 輪是平衡兩種先後順序的實務起點，不是顯著性或充分樣本數的保證。完整實驗規模要在版本固定後設定；不能把同一輪的所有票視為彼此獨立的完整實驗輪次。

目前人數順序仍固定，尚未對所有時間漂移做隨機化控制；沒有額外暖機，首筆納入結果，metadata 已記錄此設計。不能將測量視為嚴格隔離所有背景負載的純運算實驗。

| 輸出檔 | 內容 |
|---|---|
| per_vote.csv | 每筆耗時、輪次、組別與執行位置；不保存身分、秘密、C、B 或封包 |
| round_summary.csv | 每輪每組的平均、中位數、標準差、最小／最大值 |
| across_rounds.json | 各輪平均值的分布 |
| preparation.csv | 共同承諾準備、No-Merkle 集合準備、Merkle 建樹時間 |
| environment.json | 版本與產物路徑、雜湊、參數、執行狀態與環境 |

舊 Python RSS 增量不代表包含 Node.js 的總記憶體，也不是峰值。新版不把它列為正式效能指標；若論文要保留記憶體優勢主張，必須另外量測。

### 8.4 修正 Windows CLI 與混合 API 程式

新上傳的 zk_merkle.py 曾同時含 API payload 及未定義的 CLI 路徑變數，並未形成完整 API 流程。本次統一為本機 Node CLI；使用參數陣列、不依賴 shell 尋找全域 snarkjs。

來源：`zk_merkle.py` 的 `run_node()`。

```python
def run_node(args):
    try:
        return subprocess.run(["node", *map(str, args)], cwd=ROOT,
                              capture_output=True, check=True, text=True,
                              encoding="utf-8", errors="replace")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ZK_COMMAND_FAILED ({exc.returncode})\n{exc.stdout}\n{exc.stderr}") from exc
```

證明生成與驗證分別使用 TemporaryDirectory；避免共用 input.json、witness.wtns、proof.json、public.json 造成檔案互相覆寫。這個修補不代表已驗證高併發吞吐量；使用者仍須重新啟動 Notebook 核心，避免持續持有舊類別。

### 8.5 新電路、新金鑰與可追溯建置

`build_circuit.py --setup --test` 自動產生 h=1～16，保存電路、R1CS、WASM、SYM、約束數、環境與雜湊；執行 setup、local contribution、zkey verify、驗證金鑰輸出與真實功能檢查。只有成功流程才切換最新產物指向，避免程式默默使用舊 compiled_circuits。

來源：`build_circuit.py`，建置核對指令節錄。

```python
execute([node, cli, 'zkey', 'verify', r1cs, ptau, target / 'final.zkey'],
        root, target / 'zkey_verify.log')
execute([node, cli, 'zkey', 'export', 'verificationkey',
         target / 'final.zkey', target / 'vkey.json'],
        root, target / 'vkey_export.log')

vkey = json.loads((target / 'vkey.json').read_text(encoding='utf-8'))
if vkey.get('nPublic') != 3:
    raise ValueError(f'{name}: expected 3 public signals in vkey')
```

腳本亦核對 .sym 的公開訊號順序，並檢查身分、秘密、葉節點或路徑是否意外出現在公開 wire。這是結構檢查，不是匿名性的完整證明。

本地 setup／contribution 只供本研究模擬，不得寫為已完成獨立多方正式可信設定儀式。

### 8.6 API 與舊數據：尚未解決的部分

原稿 4.4 節的 CLI 2.325 秒、API 0.017 秒以下，以及 99.26% 歸因於冷啟動與 I/O 的說法，目前尚未對應到修補版的可重現實驗。研究者表示曾實測但可能未上傳紀錄；這不等於認定數字造假，但不能當作新版已驗證結論。

若保留這項貢獻，需取得目前 server.js／API 原始碼，分別確認證明生成與驗證端點、是否載入新 key、如何計時、是否重用程序與金鑰。兩種電路都可能受惠，不能把 API 工程優化當成 No-Merkle 架構本身的優勢。

沒有分段計時或控制實驗，不應把 CLI/API 總時間差全部精確歸因於 I/O，也不能稱常駐 API 已消除全部 I/O 或還原純數學時間。

### 8.7 模擬測試與實際部署

研究者已明確說明整個專案與論文以模擬測試為基礎。原稿 4.5 節等位置的真實選舉部署、完成真實選舉、證明高可用性等敘述，應改為模擬原型或功能流程展示，不能繼續引用為現場部署證據。

Python 呼叫本機 Node.js/WASM 也不是瀏覽器效能量測。若保留 React 等前端描述，需另以實際程式或操作展示支持，並與本次 CLI benchmark 分開。

## 9. 問題七：複雜度與數據該怎麼寫

### 9.1 已有明確輸出的 No-Merkle 約束數

以下為研究者貼出的 Circom 2.2.3、O1／snarkjs R1CS 統計；不是預測值。

| 指標 | 原 No-Merkle | 封包繫結版 | 增量 |
|---|---:|---:|---:|
| 非線性約束 | 243 | 486 | +243 |
| 線性約束 | 274 | 548 | +274 |
| R1CS 總約束 | 517 | 1034 | +517 |
| 公開輸入 | 0 | 1 | +1 |
| 公開輸出 | 1 | 2 | +1 |
| 私密輸入 | 2 | 2 | 0 |
| Wires | 520 | 1038 | +518 |

原稿的 243 不能在這組 O1 統計中當成 R1CS 總約束；它是非線性部分。新版本加入第二個 Poseidon，因此總約束加倍。仍可稱 C 是單一身分承諾，但不能再寫「整個新電路只執行一次 Poseidon」。

原 Merkle h=7 曾回報非線性 1972、線性 2192、總約束 4164。新 Merkle h=1～16 已確認建置成功，但本文件尚未拿到各深度 summary.md，因此不把推算值冒充最新實測表格。全文應引用新建置目錄的 summary.md／results.json。

### 9.2 可以與不可以推論的內容

| 可以表達 | 不應直接推論 |
|---|---|
| 固定設計的 No-Merkle 電路約束數不隨名冊人數改變 | 整個系統所有操作都是 O(1) |
| Merkle 電路路徑成本隨 h 增加；當 h 隨 N 約為 log2 N 變化時可討論相應成本 | 最終 Groth16 驗證一定與樹高同比增加 |
| 兩組新電路均有 3 個公開訊號，但關係與公開資訊不同 | 驗證時間必然完全相同或某組必然較快 |
| 在給定環境觀察到平均延遲差異 | 已證明高併發吞吐量、可用性或大型部署能力 |
| 篡改情境在真實功能測試遭拒絕 | 整個協定已得到完整安全性證明 |

註冊、名冊儲存、Merkle 建樹、路徑供應、程序啟動、加密與網路傳輸都有自己的成本；不能由固定電路大小推導它們全為常數。

### 9.3 已跑過的舊 benchmark 怎麼處理

8～512 人的舊 CLI 結果保留為「封包繫結前、舊收票計時版本」的探索性資料。它們支持當時版本可執行，以及觀察到的耗時現象；不能直接填入修補版的最終效能圖。

例如舊版 N=512 的 No-Merkle 生成 0.9471 秒、Merkle 1.1995 秒，是那次實驗的平均結果；不可當成新版已取得約 21% 優勢的證據。新版電路和比較介面都已改變，必須重測。

## 10. 功能測試證據與未完成工作

### 10.1 已回報的實際結果

| 項目 | 證據 | 能說明的內容 |
|---|---|---|
| 原註冊修補 | 研究者回報 5 項 registration tests 通過 | 循序測試下，重複註冊不覆寫狀態等行為 |
| 原 Merkle root／mock 修補 | 研究者回報 11 項 root tests 通過 | 當時版本的 guard 與拒絕流程；不是整套真實 ZKP 驗證 |
| No-Merkle 封包繫結 | `REAL_BOUND_SMOKE_OK` 與 5 個步驟輸出 | 原證明成功、封包與 h 替換遭拒、B 修改遭拒、原票只收一次 |
| 新 Merkle 批次 | 研究者確認顯示 `MERKLE_PRIVATE_REAL_ALL_OK`、`MERKLE_BOUND_BATCH_OK` | 依所交付批次腳本，h=1～16 的建置與功能檢查完成；逐深度 log 尚未提供給本文件 |
| 新 Notebook | 助理執行語法與 mock 流程檢查通過 | 每筆一次驗證、還原計時包裝、輪次與 CSV 順序正確；不是使用者環境中的真實整合量測 |

舊 `test_merkle_root.py` 針對舊介面，不保證可直接套用新版已停用的 castVote；新版應使用 `test_merkle_binding.py`。不同階段的測試數量不能相加後宣稱同一版本通過所有測試。

### 10.2 真實篡改測試的關鍵片段

來源：`test_merkle_binding.py` 的 `run_depth()`，先驗證原證明，再修改封包與公開 h。

```python
rejected(context, zk.MerkleProofPacket(OTHER, proof, signals), 'VOTE_HASH_MISMATCH')
changed = signals.copy()
changed[2] = zk.packet_hash(OTHER)
require(not system.verifyZKProof(proof, changed, depth), 'Old proof accepted changed hash')
rejected(context, zk.MerkleProofPacket(OTHER, proof, changed), 'ZK_VERIFICATION_FAILED')
```

這段檢查不只測後端字串相等，而是直接確認舊證明不能通過被改動的公開訊號。它仍只涵蓋指定攻擊情境，不是涵蓋所有攻擊的形式化證明。

### 10.3 接下來的必要工作

| 優先順序 | 工作 | 完成條件 |
|---|---|---|
| 1 | 確認新版 Notebook 真實整合執行 | 8 個合成樣本、2 輪成功，輸出 BOUND_COMPONENT_RUN_OK 與完整紀錄 |
| 2 | 若保留 API 貢獻，修補並確認 API | 新電路／新 key、正確端點、清楚計時與快取範圍、必要功能檢查 |
| 3 | 固定版本後正式效能量測 | 保留逐筆與跨輪資料、環境、執行順序與建置版本，依資料而非預設方向下結論 |
| 4 | 同步修改論文 | 摘要、緒論、信任模型、方法、實驗、結論均使用同一研究範圍 |

不因「可能以後需要」而現在追加 nullifier、門檻解密、公開佈告欄、抗脅迫機制或完整網路匿名層；它們屬於擴大研究範圍後的工作。若維持本次元件比較，將不涵蓋之性質明確列為限制即可。

## 11. 原稿哪些句子應替換

| 原稿方向／位置 | 建議改寫方向 |
|---|---|
| 摘要、3.2、3.3、3.4、結論：已達密碼學 Decoupling | 區分假名制資格資訊與隱藏成員證明；伺服器不保存關聯屬信任條件，不宣稱全程不可連結 |
| 3.2：未註冊者不能生成合法 ZKP | 未註冊者可能生成自己的承諾知識證明，但應無法通過外部認可集合／root 的資格檢查 |
| 3.3：單次 Poseidon 電路即可涵蓋投票保障 | C 仍為單一身分承諾；新電路另有封包繫結 Poseidon，責任分別說明 |
| 3.4、3.5：Merkle 自動提供完整 Strong Anonymity | 本研究的 Merkle 證明與驗證介面不公開成員；不推導完整匿名收票或跨提交不可連結 |
| 4.2：Constraints 固定為 243 | 指明原版 O1 非線性 243、總數 517；新版總數 1034，使用新建置結果 |
| 4.3：相同瀏覽器環境測得 0.1／0.31 秒，可擴展數萬人 | 本機 Python／Node CLI 模擬；舊數據另列來源，新版重新量測，不由延遲推導部署容量 |
| 4.4：99.26% 全是 I/O／冷啟動、API 還原純數學效能 | 未有分段證據前不精確歸因；新版 API 與量測待完成 |
| 4.5：完成真實選舉並證明高可用性 | 改為模擬環境中的原型與功能檢查，除非另取得真實部署證據 |
| 結論：全面優於傳統方案 | 依特定實驗條件報告成本差異與公開資訊取捨，承認不同安全需求 |

名詞、票別分類、文獻編號與圖表一致性依研究者指示暫不全面處理。本文件沒有重新核驗原稿列出的外部文獻，不可把上述程式功能檢查當作文獻研究的替代。

## 12. 本文件的來源與版本索引

### 12.1 來源

- [P] 研究者提供的 `TANET投稿0801_disclose (1).pdf`：尤其摘要、1、3.2～3.5、4.1～4.5、結論。原稿敘述在本文件中用來對照問題，不等於現況已支持。
- [NM] 交付的 `no_merkle_bound.circom`、`zk_no_merkle_bound.py`、`test_no_merkle_bound.py`：研究者已回報真實測試成功。
- [M] 以最新上傳 `zk_merkle(2).py`、`build_circuit(1).py` 修改後交付的 `zk_merkle.py`、`build_circuit.py`、`test_merkle_binding.py`：研究者已確認批次成功標記。
- [B] 最新交付 `benchmark.ipynb`：預設 8 個合成樣本、2 輪、元件比較；目前未收到使用者的執行結果。
- [R] 本對話貼出的 Circom/snarkjs 統計、功能測試輸出與 benchmark 結果。未提供的原始紀錄不以猜測補齊。

程式碼區塊為目前交付版本之原碼或明確標示的節錄；部分節錄省略不相關註解或上下文。不要把本說明內的片段當成完整安裝包覆寫檔案。

### 12.2 程式版本雜湊

以下 SHA-256 用於辨識本文件核對的交付檔，不表示已取得研究者電腦上所有檔案的即時狀態。

| 檔案 | SHA-256 |
|---|---|
| no_merkle_bound.circom | `85ef5e87c0694bca7bc32c28556e05514dd9403910c8a9fcaab4a4c15c26b93c` |
| zk_no_merkle_bound.py | `e27f81b9446e0ed3da725dead80c71a35fadfd6bf051d497ce6bf8508ed98f5d` |
| zk_merkle.py | `6b98a90a7bb69e3d8664929444d2536893923b348d5d528a344a5af4d49776e7` |
| build_circuit.py | `7659726c7792d9ff182603662afe684147bd2bcd5a7f3322d3d0b24c05c4e1c1` |
| test_merkle_binding.py | `fcf9d5fb1bbf85027b36b5ebf8bed855b17fb8b90bb7b744dcbc68e4ddb082bf` |
| benchmark.ipynb | `f2eb41531d9d36db40815c5a01fded27def2045a09ba703d28fac38cf5d6d4a4` |
