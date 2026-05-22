pragma circom 2.0.0;

// 引入你之前裝好的 Poseidon 雜湊庫
include "node_modules/circomlib/circuits/poseidon.circom";

// 輔助元件：用來根據 path_index 決定誰放左邊、誰放右邊
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0; // 確保 index 只能是 0 或 1
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

// 主電路：驗證 Merkle Tree 路徑
template MerkleVote(levels) {
    // 公開輸入
    signal input root;
    
    // 私密輸入
    signal input voter_id;
    signal input secret;
    signal input path_elements[levels];
    signal input path_indices[levels];

    // 1. 計算該選民的 Commitment (葉節點)
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== voter_id;
    leafHasher.inputs[1] <== secret;
    signal leaf <== leafHasher.out;

    // 2. 沿著 Merkle Path 一層層往上雜湊
    component hashers[levels];
    component mux[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // 確保提供的 index 是合法的布林值
        path_indices[i] * (1 - path_indices[i]) === 0; 

        // 判斷順序
        mux[i] = DualMux();
        mux[i].in[0] <== levelHashes[i];
        mux[i].in[1] <== path_elements[i];
        mux[i].s <== path_indices[i];

        // 兩兩雜湊
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    // 3. 核心約束：算出來的 Root 必須等於伺服器公布的 Root！
    root === levelHashes[levels];
}

// 宣告主程式：指定深度為 7，並宣告 root 為公開訊號
component main {public [root]} = MerkleVote(7);