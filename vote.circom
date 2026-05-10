pragma circom 2.0.0;

// 引入剛剛安裝的 circomlib 裡的 Poseidon 雜湊模組
include "node_modules/circomlib/circuits/poseidon.circom";

template VoteCommitment() {
    // 宣告私密輸入 (Private Inputs)：這些資料絕對不會洩漏給驗證者
    signal input voter_id;
    signal input secret;

    // 宣告公開輸出 (Public Output)：這是要對外公布的承諾 (Commitment)
    signal output commitment;

    // 實例化一個接收 2 個輸入的 Poseidon Hash 元件
    component hasher = Poseidon(2);
    
    // 把私密輸入餵給 Hash 元件
    hasher.inputs[0] <== voter_id;
    hasher.inputs[1] <== secret;

    // 將 Hash 的結果導出為公開的 commitment
    commitment <== hasher.out;
}

// 宣告主程式：指定 voter_id 和 secret 是私密的 (預設情況下 input 是 public，所以要特別標示 public {})
// 在這個架構下，我們不設定任何 public input，只設定 public output
component main = VoteCommitment();