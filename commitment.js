// get_commitment.js
const { buildPoseidon } = require("circomlibjs");

async function main() {
    // 建立與 Circom 完全一致的 Poseidon 實例
    const poseidon = await buildPoseidon();
    
    // 從命令列讀取 Python 傳過來的 voter_id 與 secret
    const id = process.argv[2];
    const secret = process.argv[3];
    
    // 計算 Hash
    const hash = poseidon([id, secret]);
    
    // 轉換成 10 進位字串並印出，讓 Python 可以讀取
    const hashStr = poseidon.F.toString(hash);
    console.log(hashStr);
}

main();