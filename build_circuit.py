import os
import subprocess
import re

MAX_DEPTH = 12
PTAU_FILE = 'pot16_final.ptau' # 確保這個檔案在目錄下
OUTPUT_DIR = 'compiled_circuits'

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True)

def build_circuit_for_depth(depth):
    print(f"\n{'='*40}\n🔨 正在編譯 Depth {depth} 的電路...\n{'='*40}")
    
    depth_dir = os.path.join(OUTPUT_DIR, f'd{depth}')
    os.makedirs(depth_dir, exist_ok=True)
    
    circom_filename = f"merkle_d{depth}.circom"
    
    # 1. 產生對應深度的 Circom 程式碼
    circom_code = f"""pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
template DualMux() {{
    signal input in[2]; signal input s; signal output out[2];
    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}}
template MerkleVote(levels) {{
    signal input root; signal input voter_id; signal input secret;
    signal input path_elements[levels]; signal input path_indices[levels];
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== voter_id; leafHasher.inputs[1] <== secret;
    signal leaf <== leafHasher.out;
    component hashers[levels]; component mux[levels];
    signal levelHashes[levels + 1]; levelHashes[0] <== leaf;
    for (var i = 0; i < levels; i++) {{
        path_indices[i] * (1 - path_indices[i]) === 0; 
        mux[i] = DualMux();
        mux[i].in[0] <== levelHashes[i]; mux[i].in[1] <== path_elements[i]; mux[i].s <== path_indices[i];
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0]; hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }}
    root === levelHashes[levels];
}}
component main {{public [root]}} = MerkleVote({depth});
"""
    with open(circom_filename, "w") as f:
        f.write(circom_code)

    # 2. 編譯電路 (將輸出檔案直接指定到子目錄)
    run_cmd(f"circom {circom_filename} --r1cs --wasm --sym -o {depth_dir}")
    
    # 定義檔案路徑
    r1cs_file = os.path.join(depth_dir, f"merkle_d{depth}.r1cs")
    zkey_0000 = os.path.join(depth_dir, "0000.zkey")
    zkey_final = os.path.join(depth_dir, "final.zkey")
    vkey_file = os.path.join(depth_dir, "vkey.json")
    
    # 3. 執行 SnarkJS 產生金鑰
    run_cmd(f"npx snarkjs groth16 setup {r1cs_file} {PTAU_FILE} {zkey_0000}")
    run_cmd(f'npx snarkjs zkey contribute {zkey_0000} {zkey_final} --name="Depth{depth}" -v -e="random{depth}"')
    run_cmd(f"npx snarkjs zkey export verificationkey {zkey_final} {vkey_file}")
    
    # 4. 清理暫存檔
    os.remove(zkey_0000)
    os.remove(r1cs_file)
    os.remove(os.path.join(depth_dir, f"merkle_d{depth}.sym"))
    os.remove(circom_filename)

if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # 深度 11 和 12 會跑比較久，請耐心等候
    for d in range(1, MAX_DEPTH + 1):
        build_circuit_for_depth(d)
    print(" 所有電路編譯完成，已存入 compiled_circuits 資料夾！")