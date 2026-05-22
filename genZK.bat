@echo off
echo ===================================================
echo [1/2] Compiling No-Merkle Baseline Circuit...
echo ===================================================

circom.exe no_merkle_vote.circom --r1cs --wasm --sym

call snarkjs groth16 setup no_merkle_vote.r1cs pot16_final.ptau no_merkle_vote_0000.zkey
call snarkjs zkey contribute no_merkle_vote_0000.zkey no_merkle_vote_final.zkey --name="NoMerkle" -v -e="random_text_for_baseline_123"
call snarkjs zkey export verificationkey no_merkle_vote_final.zkey vkey_no_merkle.json

echo Cleaning up intermediate files...
del no_merkle_vote_0000.zkey no_merkle_vote.r1cs no_merkle_vote.sym

echo.
echo ===================================================
echo [2/2] Compiling Merkle Tree Circuit...
echo ===================================================

circom.exe merkle_vote.circom --r1cs --wasm --sym

call snarkjs groth16 setup merkle_vote.r1cs pot16_final.ptau merkle_vote_0000.zkey
call snarkjs zkey contribute merkle_vote_0000.zkey merkle_vote_final.zkey --name="Merkle" -v -e="random_text_for_merkle_456"
call snarkjs zkey export verificationkey merkle_vote_final.zkey vkey_merkle.json

echo Cleaning up intermediate files...
del merkle_vote_0000.zkey merkle_vote.r1cs merkle_vote.sym

echo.
echo ===================================================
echo All circuits compiled and keys generated successfully!
echo ===================================================
pause