pragma circom 2.0.0;
include "node_modules/circomlib/circuits/poseidon.circom";
template DualMux() {
    signal input in[2]; signal input s; signal output out[2];
    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}
template MerkleVote(levels) {
    signal input root; signal input voter_id; signal input secret;
    signal input path_elements[levels]; signal input path_indices[levels];
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== voter_id; leafHasher.inputs[1] <== secret;
    signal leaf <== leafHasher.out;
    component hashers[levels]; component mux[levels];
    signal levelHashes[levels + 1]; levelHashes[0] <== leaf;
    for (var i = 0; i < levels; i++) {
        path_indices[i] * (1 - path_indices[i]) === 0; 
        mux[i] = DualMux();
        mux[i].in[0] <== levelHashes[i]; mux[i].in[1] <== path_elements[i]; mux[i].s <== path_indices[i];
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0]; hashers[i].inputs[1] <== mux[i].out[1];
        levelHashes[i + 1] <== hashers[i].out;
    }
    root === levelHashes[levels];
}
component main {public [root]} = MerkleVote(8);
