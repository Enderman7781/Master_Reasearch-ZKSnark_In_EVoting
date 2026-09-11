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
