"""Default: real Groth16 smoke test. --unit: backend guards with mocked verification."""
import base64
import copy
import sys
import unittest
from unittest.mock import patch
from zk_normal import Election, User, Ballot
from zk_no_merkle_bound import ZKVotingSystem, packet_hash, FIELD

PACKET = base64.b64encode(b"1").decode("ascii")
OTHER = base64.b64encode(b"2").decode("ascii")


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.system = ZKVotingSystem()
        self.user = User("SYNTHETIC_BINDING_TEST")
        self.election = Election("binding-test", [1, 2])
        self.system.registerVoterCommitment(self.election, self.user.hashId, "123")
        self.signals = ["123", "456", packet_hash(PACKET)]

    def test_changed_packet_rejected_without_state_change(self):
        with patch.object(self.system, "verifyZKProof") as verify:
            with self.assertRaisesRegex(ValueError, "VOTE_HASH_MISMATCH"):
                self.system.castVote(self.election, self.user, Ballot(OTHER, {}, self.signals))
            verify.assert_not_called()
        self.assertFalse(self.election.voter_registry[self.user.hashId]["has_voted"])
        self.assertEqual(self.election.vote_box, [])

    def test_invalid_proof_keeps_state(self):
        with patch.object(self.system, "verifyZKProof", return_value=False):
            with self.assertRaisesRegex(ValueError, "ZK_VERIFICATION_FAILED"):
                self.system.castVote(self.election, self.user, Ballot(PACKET, {}, self.signals))
        self.assertFalse(self.election.voter_registry[self.user.hashId]["has_voted"])
        self.assertEqual(self.election.vote_box, [])

    def test_public_commitment_not_cached_attribute(self):
        ballot = Ballot(PACKET, {}, ["999", "456", packet_hash(PACKET)])
        ballot.commitment = "123"
        with self.assertRaisesRegex(ValueError, "COMMITMENT_MISMATCH"):
            self.system.castVote(self.election, self.user, ballot)

    def test_accepted_once_and_registration_cannot_reset(self):
        ballot = Ballot(PACKET, {}, self.signals)
        with patch.object(self.system, "verifyZKProof", return_value=True):
            self.assertTrue(self.system.castVote(self.election, self.user, ballot))
            with self.assertRaisesRegex(ValueError, "ALREADY_VOTED"):
                self.system.castVote(self.election, self.user, ballot)
        with self.assertRaisesRegex(ValueError, "VOTER_ALREADY_REGISTERED"):
            self.system.registerVoterCommitment(self.election, self.user.hashId, "999")
        self.assertEqual(self.election.vote_box, [PACKET])

    def test_malformed_public_signals(self):
        for signals in [[], ["123"], ["123", "456", str(FIELD)],
                        ["123", "456", "01"], ["123", "456", 1]]:
            with self.subTest(signals=signals):
                with self.assertRaisesRegex(ValueError, "INVALID_PUBLIC_SIGNALS"):
                    self.system.castVote(self.election, self.user, Ballot(PACKET, {}, signals))


def real_test():
    system = ZKVotingSystem()
    voter = User("SYNTHETIC_BINDING_TEST")
    secret = system.generateVoterSecret()
    election = Election("binding-real-smoke", [1, 2])
    commitment = system.computeIdentityCommitment(voter, secret)
    system.registerVoterCommitment(election, voter.hashId, commitment)
    data = system.generateVoteProof(voter, secret, PACKET)
    proof, signals = data["proof"], data["public_signals"]
    if signals[0] != commitment or not system.verifyZKProof(proof, signals):
        raise AssertionError("Original real proof did not verify / wrong commitment order")
    print("1/5 Original real proof verified.")

    def expect_rejection(packet, public, error):
        try:
            system.castVote(election, voter, Ballot(packet, copy.deepcopy(proof), public))
        except ValueError as exc:
            if str(exc) != error:
                raise
        else:
            raise AssertionError("Tampered ballot accepted")
        if election.vote_box or election.voter_registry[voter.hashId]["has_voted"]:
            raise AssertionError("Rejected ballot changed state")

    expect_rejection(OTHER, signals.copy(), "VOTE_HASH_MISMATCH")
    print("2/5 Replaced packet rejected; state unchanged.")
    forged = signals.copy()
    forged[2] = packet_hash(OTHER)
    # Direct verification is necessary: proves this is not merely a backend hash comparison.
    if system.verifyZKProof(proof, forged):
        raise AssertionError("Old proof accepted a changed public voteHash")
    expect_rejection(OTHER, forged, "ZK_VERIFICATION_FAILED")
    print("3/5 Packet plus public hash replacement rejected by real Groth16.")
    forged_binding = signals.copy()
    forged_binding[1] = str((int(forged_binding[1]) + 1) % FIELD)
    if system.verifyZKProof(proof, forged_binding):
        raise AssertionError("Changed binding accepted")
    print("4/5 Changed public binding rejected.")
    ballot = Ballot(PACKET, proof, signals)
    if not system.castVote(election, voter, ballot):
        raise AssertionError("Original ballot not accepted")
    try:
        system.castVote(election, voter, ballot)
    except ValueError as exc:
        if str(exc) != "ALREADY_VOTED":
            raise
    else:
        raise AssertionError("Duplicate vote accepted")
    if election.vote_box != [PACKET]:
        raise AssertionError("Incorrect vote box")
    print("5/5 Original accepted once; duplicate rejected.")
    print("REAL_BOUND_SMOKE_OK")


if __name__ == "__main__":
    if "--unit" in sys.argv:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        real_test()
