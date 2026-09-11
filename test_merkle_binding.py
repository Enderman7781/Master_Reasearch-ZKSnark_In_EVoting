"""--unit: mock-backed guards. Default: real Groth16 checks, all built depths."""
import argparse
from dataclasses import FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import zk_merkle as zk
from zk_normal import User, Election

PACKET = "MQ=="  # Base64 simulation, NOT AES ciphertext.
OTHER = "Mg=="

# Same binary Poseidon tree and zero padding as ZKMerkleTree, built in O(depth)
# for the fixture [A, B, 0, ...]. No production tree/benchmark implementation changes.
FIXTURE_JS = r"""
const {buildPoseidon} = require('circomlibjs');
(async () => {
 const x = JSON.parse(process.argv[1]);
 const p = await buildPoseidon();
 const H = (a,b) => p.F.toString(p([a,b]));
 const a = H(x.idA,x.secretA), b = H(x.idB,x.secretB);
 const zeros = ['0'];
 for(let i=1;i<x.depth;i++) zeros.push(H(zeros[i-1],zeros[i-1]));
 const siblings = [b];
 let root = H(a,b);
 for(let i=1;i<x.depth;i++) {siblings.push(zeros[i]); root=H(root,zeros[i]);}
 console.log(JSON.stringify({root, a, b, binding:H(x.secretA,x.voteHash),
   path:{path_elements:siblings,path_indices:Array(x.depth).fill(0)}}));
})().catch(e=>{console.error(e);process.exit(1)});
"""


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        folder = Path(self.tmp.name)
        (folder / 'results.json').write_text(json.dumps({
            'environment': {'circuit_schema': zk.SCHEMA}, 'results': [{'depth': 3}]
        }), encoding='utf-8')
        self.sys = zk.ZKMerkleVotingSystem(folder)
        self.context = zk.MerkleContext('123', 3)
        self.packet = zk.MerkleProofPacket(PACKET, {}, ['456', '123', zk.packet_hash(PACKET)])

    def test_changed_packet_rejected_before_crypto(self):
        packet = zk.MerkleProofPacket(OTHER, {}, self.packet.public_signals)
        with patch.object(self.sys, 'verifyZKProof') as verify:
            with self.assertRaisesRegex(ValueError, 'VOTE_HASH_MISMATCH'):
                self.sys.verifyBallotProof(self.context, packet)
            verify.assert_not_called()

    def test_wrong_root_rejected_before_crypto(self):
        with patch.object(self.sys, 'verifyZKProof') as verify:
            with self.assertRaisesRegex(ValueError, 'MERKLE_ROOT_MISMATCH'):
                self.sys.verifyBallotProof(zk.MerkleContext('124', 3), self.packet)
            verify.assert_not_called()

    def test_invalid_proof_rejected(self):
        with patch.object(self.sys, 'verifyZKProof', return_value=False):
            with self.assertRaisesRegex(ValueError, 'ZK_VERIFICATION_FAILED'):
                self.sys.verifyBallotProof(self.context, self.packet)

    def test_repeated_validation_is_stateless(self):
        with patch.object(self.sys, 'verifyZKProof', return_value=True) as verify:
            self.assertTrue(self.sys.verifyBallotProof(self.context, self.packet))
            self.assertTrue(self.sys.verifyBallotProof(self.context, self.packet))
            self.assertEqual(verify.call_count, 2)
        self.assertFalse(hasattr(self.sys, 'vote_box'))
        self.assertEqual(list(zk.MerkleProofPacket.__dataclass_fields__),
                         ['encrypted_vote', 'proof', 'public_signals'])
        self.assertEqual(list(inspect.signature(self.sys.verifyBallotProof).parameters),
                         ['context', 'packet'])

    def test_context_frozen_and_depth_checked(self):
        with self.assertRaises(FrozenInstanceError):
            self.context.root = '999'
        for depth in [0, 17, True]:
            with self.assertRaises(ValueError):
                zk.MerkleContext('123', depth)

    def test_old_cast_is_explicitly_disabled(self):
        with self.assertRaises(NotImplementedError):
            self.sys.castVote(None, None, None, 3)

    def test_registration_still_cannot_be_overwritten(self):
        election = Election('synthetic', [1, 2])
        self.sys.registerVoterStatus(election, 'synthetic')
        with self.assertRaisesRegex(ValueError, 'VOTER_ALREADY_REGISTERED'):
            self.sys.registerVoterStatus(election, 'synthetic')
        self.sys.configureElectionTree(election, '123', 3)
        with self.assertRaisesRegex(ValueError, 'REGISTRATION_CLOSED'):
            self.sys.registerVoterStatus(election, 'other')

    def test_signal_validation(self):
        for signals in [[], ['1'], ['456', '123', str(zk.FIELD)], ['456', '123', '01']]:
            with self.subTest(signals=signals):
                with self.assertRaisesRegex(ValueError, 'INVALID_PUBLIC_SIGNALS'):
                    self.sys.verifyBallotProof(self.context, zk.MerkleProofPacket(PACKET, {}, signals))

    def test_packet_hash_matches_no_merkle_framing(self):
        for packet in [PACKET, OTHER, '封包含 IV', '{"iv":"a","ciphertext":"b"}']:
            raw = packet.encode('utf-8')
            expected = str(int.from_bytes(hashlib.sha256(
                b'zk-voting:packet-binding:v1\x00' + len(raw).to_bytes(8, 'big') + raw
            ).digest(), 'big') % zk.FIELD)
            self.assertEqual(zk.packet_hash(packet), expected)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_depth(system, depth):
    voter = User('SYNTHETIC_A')
    second = User('SYNTHETIC_B')
    outsider = User('SYNTHETIC_OUTSIDER')
    secret = system.generateVoterSecret()
    secret_b = system.generateVoterSecret()
    fixture_input = {'depth': depth, 'idA': str(int(voter.hashId, 16)),
                     'idB': str(int(second.hashId, 16)), 'secretA': str(int(secret, 16)),
                     'secretB': str(int(secret_b, 16)), 'voteHash': zk.packet_hash(PACKET)}
    fixture = json.loads(zk.run_node(['-e', FIXTURE_JS, json.dumps(fixture_input)]).stdout)
    context = zk.MerkleContext(fixture['root'], depth)
    data = system.generateVoteProof(voter, secret, fixture['path'], context.root, depth, PACKET)
    proof, signals = data['proof'], data['public_signals']
    require(signals == [fixture['binding'], context.root, zk.packet_hash(PACKET)], 'Unexpected public signals')
    require(str(int(voter.hashId, 16) % zk.FIELD) not in signals and fixture['a'] not in signals,
            'Synthetic identity or C unexpectedly present in public signals')
    packet = zk.MerkleProofPacket(PACKET, proof, signals)
    require(system.verifyBallotProof(context, packet), 'Original proof rejected')

    def rejected(ctx, pkt, code):
        try:
            system.verifyBallotProof(ctx, pkt)
        except ValueError as error:
            require(str(error) == code, f'Wrong rejection: {error}')
        else:
            raise AssertionError(f'Expected {code}')

    rejected(context, zk.MerkleProofPacket(OTHER, proof, signals), 'VOTE_HASH_MISMATCH')
    changed = signals.copy()
    changed[2] = zk.packet_hash(OTHER)
    require(not system.verifyZKProof(proof, changed, depth), 'Old proof accepted changed hash')
    rejected(context, zk.MerkleProofPacket(OTHER, proof, changed), 'ZK_VERIFICATION_FAILED')
    changed_binding = signals.copy()
    changed_binding[0] = str((int(signals[0]) + 1) % zk.FIELD)
    require(not system.verifyZKProof(proof, changed_binding, depth), 'Changed binding accepted')
    wrong_root = str((int(context.root) + 1) % zk.FIELD)
    rejected(zk.MerkleContext(wrong_root, depth), packet, 'MERKLE_ROOT_MISMATCH')
    require(not system.verifyZKProof({'mock': 'data'}, signals, depth), 'Mock proof accepted')
    try:
        system.generateVoteProof(outsider, secret, fixture['path'], context.root, depth, PACKET)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Nonmember with member path generated a proof')
    bad_path = {'path_elements': fixture['path']['path_elements'].copy(),
                'path_indices': fixture['path']['path_indices'].copy()}
    bad_path['path_indices'][0] = 1
    try:
        system.generateVoteProof(voter, secret, bad_path, context.root, depth, PACKET)
    except RuntimeError:
        pass
    else:
        raise AssertionError('Wrong path generated a proof')
    # Explicitly document component scope: repeated validation remains successful.
    require(system.verifyBallotProof(context, packet), 'Stateless revalidation unexpectedly failed')
    return {'depth': depth, 'status': 'passed', 'public_signals': ['binding', 'root', 'voteHash'],
            'checks': ['original_valid', 'packet_replaced', 'packet_and_hash_replaced',
                       'binding_replaced', 'unapproved_root', 'mock_proof', 'nonmember',
                       'wrong_path', 'stateless_repeat'], 'anonymous_double_vote_prevention': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', action='store_true')
    parser.add_argument('--circuits-dir', type=Path)
    parser.add_argument('--depths', nargs='+', type=int)
    args = parser.parse_args()
    if args.unit:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests))
        return 0 if result.wasSuccessful() else 1
    system = zk.ZKMerkleVotingSystem(args.circuits_dir)
    depths = sorted(set(args.depths if args.depths else system.depths))
    rows = []
    report = system.circuits_dir / 'functional_tests.json'
    for depth in depths:
        print(f'Checking real proofs at h={depth}...', flush=True)
        try:
            rows.append(run_depth(system, depth))
        except Exception as error:
            rows.append({'depth': depth, 'status': 'failed', 'error': str(error)})
            report.write_text(json.dumps(rows, indent=2), encoding='utf-8')
            raise
        report.write_text(json.dumps(rows, indent=2), encoding='utf-8')
        print(f'  h={depth}: PASS', flush=True)
    print('MERKLE_PRIVATE_REAL_ALL_OK', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
