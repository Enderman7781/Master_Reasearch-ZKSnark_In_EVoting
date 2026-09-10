"""Run from project folder: python test_merkle_root.py
Standard library only. Loads actual classes via AST to avoid unrelated imports.
ZKP subprocesses are simulated; these tests cover application checks, not cryptography.
"""
import ast
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def load_class(filename, name, scope):
    tree = ast.parse((ROOT / filename).read_text(encoding='utf-8-sig'))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / filename), 'exec'), scope)
    return scope[name]


scope = {'os': os, 'json': json, 'tempfile': tempfile, 'subprocess': subprocess,
         'FILE_PATH': {}, 'User': object}
Election = load_class('zk_normal.py', 'Election', scope)
Ballot = load_class('zk_normal.py', 'Ballot', scope)
System = load_class('zk_merkle.py', 'ZKMerkleVotingSystem', scope)


class MerkleRootTests(unittest.TestCase):
    def setUp(self):
        self.system = System()
        self.election = Election('synthetic', [1, 2])
        self.voter = type('SyntheticUser', (), {'hashId': 'a1'})()
        self.system.registerVoterStatus(self.election, self.voter.hashId)
        self.system.configureElectionTree(self.election, '123', 2)

    def reject(self, signals, code, depth=2):
        snapshot = copy.deepcopy((self.election.voter_registry, self.election.vote_box))
        with patch.object(self.system, 'verifyZKProof') as verifier:
            with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                self.system.castVote(self.election, self.voter, Ballot('cipher', {}, signals), depth)
            verifier.assert_not_called()
        self.assertEqual((self.election.voter_registry, self.election.vote_box), snapshot)

    def test_wrong_root(self):
        self.reject(['456'], 'MERKLE_ROOT_MISMATCH')

    def test_wrong_depth(self):
        self.reject(['123'], 'MERKLE_DEPTH_MISMATCH', 3)

    def test_missing_configuration(self):
        self.election.merkle_root = None
        self.reject(['123'], 'MERKLE_TREE_NOT_CONFIGURED')

    def test_malformed_signals(self):
        for signals in ([], ['123', '456'], [123], ['0123'], ['-1'], ['9' * 78]):
            with self.subTest(signals=signals):
                self.reject(signals, 'INVALID_PUBLIC_SIGNALS')

    def test_frozen_root(self):
        with self.assertRaisesRegex(ValueError, '^MERKLE_TREE_ALREADY_CONFIGURED$'):
            self.system.configureElectionTree(self.election, '456', 3)
        self.assertEqual((self.election.merkle_root, self.election.merkle_depth), ('123', 2))

    def test_registration_closed(self):
        before = copy.deepcopy(self.election.voter_registry)
        with self.assertRaisesRegex(ValueError, '^REGISTRATION_CLOSED$'):
            self.system.registerVoterStatus(self.election, 'another-user')
        self.assertEqual(before, self.election.voter_registry)

    def test_invalid_proof_no_state_change(self):
        with patch.object(self.system, 'verifyZKProof', return_value=False):
            with self.assertRaisesRegex(ValueError, '^ZK_VERIFICATION_FAILED$'):
                self.system.castVote(self.election, self.voter, Ballot('cipher', {}, ['123']), 2)
        self.assertFalse(self.election.voter_registry[self.voter.hashId]['has_voted'])
        self.assertEqual(self.election.vote_box, [])

    def test_valid_then_repeat(self):
        ballot = Ballot('cipher', {}, ['123'])
        with patch.object(self.system, 'verifyZKProof', return_value=True) as verifier:
            self.assertTrue(self.system.castVote(self.election, self.voter, ballot, 2))
            with self.assertRaisesRegex(ValueError, '^ALREADY_VOTED$'):
                self.system.castVote(self.election, self.voter, ballot, 2)
            verifier.assert_called_once_with({}, ['123'], 2)
        self.assertEqual(self.election.vote_box, ['cipher'])

    def test_mock_proof_not_bypassed(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'snarkjs')) as run:
            self.assertFalse(self.system.verifyZKProof({'mock': 'data'}, ['123'], 2))
            run.assert_called_once()

    def test_generation_failures_raise(self):
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                for results in ([subprocess.CalledProcessError(1, 'witness')],
                                [subprocess.CompletedProcess('witness', 0), subprocess.CalledProcessError(1, 'prove')]):
                    with self.subTest(stage=len(results)):
                        with patch.object(subprocess, 'run', side_effect=results):
                            with self.assertRaisesRegex(RuntimeError, '^ZK_PROOF_GENERATION_FAILED$') as error:
                                self.system.generateVoteProof(self.voter, '01',
                                    {'path_elements': ['0', '0'], 'path_indices': [0, 0]}, '123', 2)
                            self.assertIsInstance(error.exception.__cause__, subprocess.CalledProcessError)
            finally:
                os.chdir(original_cwd)

    def test_invalid_config_does_not_install_root(self):
        for root, depth in [('0123', 2), ('123', 0), ('123', True)]:
            with self.subTest(root=root, depth=depth):
                election = Election('new', [1, 2])
                with self.assertRaises(ValueError):
                    self.system.configureElectionTree(election, root, depth)
                self.assertIsNone(election.merkle_root)
                self.assertIsNone(election.merkle_depth)


if __name__ == '__main__':
    unittest.main(verbosity=2)
