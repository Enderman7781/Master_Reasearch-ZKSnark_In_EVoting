"""Run: python test_registration.py from the project root.

Scope: registration methods only, sequential calls, synthetic data.
Loads the actual Election class and registration methods from source using AST.
This avoids importing unrelated plotting/cryptography dependencies; method bodies
are NOT replaced or mocked. Does not exercise ZKP, casting, or concurrency.
"""
import ast
import copy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


def extract(path, class_name, method_name=None, namespace=None):
    tree = ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
    klass = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    node = klass if method_name is None else next(
        n for n in klass.body if isinstance(n, ast.FunctionDef) and n.name == method_name)
    module = ast.Module(body=[node], type_ignores=[])
    scope = {} if namespace is None else dict(namespace)
    exec(compile(ast.fix_missing_locations(module), str(path), 'exec'), scope)
    return scope[class_name if method_name is None else method_name]


Election = extract(ROOT / 'zk_normal.py', 'Election')
register_nm = extract(ROOT / 'zk_no_merkle.py', 'ZKVotingSystem',
                      'registerVoterCommitment', {'Election': Election})
register_m = extract(ROOT / 'zk_merkle.py', 'ZKMerkleVotingSystem',
                     'registerVoterStatus', {'Election': Election})


def register(mode, election, identity='synthetic-user', commitment='111'):
    if mode == 'no_merkle':
        return register_nm(None, election, identity, commitment)
    return register_m(None, election, identity)


class RegistrationTests(unittest.TestCase):
    def test_first_registration(self):
        for mode in ('no_merkle', 'merkle'):
            with self.subTest(mode=mode):
                election = Election('test', [1, 2])
                self.assertTrue(register(mode, election))
                expected = {'has_voted': False}
                if mode == 'no_merkle':
                    expected['commitment'] = '111'
                self.assertEqual(election.voter_registry, {'synthetic-user': expected})
                self.assertEqual(election.vote_box, [])

    def assert_rejected_without_mutation(self, mode, voted, new_commitment):
        election = Election('test', [1, 2])
        register(mode, election)
        record = election.voter_registry['synthetic-user']
        record['has_voted'] = voted
        if voted:
            election.vote_box.append('synthetic-encrypted-ballot')
        before = copy.deepcopy((election.voter_registry, election.vote_box))
        with self.assertRaisesRegex(ValueError, '^VOTER_ALREADY_REGISTERED$'):
            register(mode, election, commitment=new_commitment)
        self.assertEqual((election.voter_registry, election.vote_box), before)
        self.assertIs(election.voter_registry['synthetic-user'], record)

    def test_duplicate_before_voting(self):
        for mode in ('no_merkle', 'merkle'):
            for commitment in ('111', '222'):
                with self.subTest(mode=mode, commitment=commitment):
                    self.assert_rejected_without_mutation(mode, False, commitment)

    def test_duplicate_after_voting(self):
        for mode in ('no_merkle', 'merkle'):
            for commitment in ('111', '222'):
                with self.subTest(mode=mode, commitment=commitment):
                    self.assert_rejected_without_mutation(mode, True, commitment)

    def test_other_voter_can_register(self):
        for mode in ('no_merkle', 'merkle'):
            with self.subTest(mode=mode):
                election = Election('test', [1, 2])
                register(mode, election)
                original = copy.deepcopy(election.voter_registry['synthetic-user'])
                self.assertTrue(register(mode, election, 'other-user', '222'))
                self.assertEqual(len(election.voter_registry), 2)
                self.assertEqual(election.voter_registry['synthetic-user'], original)

    def test_same_user_in_different_election(self):
        for mode in ('no_merkle', 'merkle'):
            with self.subTest(mode=mode):
                first, second = Election('first', [1, 2]), Election('second', [1, 2])
                register(mode, first)
                first.voter_registry['synthetic-user']['has_voted'] = True
                self.assertTrue(register(mode, second, commitment='222'))
                self.assertTrue(first.voter_registry['synthetic-user']['has_voted'])
                self.assertFalse(second.voter_registry['synthetic-user']['has_voted'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
