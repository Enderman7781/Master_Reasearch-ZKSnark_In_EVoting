"""Run from project root: python test_no_merkle_real.py
Real CLI proof generation + application's castVote; synthetic data only.
Does NOT measure performance or exercise the old generateVoteProof wrapper.
"""
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node.js not found')
    required = ['node_modules/snarkjs/build/cli.cjs', 'commitment.js',
                'no_merkle_vote_js/no_merkle_vote.wasm', 'no_merkle_vote_final.zkey',
                'vkey_no_merkle.json', 'zk_normal.py', 'zk_no_merkle.py']
    for filename in required:
        if not (root / filename).is_file():
            raise FileNotFoundError(filename)
    os.environ['PATH'] = str(root / 'node_modules/.bin') + os.pathsep + os.environ.get('PATH', '')
    from zk_normal import Election, User, Ballot
    from zk_no_merkle import ZKVotingSystem

    output = root / 'research_results' / 'smoke_no_merkle' / datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    output.mkdir(parents=True)
    cli = root / 'node_modules/snarkjs/build/cli.cjs'

    def run(args, logfile):
        result = subprocess.run([str(x) for x in args], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = result.stdout.decode('utf-8', errors='replace')
        (output / logfile).write_text(text, encoding='utf-8')
        if result.returncode:
            raise RuntimeError(f'Command failed ({result.returncode}); see {output / logfile}\n{text}')
        return text

    voter = User('SYNTHETIC_SMOKE_VOTER')
    # Publicly known synthetic inputs; never reuse them for a real election.
    input_data = {'voter_id': str(int(voter.hashId, 16)), 'secret': '2'}
    (output / 'input.json').write_text(json.dumps(input_data), encoding='utf-8')
    commitment = run([node, root / 'commitment.js', input_data['voter_id'], '2'], 'commitment.log').strip()
    print('1/4 Commitment generated.', flush=True)
    run([node, cli, 'groth16', 'fullprove', output / 'input.json',
         root / 'no_merkle_vote_js/no_merkle_vote.wasm', root / 'no_merkle_vote_final.zkey',
         output / 'proof.json', output / 'public.json'], 'prove.log')
    proof = json.loads((output / 'proof.json').read_text())
    signals = json.loads((output / 'public.json').read_text())
    if signals != [commitment]:
        raise AssertionError('Public signals do not match computed commitment')
    print('2/4 Real proof generated; commitment matches.', flush=True)
    verified = run([node, cli, 'groth16', 'verify', root / 'vkey_no_merkle.json',
                    output / 'public.json', output / 'proof.json'], 'verify.log')
    if 'OK' not in verified:
        raise AssertionError('Verifier did not report OK; inspect verify.log')
    print('3/4 Real proof verified.', flush=True)
    system = ZKVotingSystem(vkey_path='./vkey_no_merkle.json')
    election = Election('synthetic-smoke-election', [1, 2])
    system.registerVoterCommitment(election, voter.hashId, commitment)
    # Match the experiment's Base64 placeholder; this is NOT AES encryption.
    enc_vote = base64.b64encode(b'1').decode('ascii')
    ballot = Ballot(enc_vote, proof, signals)
    if not system.castVote(election, voter, ballot):
        raise AssertionError('castVote returned false')
    if election.vote_box != [enc_vote] or not election.voter_registry[voter.hashId]['has_voted']:
        raise AssertionError('Unexpected vote box or voting status')
    try:
        system.castVote(election, voter, ballot)
    except ValueError as error:
        if str(error) != 'ALREADY_VOTED':
            raise
    else:
        raise AssertionError('Repeated vote was accepted')
    if election.vote_box != [enc_vote]:
        raise AssertionError('Repeated request changed vote box')
    print('4/4 Ballot accepted once; repeated submission rejected.', flush=True)
    summary = {'status': 'passed', 'synthetic_data': True,
               'real_groth16': True, 'tested_generateVoteProof_wrapper': False,
               'performance_benchmark': False, 'ciphertext_placeholder': 'Base64, not AES',
               'node': run([node, '--version'], 'node_version.log').strip()}
    (output / 'result.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print('REAL_PROOF_SMOKE_OK')
    print(f'Results: {output}')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'FAILED: {error}', file=sys.stderr)
        sys.exit(1)
