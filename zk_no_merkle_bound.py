"""Experimental ciphertext-packet binding; no ballot validity/anonymity claim."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from zk_no_merkle import ZKVotingSystem as OriginalSystem

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "research_results" / "no_merkle_bound_v1"
DOMAIN = b"zk-voting:packet-binding:v1\x00"


def packet_hash(encrypted_vote):
    """Hash exact UTF-8 packet string; not plaintext or decoded Base64.

    All decryption metadata (e.g. IV) must be inside this string if used.
    SHA-256 is computed outside the circuit and reduced to the scalar field.
    """
    if not isinstance(encrypted_vote, str) or not encrypted_vote:
        raise ValueError("INVALID_VOTE_PACKET")
    raw = encrypted_vote.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).digest()
    return str(int.from_bytes(digest, "big") % FIELD)


def valid_signals(signals):
    return isinstance(signals, list) and len(signals) == 3 and all(
        isinstance(x, str) and 1 <= len(x) <= 77 and x.isascii()
        and x.isdecimal() and str(int(x)) == x and int(x) < FIELD
        for x in signals
    )


class ZKVotingSystem(OriginalSystem):
    def __init__(self, artifact_dir=None):
        self.artifact_dir = Path(artifact_dir).resolve() if artifact_dir else ARTIFACTS
        super().__init__(str(self.artifact_dir / "vkey.json"))
        self.cli = ROOT / "node_modules" / "snarkjs" / "build" / "cli.cjs"

    @staticmethod
    def _run(args):
        try:
            return subprocess.run(
                [str(x) for x in args], cwd=ROOT, check=True,
                capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"ZK_COMMAND_FAILED ({exc.returncode})\n{exc.stdout}\n{exc.stderr}"
            ) from exc

    def computeIdentityCommitment(self, voter, secret):
        # Retains the original Poseidon(voter_id, secret) registration value.
        return self._run([
            "node", ROOT / "commitment.js", str(int(voter.hashId, 16)),
            str(int(secret, 16))
        ]).stdout.strip()

    def registerVoterCommitment(self, election, voter_id_hash, commitment):
        if voter_id_hash in election.voter_registry:
            raise ValueError("VOTER_ALREADY_REGISTERED")
        return super().registerVoterCommitment(election, voter_id_hash, commitment)

    def generateVoteProof(self, voter, secret, encrypted_vote):
        vote_hash = packet_hash(encrypted_vote)
        with tempfile.TemporaryDirectory(prefix="nm_bound_") as tmp:
            tmp = Path(tmp)
            input_path, witness = tmp / "input.json", tmp / "witness.wtns"
            proof_path, public_path = tmp / "proof.json", tmp / "public.json"
            input_path.write_text(json.dumps({
                "voter_id": str(int(voter.hashId, 16)),
                "secret": str(int(secret, 16)), "voteHash": vote_hash
            }), encoding="utf-8")
            wasm_dir = self.artifact_dir / "no_merkle_bound_js"
            self._run(["node", wasm_dir / "generate_witness.js",
                       wasm_dir / "no_merkle_bound.wasm", input_path, witness])
            self._run(["node", self.cli, "groth16", "prove",
                       self.artifact_dir / "final.zkey", witness, proof_path, public_path])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            signals = json.loads(public_path.read_text(encoding="utf-8"))
        if not valid_signals(signals) or signals[2] != vote_hash:
            raise RuntimeError("BOUND_CIRCUIT_PUBLIC_SIGNALS_MISMATCH")
        return {"proof": proof, "public_signals": signals}

    def verifyZKProof(self, proof, public_signals):
        if not isinstance(proof, dict) or not valid_signals(public_signals):
            return False
        with tempfile.TemporaryDirectory(prefix="nm_verify_") as tmp:
            tmp = Path(tmp)
            proof_path, public_path = tmp / "proof.json", tmp / "public.json"
            proof_path.write_text(json.dumps(proof), encoding="utf-8")
            public_path.write_text(json.dumps(public_signals), encoding="utf-8")
            try:
                result = self._run(["node", self.cli, "groth16", "verify",
                                    self.vkey_path, public_path, proof_path])
            except RuntimeError:
                return False
            return "OK!" in result.stdout

    def castVote(self, election, voter, ballot):
        record = election.voter_registry.get(voter.hashId)
        if record is None:
            raise ValueError("VOTER_NOT_REGISTERED")
        if record["has_voted"]:
            raise ValueError("ALREADY_VOTED")
        signals = ballot.public_signals
        if not valid_signals(signals):
            raise ValueError("INVALID_PUBLIC_SIGNALS")
        # Always use the public value verified by the proof, not a cached attribute.
        if signals[0] != record["commitment"]:
            raise ValueError("COMMITMENT_MISMATCH")
        if signals[2] != packet_hash(ballot.encrypted_vote):
            raise ValueError("VOTE_HASH_MISMATCH")
        if not self.verifyZKProof(ballot.proof, signals):
            raise ValueError("ZK_VERIFICATION_FAILED")
        # Sequential in-memory experimental flow, not a transactional database.
        record["has_voted"] = True
        election.vote_box.append(ballot.encrypted_vote)
        return True
