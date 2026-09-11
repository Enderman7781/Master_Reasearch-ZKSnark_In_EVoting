"""Private Merkle membership + packet binding; not a complete voting scheme.

Proof generation is a prover-side operation; verification takes no identity.
The original identity-based castVote is deliberately disabled.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile

from zk_normal import User, Election

ROOT = Path(__file__).resolve().parent
FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SCHEMA = "merkle-private-packet-binding-v1"
DOMAIN = b"zk-voting:packet-binding:v1\x00"


def calculate_optimal_depth(num_voters):
    return max(1, (max(1, num_voters) - 1).bit_length())


def packet_hash(encrypted_vote):
    # Identical to the already tested No-Merkle bound v1 framing.
    if not isinstance(encrypted_vote, str) or not encrypted_vote:
        raise ValueError("INVALID_VOTE_PACKET")
    raw = encrypted_vote.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).digest()
    return str(int.from_bytes(digest, "big") % FIELD)


def valid_field(x):
    return (isinstance(x, str) and 1 <= len(x) <= 77 and x.isascii()
            and x.isdecimal() and str(int(x)) == x and int(x) < FIELD)


def valid_signals(signals):
    return isinstance(signals, list) and len(signals) == 3 and all(map(valid_field, signals))


def check_depth(depth):
    if type(depth) is not int or not 1 <= depth <= 16:
        raise ValueError("INVALID_MERKLE_DEPTH")


def run_node(args):
    try:
        return subprocess.run(["node", *map(str, args)], cwd=ROOT,
                              capture_output=True, check=True, text=True,
                              encoding="utf-8", errors="replace")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ZK_COMMAND_FAILED ({exc.returncode})\n{exc.stdout}\n{exc.stderr}") from exc


def poseidon_hash_2(left, right):
    return run_node([ROOT / "commitment.js", left, right]).stdout.strip()


@dataclass(frozen=True)
class MerkleContext:
    # Selected by trusted experiment setup, not supplied by the submitting voter.
    root: str
    depth: int

    def __post_init__(self):
        check_depth(self.depth)
        if not valid_field(self.root):
            raise ValueError("INVALID_MERKLE_ROOT")


@dataclass(frozen=True)
class MerkleProofPacket:
    encrypted_vote: str
    proof: dict
    public_signals: list
    # No voter identity, C, index or path; do not use the old Ballot.commitment.


class ZKMerkleTree:
    def __init__(self, leaves: list, depth: int):
        check_depth(depth)
        if not isinstance(leaves, list) or not all(valid_field(x) for x in leaves):
            raise ValueError("INVALID_LEAVES")
        self.depth = depth
        self.max_leaves = 2 ** depth
        if len(leaves) > self.max_leaves:
            raise ValueError("Too many leaves for the given tree depth.")
        self.leaves = leaves.copy()
        while len(self.leaves) < self.max_leaves:
            self.leaves.append("0")
        self.tree = [self.leaves]
        self._build_tree()

    def _build_tree(self):
        current_level = self.leaves
        for level in range(self.depth):
            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(poseidon_hash_2(
                    current_level[i], current_level[i+1]))
            self.tree.append(next_level)
            current_level = next_level

    def get_root(self) -> str: return self.tree[-1][0]

    def get_path(self, index: int) -> dict:
        if type(index) is not int or not 0 <= index < len(self.leaves):
            raise ValueError("INVALID_LEAF_INDEX")
        path_elements = []
        path_indices = []
        current_index = index
        for level in range(self.depth):
            is_right_node = current_index % 2 != 0
            sibling_index = current_index - 1 if is_right_node else current_index + 1
            path_elements.append(self.tree[level][sibling_index])
            path_indices.append(1 if is_right_node else 0)
            current_index //= 2
        return {"path_elements": path_elements, "path_indices": path_indices}


class ZKMerkleVotingSystem:
    def __init__(self, circuits_dir=None):
        if circuits_dir is None:
            pointer = ROOT / "research_results/merkle_private_bound/latest.json"
            if not pointer.is_file():
                raise FileNotFoundError("Run python build_circuit.py --setup --test first")
            config = json.loads(pointer.read_text(encoding="utf-8"))
            if config.get("circuit_schema") != SCHEMA:
                raise ValueError("CIRCUIT_SCHEMA_MISMATCH")
            circuits_dir = ROOT / config["path"]
        self.circuits_dir = Path(circuits_dir).resolve()
        manifest_path = self.circuits_dir / "results.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(f"Missing new circuit manifest: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("environment", {}).get("circuit_schema") != SCHEMA:
            raise ValueError("CIRCUIT_SCHEMA_MISMATCH")
        self.depths = {row["depth"] for row in manifest["results"] if row["depth"] is not None}
        self.cli = ROOT / "node_modules/snarkjs/build/cli.cjs"

    def _get_paths(self, depth):
        check_depth(depth)
        if depth not in self.depths:
            raise ValueError("MERKLE_DEPTH_NOT_BUILT")
        directory = self.circuits_dir / f"d{depth}"
        wasm = directory / f"merkle_d{depth}_js"
        return (wasm / "generate_witness.js", wasm / f"merkle_d{depth}.wasm",
                directory / "final.zkey", directory / "vkey.json")

    _valid_root = staticmethod(valid_field)

    def configureElectionTree(self, election, root, depth):
        """Trusted setup compatibility helper; returns identity-free context."""
        context = MerkleContext(root, depth)
        if election.merkle_root is not None or election.merkle_depth is not None:
            raise ValueError("MERKLE_TREE_ALREADY_CONFIGURED")
        if election.vote_box or any(r["has_voted"] for r in election.voter_registry.values()):
            raise ValueError("VOTING_ALREADY_STARTED")
        election.merkle_root, election.merkle_depth = root, depth
        return context

    def generateVoterSecret(self):
        return os.urandom(31).hex()

    def computeIdentityCommitment(self, voter, secret):
        return poseidon_hash_2(str(int(voter.hashId, 16)), str(int(secret, 16)))

    def registerVoterStatus(self, election, voter_id_hash):
        # Retained for trusted registration experiments only; verifier never reads it.
        if voter_id_hash in election.voter_registry:
            raise ValueError("VOTER_ALREADY_REGISTERED")
        if election.merkle_root is not None:
            raise ValueError("REGISTRATION_CLOSED")
        election.voter_registry[voter_id_hash] = {"has_voted": False}
        return True

    def generateVoteProof(self, voter, secret, merkle_path, root, depth, encrypted_vote):
        """Prover-side function. Its private inputs must not be sent to the verifier."""
        MerkleContext(root, depth)
        elements, indices = merkle_path.get("path_elements"), merkle_path.get("path_indices")
        if (not isinstance(elements, list) or not isinstance(indices, list)
                or len(elements) != depth or len(indices) != depth
                or not all(map(valid_field, elements))
                or not all(type(x) is int and x in (0, 1) for x in indices)):
            raise ValueError("INVALID_MERKLE_PATH")
        witness_js, wasm, zkey, _ = self._get_paths(depth)
        for file in (witness_js, wasm, zkey):
            if not file.is_file():
                raise FileNotFoundError(file)
        h = packet_hash(encrypted_vote)
        with tempfile.TemporaryDirectory(prefix="merkle_prove_") as tmp:
            tmp = Path(tmp)
            inp, witness = tmp / "input.json", tmp / "witness.wtns"
            proof_file, public_file = tmp / "proof.json", tmp / "public.json"
            inp.write_text(json.dumps({
                "voter_id": str(int(voter.hashId, 16)), "secret": str(int(secret, 16)),
                "root": root, "voteHash": h, "path_elements": elements,
                "path_indices": indices
            }), encoding="utf-8")
            run_node([witness_js, wasm, inp, witness])
            run_node([self.cli, "groth16", "prove", zkey, witness, proof_file, public_file])
            proof = json.loads(proof_file.read_text(encoding="utf-8"))
            signals = json.loads(public_file.read_text(encoding="utf-8"))
        if not valid_signals(signals) or signals[1:] != [root, h]:
            raise RuntimeError("PUBLIC_SIGNALS_MISMATCH")
        return {"proof": proof, "public_signals": signals}

    def verifyZKProof(self, proof, public_signals, depth):
        """Raw CLI verification; use verifyBallotProof for root/packet checks too."""
        if not isinstance(proof, dict) or not valid_signals(public_signals):
            return False
        _, _, _, vkey = self._get_paths(depth)
        if not vkey.is_file():
            raise FileNotFoundError(vkey)
        with tempfile.TemporaryDirectory(prefix="merkle_verify_") as tmp:
            tmp = Path(tmp)
            proof_file, public_file = tmp / "proof.json", tmp / "public.json"
            proof_file.write_text(json.dumps(proof), encoding="utf-8")
            public_file.write_text(json.dumps(public_signals), encoding="utf-8")
            try:
                result = run_node([self.cli, "groth16", "verify", vkey, public_file, proof_file])
            except RuntimeError:
                return False
            return "OK!" in result.stdout

    def verifyBallotProof(self, context, packet):
        """Identity-free, stateless verification; NOT ballot acceptance or deduplication."""
        if not isinstance(context, MerkleContext):
            raise TypeError("TRUSTED_MERKLE_CONTEXT_REQUIRED")
        if not isinstance(packet, MerkleProofPacket):
            raise TypeError("MERKLE_PROOF_PACKET_REQUIRED")
        signals = packet.public_signals
        if not valid_signals(signals):
            raise ValueError("INVALID_PUBLIC_SIGNALS")
        if signals[1] != context.root:
            raise ValueError("MERKLE_ROOT_MISMATCH")
        if signals[2] != packet_hash(packet.encrypted_vote):
            raise ValueError("VOTE_HASH_MISMATCH")
        if not self.verifyZKProof(packet.proof, signals, context.depth):
            raise ValueError("ZK_VERIFICATION_FAILED")
        return True

    def castVote(self, *args, **kwargs):
        raise NotImplementedError(
            "Identity-based castVote is disabled. Use verifyBallotProof(context, packet); "
            "this component does not implement anonymous double-vote prevention."
        )

    def tally(self, *args, **kwargs):
        raise NotImplementedError("This proof component does not collect or tally ballots.")
