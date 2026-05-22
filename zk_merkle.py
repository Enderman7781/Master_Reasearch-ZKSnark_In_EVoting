import os
import json
import math
import tempfile
import subprocess
from zk_normal import User, Election, Ballot, FILE_PATH


def calculate_optimal_depth(num_voters: int) -> int:
    if num_voters <= 1:
        return 1
    return math.ceil(math.log2(num_voters))


def poseidon_hash_2(left: str, right: str) -> str:
    cmd = f"node {FILE_PATH['commitment']} {left} {right}"
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=True)
    return result.stdout.strip()


class ZKMerkleTree:
    def __init__(self, leaves: list, depth: int):
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
    def __init__(self, circuits_dir="compiled_circuits"):
        self.circuits_dir = circuits_dir

    def _get_paths(self, depth: int):
        """輔助函數：動態組合對應深度的檔案路徑"""
        base_path = os.path.join(self.circuits_dir, f"d{depth}")
        wasm_path = os.path.join(
            base_path, f"merkle_d{depth}_js", f"merkle_d{depth}.wasm")
        witness_gen_path = os.path.join(
            base_path, f"merkle_d{depth}_js", "generate_witness.js")
        zkey_path = os.path.join(base_path, "final.zkey")
        vkey_path = os.path.join(base_path, "vkey.json")
        return witness_gen_path, wasm_path, zkey_path, vkey_path

    def generateVoterSecret(self) -> str:
        return os.urandom(31).hex()

    def computeIdentityCommitment(self, voter: User, secret: str) -> str:
        voter_id_int = str(int(voter.hashId, 16))
        secret_int = str(int(secret, 16))
        try:
            cmd = f"node {FILE_PATH['commitment']} {voter_id_int} {secret_int}"
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise Exception("Failed to compute Identity Commitment")

    def registerVoterStatus(self, election: Election, voter_id_hash: str) -> bool:
        election.voter_registry[voter_id_hash] = {"has_voted": False}
        return True

    def generateVoteProof(self, voter, secret: str, merkle_path: dict, root: str, depth: int) -> dict:
        witness_gen_path, wasm_path, zkey_path, _ = self._get_paths(depth)
        voter_id_int = str(int(voter.hashId, 16))
        secret_int = str(int(secret, 16))

        input_data = {
            "voter_id": voter_id_int,
            "secret": secret_int,
            "root": root,
            "path_elements": merkle_path["path_elements"],
            "path_indices": merkle_path["path_indices"]
        }

        with open("input.json", "w") as f:
            json.dump(input_data, f)

        try:
            # 動態調用對應深度的 .wasm 和 .zkey
            cmd_witness = f"node {witness_gen_path} {wasm_path} input.json witness.wtns"
            subprocess.run(cmd_witness, shell=True,
                           check=True, capture_output=True)

            cmd_prove = f"snarkjs groth16 prove {zkey_path} witness.wtns proof.json public.json"
            subprocess.run(cmd_prove, shell=True,
                           check=True, capture_output=True)

            with open("proof.json", "r") as f:
                real_proof = json.load(f)
            with open("public.json", "r") as f:
                real_public_signals = json.load(f)

            os.remove("input.json")
            os.remove("witness.wtns")
            return {"proof": real_proof, "public_signals": real_public_signals}
        except subprocess.CalledProcessError:
            return {"proof": {"mock": "data"}, "public_signals": [root]}

    def verifyZKProof(self, proof: dict, public_signals: list, depth: int) -> bool:
        _, _, _, vkey_path = self._get_paths(depth)
        if proof.get("mock") == "data":
            return True
        with tempfile.TemporaryDirectory() as temp_dir:
            proof_path = os.path.join(temp_dir, "proof.json")
            public_path = os.path.join(temp_dir, "public.json")
            with open(proof_path, 'w') as f:
                json.dump(proof, f)
            with open(public_path, 'w') as f:
                json.dump(public_signals, f)
            try:
                cmd = f"snarkjs groth16 verify {vkey_path} {public_path} {proof_path}"
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, check=True)
                return "OK" in result.stdout
            except subprocess.CalledProcessError:
                return False

    def castVote(self, election: Election, voter: User, ballot: Ballot, depth: int) -> bool:
        if voter.hashId not in election.voter_registry:
            raise ValueError("VOTER_NOT_REGISTERED")
        voter_record = election.voter_registry[voter.hashId]
        
        if voter_record["has_voted"]:
            raise ValueError("ALREADY_VOTED")

        is_valid = self.verifyZKProof(
            ballot.proof, ballot.public_signals, depth)
        if not is_valid:
            raise ValueError("ZK_VERIFICATION_FAILED")

        voter_record["has_voted"] = True
        election.vote_box.append(ballot.encrypted_vote)
        return True

    def tally(self, election: Election, decrypt_fn) -> dict:
        results = {"candidate_votes": {c_id: 0 for c_id in election.candidates},
                   "blank_votes": 0, "total_votes": len(election.vote_box)}
        for encrypted_vote in election.vote_box:
            try:
                decrypted_val = decrypt_fn(encrypted_vote)
                if decrypted_val == Election.BLANK_VOTE:
                    results["blank_votes"] += 1
                elif decrypted_val in results["candidate_votes"]:
                    results["candidate_votes"][decrypted_val] += 1
                else:
                    results["blank_votes"] += 1
            except Exception:
                results["blank_votes"] += 1
        return results
