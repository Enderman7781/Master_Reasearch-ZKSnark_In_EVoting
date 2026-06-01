import requests

from zk_normal import *

#from __future__ import annotations

class ZKVotingSystem:
    def __init__(self, vkey_path):
        self.vkey_path = vkey_path

    # 產生 31 bytes 的隨機私鑰。
    def generateVoterSecret(self) -> str:
        random_bytes = os.urandom(31)
        return random_bytes.hex()

    # 計算公開承諾
    def computeIdentityCommitment(self, voter, secret: str) -> str:
        """
        計算使用者的身分承諾 (Identity Commitment)
        透過呼叫 Node.js 確保與 Circom 電路的 Poseidon 參數 100% 一致
        """
        voter_id_int = str(int(voter.hashId, 16))
        secret_int = str(int(secret, 16))
        
        try:
            # 呼叫 Node.js 腳本
            cmd = f"node {FILE_PATH['commitment']} {voter_id_int} {secret_int}"
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # 把 JS 印出來的字串去頭去尾 (去掉換行符號)
            commitment_str = result.stdout.strip()
            return commitment_str
            
        except subprocess.CalledProcessError as e:
            print(f"Error computing commitment: {e.stderr}")
            raise Exception("Failed to compute Identity Commitment")

    # 將選民的 Commitment 寫入資料庫

    def registerVoterCommitment(self, election: Election, voter_id_hash: str, commitment: str) -> bool:
        # 將選民與對應的 Commitment 寫入選民名冊，並初始化為未投票
        election.voter_registry[voter_id_hash] = {
            "commitment": commitment,
            "has_voted": False
        }
        return True

    # 產生 Groth16 的零知識證明與公開信號
    def generateVoteProof(self, voter, secret: str) -> dict:
        voter_id_int = str(int(voter.hashId, 16))
        secret_int = str(int(secret, 16))

        input_data = {
            "voter_id": voter_id_int,
            "secret": secret_int
        }

        payload = {
            "input": input_data
        }

        api_url = "http://localhost:3000/api/prove/no-merkle"

        try:
            # 發送 POST 請求給本地常駐伺服器
            response = requests.post(api_url, json=payload)
            response.raise_for_status() 
            
            result = response.json()
            
            if result.get("success"):
                return {
                    "proof": result["proof"],
                    "public_signals": result["publicSignals"]
                }
            else:
                raise Exception(f"Server returned failure: {result.get('error')}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to communicate with ZKP server: {e}")
        
    # 投遞選票
    def castVote(self, election: Election, voter: User, ballot: Ballot) -> bool:

        # List check
        if voter.hashId not in election.voter_registry:
            raise ValueError("VOTER_NOT_REGISTERED")

        is_valid = self.verifyZKProof(ballot.proof, ballot.public_signals)
        if not is_valid:
            raise ValueError("ZK_VERIFICATION_FAILED")

        voter_record = election.voter_registry[voter.hashId]

        # double voting check
        if voter_record["has_voted"]:
            raise ValueError("ALREADY_VOTED")

        # 4. 驗證 ZKP 出示的承諾，是否與該選民當初註冊的承諾一致
        # 直接比對 ballot 裡的 commitment
        if voter_record["commitment"] != ballot.commitment:
            raise ValueError("COMMITMENT_MISMATCH")

        # 5. 在系統紀錄該選民已投票，並將不記名選票投入票匭
        voter_record["has_voted"] = True

        # 票匭只收加密選票，與身分完美切割
        election.vote_box.append(ballot.encrypted_vote)

        return True

    def verifyZKProof(self, proof: dict, public_signals: list) -> bool:
        """
        透過 snarkjs 驗證 Groth16 證明
        """
        vkey_path = self.vkey_path

        # 使用 tempfile 建立暫存資料夾，驗證完自動清理
        with tempfile.TemporaryDirectory() as temp_dir:
            proof_path = os.path.join(temp_dir, "proof.json")
            public_path = os.path.join(temp_dir, "public.json")

            # 將 Python 字典寫入臨時 JSON 檔案
            with open(proof_path, 'w') as f:
                json.dump(proof, f)
            with open(public_path, 'w') as f:
                json.dump(public_signals, f)

            try:
                # Use a single string command and shell=True for macOS compatibility
                cmd = f"snarkjs groth16 verify {vkey_path} {public_path} {proof_path}"
                
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=True 
                )
                
                if "OK" in result.stdout:
                    return True
                else:
                    print(f"ZKP verification failed: {result.stdout}")
                    return False
                    
            except subprocess.CalledProcessError as e:
                print(f"[SnarkJS Error] Proof not eligible: {e.stderr}")
                return False

    def tally(self, election: Election, decrypt_fn) -> dict:
        """
        Tally the election results.
        :param election: The Election object containing the vote box.
        :param decrypt_fn: A function or service that can decrypt the vote_content.
        :return: A dictionary containing the results.
        """
        results = {
            "candidate_votes": {c_id: 0 for c_id in election.candidates},
            "blank_votes": 0,
            "total_votes": len(election.vote_box)
        }

        # Process each encrypted vote in the box
        for encrypted_vote in election.vote_box:
            try:
                # Decrypt the vote back to its original value (e.g., candidate ID)
                decrypted_val = decrypt_fn(encrypted_vote)

                # Check if it's a blank vote or a valid candidate ID
                if decrypted_val == Election.BLANK_VOTE:
                    results["blank_votes"] += 1
                elif decrypted_val in results["candidate_votes"]:
                    results["candidate_votes"][decrypted_val] += 1
                else:
                    # Optional: Handle cases where decrypted value is not in candidate list
                    print(
                        f"Warning: Decrypted value {decrypted_val} is not a valid candidate.")
                    results["blank_votes"] += 1

            except Exception as e:
                print(f"Error decrypting vote: {e}")
                results["blank_votes"] += 1

        return results