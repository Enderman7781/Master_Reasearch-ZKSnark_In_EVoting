import hashlib
import matplotlib.pyplot as plb
import numpy

# The random libararies
import csv
import os
import random
import subprocess
import json
import tempfile
import base64
from poseidon_py.poseidon_hash import poseidon_hash


# 
FILE_PATH = {
    'csv': './voters.csv',
    'commitment': './commitment.js',
    'vkey' : './verification_key.json'
} 

class Election:
    BLANK_VOTE = 0
    
    
    def __init__(self,name,candidates):
        self.name = name
        self.candidates = candidates

        # vote box: save the vote
        self.vote_box = []

        # format: { "voter_id_hash": {"commitment": str, "has_voted": bool} }
        self.voter_registry = {}
    
    
#   User Class
#   負責處理 User 的所有函數
#       - This Class is an abstract class, it only shows the method.
#       - The accurate method should be done by the user.
class User:    
    def __init__(self,stuId):
        self.id = stuId
        self.hashId = self._generateHash(stuId,method='SHA-256')
        
    def _generateHash(self,stuId: str,method: str) -> str:
        if method == 'SHA-256':
            return hashlib.sha256(stuId.encode('utf-8')).hexdigest()
        elif method == 'SHA-384':
            return hashlib.sha384(stuId.encode('utf-8')).hexdigest()
        elif method == 'SHA-512':
            return hashlib.sha512(stuId.encode('utf-8')).hexdigest()
        else:
            # Raise an error if an unsupported method is provided
            raise ValueError(f"Unsupported hash method: {method}")
    def __str__(self):
        return f"Id:{self.id},Hash:{self.hashId}"
        
    
    # Test only, return True
    def validEligibility(self):
        return True
    
    # Random Vote for the candidate K
    def userRandomVote(self,eleciton):
        candidateCounts = len(eleciton.candidates)
        manuplate = random.randint(1,candidateCounts + 1)
        if manuplate == candidateCounts + 1:
            return Election.BLANK_VOTE
        else:
            return manuplate
        
class Ballot:
    def __init__(self, encrypted_vote: str, proof: dict, public_signals: list):
        self.encrypted_vote = encrypted_vote
        self.proof = proof
        self.public_signals = public_signals
        self.commitment = public_signals[0] if public_signals else None

def readCsvData(file_name: str):
    users = []
    with open(file_name, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            userId = row['studentId']
            #print(userId)
            user = User(userId)
            if user.validEligibility() == False:
                continue
            else:
                users.append(user)           
    
            #print(user)
    return users