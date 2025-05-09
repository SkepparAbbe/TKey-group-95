from mnemonic import Mnemonic
import hashlib
import os

# Higher iteration count yields longer time to successful brute force attempts
iterations = 100000

# Generate a mnemonic phrase 
def generate_mnemonic():
    mnemo = Mnemonic("english") # Creates a Mnemonic object 
    mnemonic = mnemo.generate(strength=128) # Generates a 12 or 24 word mnemonic depending for strength 128 or 254
    return mnemonic

# Convert the mnemonic phrase to a seed phrase
def convert_to_seed(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic, passphrase="")
    return seed.hex()

# Hashes seed phrase and generates salt
def hash_seed(seed):
        salt = os.urandom(16)
        return hashlib.pbkdf2_hmac('sha256', seed.encode(), salt, iterations).hex() , salt.hex()

def verify_mnemonic(stored_hash, salt, mnemonic):
    new_seed = convert_to_seed(mnemonic)
    new_hash = hashlib.pbkdf2_hmac('sha256', new_seed.encode(), bytes.fromhex(salt), iterations).hex()
    return stored_hash == new_hash