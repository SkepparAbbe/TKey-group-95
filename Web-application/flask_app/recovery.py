from mnemonic import Mnemonic
import hashlib
import os

# Generate a mnemonic phrase 
def generate_mnemonic():
    mnemo = Mnemonic("english") # Creates a Mnemonic object 
    mnemonic = mnemo.generate(strength=128) # Generates a 12 or 24 word mnemonic depending for strength 128 or 254
    return mnemonic

# Convert the mnemonic phrase to a seed phrase
def conv_seed(mnemonic):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic, passphrase="")
    return seed.hex()

# Hashes seed phrase and generates salt
def hash_seed(seed):
        salt = os.urandom(16)
        return hashlib.pbkdf2_hmac('sha256', seed.encode(), salt, 100000).hex() , salt.hex()


'''
if __name__ == "__main__":
    nemonic = generate_mnemonic()   
    print("Mnemonic Phrase: ", nemonic)

    seed = conv_seed(nemonic)  
    print("Seed Phrase: ", seed)
    
    hashed_seed, salt = hash_seed(seed)
    print("Hashed Seed: ", hashed_seed)
    print("Salt: ", salt)

'''