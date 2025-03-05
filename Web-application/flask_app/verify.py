## Module for verifying signatures with ED25519
## Export verify

from cryptography.hazmat.primitives import serialization
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.exceptions import InvalidSignature
import pytest
import argparse
from dotenv import load_dotenv
import os

### GET the public key
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(base_dir, ".env"))

# Test data
message = "hemligtt"
signature = "c5fd4c237ee479943599008c3b5fcbaf033fcedb4a266f9866bbeec859f8036b7b00cf1850422f5988d9a8dd7bab9244de0354fa53b4031440a316def01c7e0e"
the_pub_key = os.getenv("PUBLIC_KEY")


def get_pub_key_bytes(key):
    pub_key_bytes = bytes.fromhex(key)
    return ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
    

def get_signature_bytes(signature):
    return bytes.fromhex(signature)
    

def get_message_bytes(message):
    return message.encode('utf-8')



def verify(message, signature, key):
    signature_bytes = get_signature_bytes(signature)
    pub_key_bytes = get_pub_key_bytes(key)
    message = get_message_bytes(message)
    pub_key_bytes.verify(signature_bytes, message)

def main():
    parser = argparse.ArgumentParser(description="Run the verify function, to test --test")
    
    parser.add_argument("--test", action="store_true", help="Run in test mode")
    args = parser.parse_args()
    if args.test:
        test_verify()


"""     else:
        try:
            verify()
        except InvalidSignature:
            print("did not work") """

def test_verify():

    """To test run `python verify.py --test`"""
    # Test data generated with Albin Skeppstedts' TKey
    message = "hemligtt"
    signature = "c5fd4c237ee479943599008c3b5fcbaf033fcedb4a266f9866bbeec859f8036b7b00cf1850422f5988d9a8dd7bab9244de0354fa53b4031440a316def01c7e0e"
    
    test1 = [message, signature, the_pub_key]

    message = "test1"
    signature = "42912f51e9c3e4eff295a3fabb46e98998fca70fb8842d92a09ddba99b5b524ba0a12d727f244b7a6cc779ce25ea99fcaf262967c36fabd2d986693586aa1a0b"
    test2 = [message, signature, the_pub_key]

    message = "test2"
    signature = "cb52ad81d0025da4e372523e3c5133c527ba11156ca97d3a2a15cb1fc4592b5615c6ee046fb5d75131970d757f18ccdc4ef433a1fdf7b2df16da13eced5e6404"
    test3 = [message, signature, the_pub_key]

    
    verify(test1[0], test1[1], test1[2])
    verify(test2[0], test2[1], test2[2])
    verify(test3[0], test3[1], test3[2])


if __name__ == "__main__":
    main()
