## Module for verifying signatures with ED25519
## Export verify

from cryptography.hazmat.primitives import serialization
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.exceptions import InvalidSignature


# Test data
message = "hemligtt"
signature = "c5fd4c237ee479943599008c3b5fcbaf033fcedb4a266f9866bbeec859f8036b7b00cf1850422f5988d9a8dd7bab9244de0354fa53b4031440a316def01c7e0e"
pub_key = "4d363ab7c0c7dbab66ea2faa8182cc9a6bab31fd3125d9fb3a163d6ba0ccc898"

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
    """Main function to test the program"""
    try:
        verify(message, signature, pub_key)
    except InvalidSignature:
        print("did not work")

if __name__ == "__main__":
    main()
