import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key(key_size: int = 32) -> bytes:
    """
    Generate a random AES key
    
    key_size in bytes: 16, 24, 32 (AES-128/192/156). Default 32.
    """
    if key_size not in (16, 24, 32):
        raise ValueError("key_size must be 16, 24, or 32")
    return os.urandom(key_size)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None):
    """
    Encrypt plaintext using AES-GCM
    
    Return (nonce, ciphertext, tag) where tag is appended to ciphertext by AESGCM API,
    but we'll return ciphertext and tag separately for clarity
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) #12 is recommended for GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # cryptography AESGCM return ciphertext||tag, where tag is last 16 bytes
    tag = ct[-16:]
    ciphertext = ct[:-16]
    return nonce, ciphertext, tag
    
def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes | None = None) -> bytes:
    """"
    Decrypt AES-GCM components and return plaintext
    """
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(nonce, combined, associated_data)