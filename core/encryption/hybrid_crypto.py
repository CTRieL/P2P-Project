import json
import base64
from typing import Dict
from core.encryption.aes import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt
from core.encryption.rsa import rsa_encrypt, rsa_decrypt

# Public interface excepted by core: encrypt_message(plaintext: bytes, recipient_public_key_pem: bytes) -> bytes
# and decrypt_message(payload: bytes, own_private_key_pem: bytes) -> bytes

def _b64(x: bytes) -> str:
    return base64.b64decode(x).decode()

def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def encrypt_message(plaintext: bytes, recipient_public_key_pem: bytes) -> bytes:
    """
    Hybrid encrypt: generate AES-256 key, encrypt plaintext with AES-GCM,
    encrypt AES key with recipient RSA public key (OAEP SHA-256).
    Package as JSON with base64 fields and return bytes.
    """
    aes_key = generate_aes_key(32)
    nonce, ciphertext, tag = aes_gcm_encrypt(aes_key, plaintext, associated_data=None)
    
    # encrypt AES key with recipient RSA pubkey
    enc_key = rsa_encrypt(recipient_public_key_pem, aes_key)
    
    payload: Dict[str, str] = {
        "k" : _b64(enc_key),
        "n" : _b64(nonce),
        "c" : _b64(ciphertext), 
        "t" : _b64(tag),
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()

def decrypt_message(payload_bytes: bytes, own_private_key_pem: bytes) -> bytes:
    """
    Reverse of encrypt_message: parse JSON, RSA-decrypt AES key, AES-GCM decrypt ciphertext.
    return plaintext bytes. Raises exception if decryption/auth fails.
    """
    obj = json.loads(payload_bytes.decode())
    enc_key_b64 = obj.get("k")
    nonce_b64 = obj.get("n")
    c_b64 = obj.get("c")
    tag_b64 = obj.get("t")
    if not all((enc_key_b64, nonce_b64, c_b64, tag_b64)):
        raise ValueError("invalid hybrid payload")
    
    enc_key = _unb64(enc_key_b64)
    nonce = _unb64(nonce_b64)
    ciphertext = _unb64(c_b64)
    tag = _unb64(tag_b64)
    
    aes_key = rsa_decrypt(own_private_key_pem, enc_key)
    
    plaintext = aes_gcm_decrypt(aes_key, nonce, ciphertext, tag, associated_data=None)
    return plaintext