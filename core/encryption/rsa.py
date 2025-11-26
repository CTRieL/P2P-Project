from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA private key and return (private_pem_bytes, public_pem_bytes).
    Private PREM is PKCS8 (unencrypted). Adjust if need passphrase
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def load_public_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

def load_private_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

def rsa_encrypt(public_key_pem: bytes, data: bytes) -> bytes:
    """"
    Encrypt small data (e.g. AES key) with RSA-OAEP(SHA-256).
    """
    pub = load_public_key_from_pem(public_key_pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Public key must be RSA!")
    
    cipher = pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return cipher

def rsa_decrypt(private_key_pem: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA-OAEP(SHA-256)
    """
    priv = load_private_key_from_pem(private_key_pem)
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise TypeError("Private keykey must be RSA!")
        
    pt = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return pt