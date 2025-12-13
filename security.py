import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils import TxtColors

class SecurityManager:
    """Menangani RSA (asymetric) dan AES-256 (symetric) cryptography"""
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        
        # simpan public key dalam format PEM (bytes) untuk dikirim
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # generate session key untuk AES-256
        self.session_key = os.urandom(32)
        
    def get_public_key_pem(self):
        return self.public_pem.decode('utf-8')

    def encrypt_with_peer_public(self, message_bytes, peer_public_pem):
        """Mengenkripsi pesan menggunakan Public Key teman"""
        peer_pub_key = serialization.load_pem_public_key(peer_public_pem.encode('utf-8'))
        encrypted = peer_pub_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
        return encrypted
    
    def decrypt_with_my_private(self, encrypted_bytes):
        """Mendekripsi pesan menggunakan Private Key sendiri"""
        return self.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
    
    def set_session_key(self, key_bytes):
        """Set kucii sesi"""
        self.session_key = key_bytes
    
    def encrypt_chat(self, message):
        """Enkripsi chat biasa menggunakan AES-256-GCM"""
        iv = os.urandom(12) #generate Nonce
        encryptor = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
        ).encryptor()
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        ciphertext = encryptor.update(message) + encryptor.finalize()

        combined_data = iv + encryptor.tag + ciphertext
        return base64.urlsafe_b64encode(combined_data).decode('utf-8')
    
    def decrypt_chat(self, encrypted_token) -> bytes:
        """Dekripsi chat biasa menggunakan AES-256-GCM"""  
        try:
            data = base64.urlsafe_b64decode(encrypted_token)

            iv = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]

            decryptor = Cipher(
                algorithms.AES(self.session_key),
                modes.GCM(iv, tag),
            ).decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()
        
        except Exception as e:
            print(f"{TxtColors.FAIL}[!] Decryption Error: {e}{TxtColors.ENDC}")
            return b""
        