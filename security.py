from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet    

class SecurityManager:
    """Menangani RSA (asymetric) dan Fernet (symetric) cryptography"""
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
        # kunci symetric untuk sesi (saat ini) menggunakan Fernet
        self.session_key = Fernet.generate_key()
        self.fernet = Fernet(self.session_key)
        
    def get_public_key_pem(self):
        return self.public_pem.decode('utf-8')

    def encrypt_with_peer_public(self, message_bytes, peer_public_pem):
        """Mengenkripsi pesan menggunakan Public Key teman"""
        peer_pub_key = serialization.load_pem_public_key(peer_public_pem.encode('utf-8'))
        encrypted = peer_pub_key.encrypt(
            message_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return encrypted
    
    def decrypt_with_my_private(self, encrypted_bytes):
        """Mendekripsi pesan menggunakan Private Key sendiri"""
        return self.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    
    def encrypt_chat(self, message):
        """Enkripsi chat biasa menggunakan Fernet"""
        return self.fernet.encrypt(message.encode()).decode('utf-8')
    
    def decrypt_chat(self, encrypted_token):
        """Dekripsi chat biasa menggunakan Fernet"""
        return self.fernet.decrypt(encrypted_token.encode()).decode('utf-8')