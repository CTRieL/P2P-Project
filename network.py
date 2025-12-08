import socket
import threading
import sys
from security import Cipher

class P2PNode:
    def __init__(self, port, peer_ip, peer_port, cipher:Cipher):
        self.port = port
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.cipher = cipher
        self.running = True
        
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        print(f"[*] Listening on port {self.port}...")

        while self.running:
            client, addr = server.accept()
            threading.Thread(target=self.handle_incoming_message, args=(client,)).start()
            
    def handle_incoming_message(self, client_socket):
        try:
            message = client_socket.recv(1024)
            decrypted_msg = self.cipher.decrypt_message(message)
            print(f"\n[*] Pesan masuk: {decrypted_msg}")
            print("Anda: ", end="", flush=True)
        except:
            pass
        finally:
            client_socket.close()
    
    def send_message(self, message):
        try:
            encrypted_msg = self.cipher.encrypt_message(message)

            #koneksi ke peer untuk kirim pesan
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.peer_ip, self.peer_port))
            client.send(encrypted_msg)
            client.close()
        except Exception as e:
            print(f"[!] Gagal mengirim pesan: {e}")