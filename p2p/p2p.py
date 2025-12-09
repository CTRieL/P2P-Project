import json
import socket
import sys
import threading
from cryptography.fernet import Fernet

from p2p.discovery import DiscoveryService
from security import SecurityManager
from config import BUFFER_SIZE
from utils import Colors

class P2PMessenger:
    def __init__(self, port, username, verbose=True) :
        self.port = port
        self.username = username
        self.security = SecurityManager()
        self.discovery = DiscoveryService(port, username)
        self.verbose = verbose

        #state koneksi
        self.connected_peer_socket = None
        self.peer_fernet = None #diisi setelah handshake
        self.peer_name = None

    def start(self):
        print(f"{Colors.HEADER}[*] Memulai node P2P pada port {self.port}...{Colors.ENDC}")
        self.discovery.start()

        server_thread = threading.Thread(target=self.tcp_listener, daemon=True)
        server_thread.start()

        self.input_loop()

    def tcp_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        
        while True:
            client, addr = server.accept()
            # Jika sedang chat dengan peer lain, tolak koneksi baru
            if self.connected_peer_socket is not None:
                client.close()
                continue
            
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
    
    def handle_client(self, client_sock):
        """Menangani pesan masuk dan Handshake"""
        try:
            while True:
                data = client_sock.recv(BUFFER_SIZE)
                if not data: break
                self.log_debug("IN", data)

                packet = json.loads(data.decode())

                if packet['type'] == 'PUBKEY_REQ':
                    response = json.dumps({
                        "type" : "PUBKEY_RESP",
                        "pubkey" : self.security.get_public_key_pem(),
                    }).encode()
                    self.log_debug("OUT", response)
                    client_sock.send(response)
                    
                elif packet['type'] == 'HANDSHAKE_FIN':
                    enc_sess_key = bytes.fromhex(packet['session_key'])
                    sess_key = self.security.decrypt_with_my_private(enc_sess_key)
                    self.peer_fernet = Fernet(sess_key)
                    self.peer_name = packet['username']
                    self.connected_peer_socket = client_sock
                    
                    print(f"\n{Colors.GREEN}[*] Terhubung dengan {packet['username']}{Colors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                    
                elif packet['type'] == 'MESSAGE':
                    encrypted_msg = packet['content']
                    msg = self.peer_fernet.decrypt(encrypted_msg.encode()).decode()

                    print(f"\n{Colors.BLUE}[{packet['sender']}]: {msg}{Colors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                
                elif packet['type'] == 'DISCONNECT':
                    print(f"\n{Colors.FAIL}[!] {self.peer_name} memutus koneksi{Colors.ENDC}")
                    self.reset_connection()
                    break
                    
        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Error Koneksi: {e}{Colors.ENDC}")
            print(f"{self.username}: ", end="", flush=True)
        finally:
            self.reset_connection()
            
    def connect_to_peer(self, target_ip, target_port):
        """Logika client aktif menghubungi server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, int(target_port)))

            #request public key
            req_data = json.dumps({
                "type" : "PUBKEY_REQ", 
                "username" : self.username,
            }).encode()
            self.log_debug("OUT", req_data)
            sock.send(req_data)
            
            
            #terima public key teman
            resp = sock.recv(BUFFER_SIZE)
            self.log_debug("IN", resp)
            
            resp_json = json.loads(resp.decode())
            peer_pub_pem = resp_json['pubkey']
            
            #enkripsi session key pakai public key teman dan dikirim
            encrypted_sess_key = self.security.encrypt_with_peer_public(self.security.session_key, peer_pub_pem)
            final_handshake = json.dumps({
                "type" : "HANDSHAKE_FIN",
                "session_key" : encrypted_sess_key.hex(),
                "username": self.username,
            }).encode()
            self.log_debug("OUT", final_handshake)            
            sock.send(final_handshake)

            self.peer_fernet = self.security.fernet #pakai key sendiri
            self.connected_peer_socket = sock
            print(f"{Colors.GREEN}[*] Terhubung dengan {target_ip}:{target_port}{Colors.ENDC}")

            threading.Thread(target=self.handle_client, args=(sock,), daemon=True).start()

        except Exception as e:
            print(f"{Colors.FAIL}[!] Gagal connect: {e}{Colors.ENDC}")
            # print(f"{self.username}: ", end="", flush=True)
            
    def disconnect(self):
        """Mengirim sinyal putus dan reset state"""
        if self.connected_peer_socket:
            try:
                msg = json.dumps({
                    "type" : "DISCONNECT",
                    "sender" : self.username,
                    })
                self.log_debug("OUT", msg)
                self.connected_peer_socket.send(msg.encode())
                self.connected_peer_socket.close()
            except: pass
            print(f"{Colors.FAIL}[*] Memutus koneksi.{Colors.ENDC}")
            print(f"{self.username}: ", end="", flush=True)
        self.reset_connection()

    def reset_connection(self):
        self.connected_peer_socket = None
        self.peer_fernet = None
        self.peer_name = None
        # print("\n[*] Mode Standby (Listening). Ketik 'list' untuk cari teman.")

    def log_debug(self, direction, data):
        """"Menampilkan data RAW JSON bila verbose aktif"""
        if self.verbose:
            prefix = "[>>> SEND]" if direction == "OUT" else "[RECV <<<]"
            print(f"{prefix}:")
            try: 
                parsed = json.loads(data) if isinstance(data, str) else json.loads(data.decode())
                print(f"{Colors.WARNING}{json.dumps(parsed, indent=2)}{Colors.ENDC}")
            except:
                print(f"{Colors.WARNING}{data}{Colors.ENDC}")
            print("-" * 30)
    
    def input_loop(self):
        print("\n-- Command --")
        print("/list                 -> Lihat siapa yang online")
        print("/connect <IP> <PORT>  -> Chat dengan teman")
        print("/disconnect           -> Putus chat saat ini")
        print("/exit                 -> Tutup aplikasi")

        while True:
            cmd = input(f"{self.username}: ")
            
            if not cmd: continue

            if cmd.startswith('/'):
                cmd = cmd.removeprefix('/')
                #/list
                if cmd.lower() == 'list':
                    peers = self.discovery.get_active_peers()
                    print(f"{Colors.HEADER}--- User Online ---{Colors.ENDC}")
                    if not peers: print("Belum ada user lain terdeteksi.")
                    for p in peers: print(p)
                    print(f"{Colors.HEADER}-------------------{Colors.ENDC}")

                #/connect <IP> <PORT>
                elif cmd.startswith('connect'):
                    if self.connected_peer_socket:
                        print(f"{Colors.FAIL}[!] Anda harus disconnect dulu sebelum ganti teman!{Colors.ENDC}")
                        continue
                    try:
                        _, ip, port = cmd.split()
                        self.connect_to_peer(ip, port)
                    except:
                        print("[!] Format salah. Gunakan: /connect <IP> <PORT>")

                # /disconnect
                elif cmd.lower() == 'disconnect':
                    self.disconnect()

                # /exit
                elif cmd.lower() == 'exit':
                    self.disconnect()
                    self.discovery.running = False
                    sys.exit()

            # logika message
            elif self.connected_peer_socket:
                if self.peer_fernet:
                    encrypted_content = self.peer_fernet.encrypt(cmd.encode()).decode()
                    msg = json.dumps({
                        "type": "MESSAGE",
                        "sender": self.username,
                        "content": encrypted_content
                    }).encode()
                    try:
                        self.log_debug("OUT", msg)
                        self.connected_peer_socket.send(msg)
                    except:
                        print("[!] Gagal kirim. Koneksi putus.")
                        self.reset_connection()
            else:
                print("[!] Anda belum terhubung. Ketik '/list' lalu '/connect <IP> <PORT>'")