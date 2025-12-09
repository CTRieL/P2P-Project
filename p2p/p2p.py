import base64
import json
import os
import socket
import struct
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
                packet = self.recv_packet(client_sock)
                if not packet: break

                if packet['type'] == 'PUBKEY_REQ':
                    self.send_packet(client_sock, {
                        "type" : "PUBKEY_RESP",
                        "pubkey" : self.security.get_public_key_pem(),
                    })
                    
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
                
                elif packet['type'] == 'FILE':
                    print(f"\n{Colors.BLUE}[*] Menerima file: {packet['filename']}...{Colors.ENDC}")
                    enc_content_b64 = packet['content']
                    enc_bytes = base64.b64decode(enc_content_b64)
                    file_bytes = self.peer_fernet.decrypt(enc_bytes)

                    filepath = os.path.join("downloads", f"received_{packet['filename']}")
                    with open(filepath, 'wb') as f:
                        f.write(file_bytes)

                    print(f"{Colors.GREEN}[V] File tersimpan di: {filepath}{Colors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                    
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
            self.send_packet(sock, {
                "type" : "PUBKEY_REQ", 
                "username" : self.username,
            })
            
            #terima public key teman
            resp = self.recv_packet(BUFFER_SIZE)
            self.log_debug("IN", resp)
            
            resp_json = self.recv_packet(sock)
            peer_pub_pem = resp_json['pubkey']
            
            #enkripsi session key pakai public key teman dan dikirim
            encrypted_sess_key = self.security.encrypt_with_peer_public(self.security.session_key, peer_pub_pem)
            self.send_packet(sock, {
                "type" : "HANDSHAKE_FIN",
                "session_key" : encrypted_sess_key.hex(),
                "username": self.username,
            })

            self.peer_fernet = self.security.fernet #pakai key sendiri
            self.connected_peer_socket = sock
            print(f"{Colors.GREEN}[*] Terhubung dengan {target_ip}:{target_port}{Colors.ENDC}")

            threading.Thread(target=self.handle_client, args=(sock,), daemon=True).start()

        except Exception as e:
            print(f"{Colors.FAIL}[!] Gagal connect: {e}{Colors.ENDC}")
    
    def input_loop(self):
        print("\n-- Command --")
        print("/list                 -> Lihat siapa yang online")
        print("/connect <IP> <PORT>  -> Chat dengan teman")
        print("/sendfile <PATH>      -> Kirim file")
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
                        print(f"{Colors.GRAY}[!] Invalid Format : /connect <IP> <PORT>{Colors.ENDC}")

                # /sendfile <PATH>
                elif cmd.startswith('sendfile'):
                    try:
                        _, path = cmd.split(maxsplit=1)
                        self.send_file(path)
                    except ValueError:
                        print(f"{Colors.GRAY}[!] Invalid Format: /sendfile <PATH>{Colors.ENDC}")
                        
                
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
                    try:
                        self.send_packet(self.connected_peer_socket, {
                            "type": "MESSAGE",
                            "sender": self.username,
                            "content": encrypted_content
                        })
                    except:
                        print(f"{Colors.FAIL}[!] Gagal kirim. Koneksi putus.{Colors.ENDC}")
                        self.reset_connection()
            else:
                print(f"{Colors.GRAY}[!] Anda belum terhubung. Ketik '/list' lalu '/connect <IP> <PORT>'{Colors.ENDC}")
    
    def send_packet(self, sock, data_dict):
        """Helper mengirim panjang data lebih dahulu, lalu datanya"""
        try:
            msg_json = json.dumps(data_dict).encode()
            #pack integer (length) jadi 4 byte (big-endian)
            header =  struct.pack("!I", len(msg_json))

            self.log_debug("OUT", msg_json)

            sock.sendall(header + msg_json)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Gagal mengirim packet: {e}{Colors.ENDC}")
    
    def recv_packet(self, sock):
        """Helper membaca 4 bytes panjang, lalu baca isi datanya"""
        try:
            header = sock.recv(4)
            if not header: return None

            #unpack header
            msg_len = struct.unpack("!I", header)[0]

            data = b""
            while len(data) < msg_len:
                chunk = sock.recv(min(4096, msg_len - len(data)))
                if not chunk: break
                data += chunk
            
            if len(data) != msg_len:
                return None
            
            self.log_debug("IN", data)
            return json.loads(data.decode())

        except Exception as e:
            return None
    
    def send_file(self, filepath):
        if not self.connected_peer_socket:
            print(f"{Colors.FAIL}[!] Belum terhubung. {Colors.ENDC}")
            return
        if not os.path.exists(filepath):
            print(f"{Colors.FAIL}[!] File tidak ditemukan. {Colors.ENDC}")
            return
        
        try: 
            filename = os.path.basename(filepath)
            print(f"{Colors.GRAY}[*] Mengirim file {filename}{Colors.ENDC}")

            with open(filepath, 'rb') as f:
                file_bytes = f.read()
            encrypted_bytes = self.peer_fernet.encrypt(file_bytes)
            b64_content = base64.b64encode(encrypted_bytes).decode('utf-8')
            
            packet = {
                "type" : "FILE",
                "sender" : self.username,
                "filename" : filename,
                "content" : b64_content,
            }

            self.send_packet(self.connected_peer_socket, packet)
            print(f"{Colors.GREEN}[V] File Berhasil dikirim!{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Gagal kirim file: {e}{Colors.ENDC}")
             
    def log_debug(self, direction, data):
        """"Menampilkan data RAW JSON bila verbose aktif"""
        if self.verbose:
            prefix = "[>>> SEND]" if direction == "OUT" else "[RECV <<<]"
            print(f"{prefix}:")
            try: 
                parsed = json.loads(data) if isinstance(data, str) else json.loads(data.decode())
                print(f"{Colors.WARNING}{json.dumps(parsed, indent=2)}{Colors.ENDC}")
            except:
                print(f"not json{Colors.WARNING}{data}{Colors.ENDC}")
            print("-" * 30)
    
    def disconnect(self):
        """Mengirim sinyal putus dan reset state"""
        if self.connected_peer_socket:
            try:
                self.send_packet(self.connected_peer_socket, {
                    "type" : "DISCONNECT",
                    "sender" : self.username,
                })
                self.connected_peer_socket.close()
            except: pass
            print(f"{Colors.FAIL}[*] Memutus koneksi.{Colors.ENDC}")
        self.reset_connection()

    def reset_connection(self):
        self.connected_peer_socket = None
        self.peer_fernet = None
        self.peer_name = None
        # print("\n[*] Mode Standby (Listening). Ketik 'list' untuk cari teman.")