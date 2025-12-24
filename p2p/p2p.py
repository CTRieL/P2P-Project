import json
import os
import socket
import struct
import sys
import threading

from p2p.discovery import DiscoveryService
from p2p.security import SecurityManager
from p2p.config import BUFFER_SIZE
from p2p.utils import TxtColors

class P2PMessenger:
    def __init__(self, port, username, verbose=False, callback=None) :
        self.port = port
        self.username = username
        self.security = SecurityManager()
        self.discovery = DiscoveryService(port, username)
        self.verbose = verbose
        self.callback = callback

        #state koneksi
        self.connected_peer_socket = None
        self.peer_name = None

    def start(self):
        print(f"{TxtColors.HEADER}[*] Memulai node P2P pada port {self.port}...{TxtColors.ENDC}")
        self.discovery.start()

        server_thread = threading.Thread(target=self.tcp_listener, daemon=True)
        server_thread.start()

        self.input_loop()
        
    def start_threads_only(self):
        """Menjalankan komponen background tanpa masuk ke input loop untuk GUI"""
        print(f"{TxtColors.HEADER}[*] Memulai node P2P pada port {self.port}...{TxtColors.ENDC}")
        self.discovery.start()

        server_thread = threading.Thread(target=self.tcp_listener, daemon=True)
        server_thread.start()

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
                    self.security.set_session_key(sess_key)
                    self.peer_name = packet['username']
                    self.connected_peer_socket = client_sock
                    
                    print(f"\n{TxtColors.GREEN}[*] Terhubung dengan {packet['username']}{TxtColors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                    
                    if self.callback:
                        self.callback("CONNECTED", packet['username'])
                    
                elif packet['type'] == 'MESSAGE':
                    encrypted_msg = packet['content']
                    msg = self.security.decrypt_chat(encrypted_msg).decode('utf-8')

                    print(f"\n{TxtColors.BLUE}[{packet['sender']}]: {msg}{TxtColors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                    
                    if self.callback:
                        self.callback("MESSAGE", {"sender" : packet['sender'], "text": msg})
                
                elif packet['type'] == 'FILE':
                    print(f"\n{TxtColors.BLUE}[*] Menerima file: {packet['filename']}...{TxtColors.ENDC}")
                    enc_content_b64 = packet['content']
                    file_bytes = self.security.decrypt_chat(enc_content_b64)

                    filepath = os.path.join("downloads", f"received_{packet['filename']}")
                    with open(filepath, 'wb') as f:
                        f.write(file_bytes)

                    print(f"{TxtColors.GREEN}[V] File tersimpan di: {filepath}{TxtColors.ENDC}")
                    print(f"{self.username}: ", end="", flush=True)
                    
                    if self.callback:
                        self.callback("FILE", {"sender" : packet['sender'], "filename": packet['filename']})                
                
                elif packet['type'] == 'DISCONNECT':
                    print(f"\n{TxtColors.FAIL}[!] {packet['sender']} memutus koneksi{TxtColors.ENDC}")
                    self.reset_connection()
                    
                    if self.callback:
                        self.callback("DISCONNECT", None)
                    break
                    
        except Exception as e:
            print(f"\n{TxtColors.FAIL}[!] Error Koneksi: {e}{TxtColors.ENDC}")
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
            resp_json = self.recv_packet(sock)
            peer_pub_pem = resp_json['pubkey']
            
            #enkripsi session key pakai public key teman dan dikirim
            encrypted_sess_key = self.security.encrypt_with_peer_public(self.security.session_key, peer_pub_pem)
            self.send_packet(sock, {
                "type" : "HANDSHAKE_FIN",
                "session_key" : encrypted_sess_key.hex(),
                "username": self.username,
            })

            self.connected_peer_socket = sock
            
            print(f"{TxtColors.GREEN}[*] Terhubung dengan {target_ip}:{target_port}{TxtColors.ENDC}")
            if self.callback:
                self.callback("CONNECTED", f"{target_ip}:{target_port}")

            threading.Thread(target=self.handle_client, args=(sock,), daemon=True).start()

        except Exception as e:
            print(f"{TxtColors.FAIL}[!] Gagal connect: {e}{TxtColors.ENDC}")
    
    def input_loop(self):
        if self.callback == None:
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
                    print(f"{TxtColors.HEADER}--- User Online ---{TxtColors.ENDC}")
                    if not peers: print("Belum ada user lain terdeteksi.")
                    for p in peers: print(p)
                    print(f"{TxtColors.HEADER}-------------------{TxtColors.ENDC}")

                #/connect <IP> <PORT>
                elif cmd.startswith('connect'):
                    if self.connected_peer_socket:
                        print(f"{TxtColors.FAIL}[!] Anda harus disconnect dulu sebelum ganti teman!{TxtColors.ENDC}")
                        continue
                    try:
                        _, ip, port = cmd.split()
                        self.connect_to_peer(ip, port)
                    except:
                        print(f"{TxtColors.GRAY}[!] Invalid Format : /connect <IP> <PORT>{TxtColors.ENDC}")

                # /sendfile <PATH>
                elif cmd.startswith('sendfile'):
                    try:
                        _, path = cmd.split(maxsplit=1)
                        self.send_file(path)
                    except ValueError:
                        print(f"{TxtColors.GRAY}[!] Invalid Format: /sendfile <PATH>{TxtColors.ENDC}")
                        
                
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
                self.send_msg(cmd)
            else:
                print(f"{TxtColors.GRAY}[!] Anda belum terhubung. Ketik '/list' lalu '/connect <IP> <PORT>'{TxtColors.ENDC}")
    
    def send_packet(self, sock, data_dict):
        """Helper mengirim panjang data lebih dahulu, lalu datanya"""
        try:
            msg_json = json.dumps(data_dict).encode()
            #pack integer (length) jadi 4 byte (big-endian)
            header =  struct.pack("!I", len(msg_json))

            self.log_debug("OUT", msg_json)

            sock.sendall(header + msg_json)
        except Exception as e:
            print(f"{TxtColors.FAIL}[!] Gagal mengirim packet: {e}{TxtColors.ENDC}")
    
    def recv_packet(self, sock):
        """Helper membaca 4 bytes panjang, lalu baca isi datanya"""
        try:
            header = sock.recv(4)
            if not header: return None

            #unpack header
            msg_len = struct.unpack("!I", header)[0]

            data = b""
            while len(data) < msg_len:
                chunk = sock.recv(min(BUFFER_SIZE, msg_len - len(data)))
                if not chunk: break
                data += chunk
            
            if len(data) != msg_len:
                return None
            
            self.log_debug("IN", data)
            return json.loads(data.decode())

        except Exception as e:
            return None
    
    def send_msg(self, message):
        if self.security.session_key:
            encrypted_content = self.security.encrypt_chat(message)
            try:
                self.send_packet(self.connected_peer_socket, {
                    "type": "MESSAGE",
                    "sender": self.username,
                    "content": encrypted_content
                })
            except:
                print(f"{TxtColors.FAIL}[!] Gagal kirim. Koneksi putus.{TxtColors.ENDC}")
                self.reset_connection()
    
    def send_file(self, filepath):
        if not self.connected_peer_socket:
            print(f"{TxtColors.FAIL}[!] Belum terhubung. {TxtColors.ENDC}")
            return
        if not os.path.exists(filepath):
            print(f"{TxtColors.FAIL}[!] File tidak ditemukan. {TxtColors.ENDC}")
            return
        
        try: 
            filename = os.path.basename(filepath)
            print(f"{TxtColors.GRAY}[*] Mengirim file {filename}{TxtColors.ENDC}")

            with open(filepath, 'rb') as f:
                file_bytes = f.read()
            
            b64_content = self.security.encrypt_chat(file_bytes)
            if not b64_content: return
            
            packet = {
                "type" : "FILE",
                "sender" : self.username,
                "filename" : filename,
                "content" : b64_content,
            }

            self.send_packet(self.connected_peer_socket, packet)
            print(f"{TxtColors.GREEN}[V] File Berhasil dikirim!{TxtColors.ENDC}")

        except Exception as e:
            print(f"{TxtColors.FAIL}[!] Gagal kirim file: {e}{TxtColors.ENDC}")
    
    def log_debug(self, direction, data):
        """"Menampilkan data RAW JSON bila verbose aktif"""
        if self.verbose:
            prefix = "[>>> SEND]" if direction == "OUT" else "[RECV <<<]"
            print(f"{prefix}:")
            try: 
                parsed = json.loads(data) if isinstance(data, str) else json.loads(data.decode())
                print(f"{TxtColors.WARNING}{json.dumps(parsed, indent=2)}{TxtColors.ENDC}")
            except:
                print(f"not json{TxtColors.WARNING}{data}{TxtColors.ENDC}")
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
            print(f"{TxtColors.FAIL}[*] Memutus koneksi.{TxtColors.ENDC}")
        self.reset_connection()
        
        if self.callback:
            self.callback("DISCONNECT", None)
            

    def reset_connection(self):
        self.connected_peer_socket = None
        self.peer_name = None
        # print("\n[*] Mode Standby (Listening). Ketik 'list' untuk cari teman.")