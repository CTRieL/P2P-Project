import json
import socket
import threading
import time

from config import BROADCAST_PORT


class DiscoveryService:
    """Service untuk mencari teman di jaringan lokal (UDP Broadcast)"""
    def __init__(self, my_tcp_port, username):
        self.my_tcp_port = my_tcp_port
        self.username = username
        self.peers = {} # dictionary simpan peer2; format {ip:{port, username, last_seen}}
        self.running = True
    
    def start(self):
        threading.Thread(target=self.send_broadcast, daemon=True).start()
        threading.Thread(target=self.listen_broadcast, daemon=True).start()
    
    def send_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        message = json.dumps({
            "type" : "DISCOVERY",
            "username" : self.username,
            "tcp_port" : self.my_tcp_port,
        }).encode()
        
        while self.running:
            try: 
                sock.sendto(message, ('<broadcast>', BROADCAST_PORT))
                time.sleep(2)
            except Exception as e:
                print(f"[!] Discovery Error: {e}")
                print(f"{self.username}: ", end="", flush=True)
                
    def listen_broadcast(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        #izinkan penggunaan alamat/port
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) #untuk macOS/Linux
        except AttributeError:
            pass
        
        sock.bind(('', BROADCAST_PORT))

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                peer_ip = addr[0]
                msg = json.loads(data.decode())

                if msg['type'] == 'DISCOVERY' and str(msg['tcp_port']) != str(self.my_tcp_port):
                    #simpan/update data peer:
                    peer_id = f"{peer_ip}:{msg['tcp_port']}"

                    is_new = peer_id not in self.peers
                    self.peers[peer_id] = {
                        'port' : msg['tcp_port'],
                        'username' : msg['username'],
                        'last_seen' : time.time()
                    }
                    if is_new:
                        print(f"\n[+] Teman peer baru: {msg['username']} ({peer_id}) - Ketik 'list' untuk detail.")
                        print(f"{self.username}: ", end="", flush=True)
            except: pass
            
    def get_active_peers(self) -> list:
        """Membersihkan peer yang sudah offline (>10 detik) dan return listnya"""
        current_time = time.time()
        active = []
        to_remove = []

        for ip_port, data in self.peers.items():
            if current_time - data['last_seen'] < 10:
                active.append(f"{data['username']} -> {ip_port}")
            else:
                to_remove.append(ip_port)
        
        for ip_port in to_remove:
            del self.peers[ip_port]
        
        return active