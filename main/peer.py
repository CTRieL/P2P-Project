import socket
import threading
import uuid
from typing import Dict, Optional
from main.connection import Connection, recv_message_with_length, send_with_length
from main.message_handler import MessageHandler


class Peer:
    def __init__(self, 
                 peer_id: Optional[str], 
                 host: str, 
                 port: int, 
                 private_key_pem: bytes, 
                 public_key_pem: bytes, 
                 logger=None):
        
        self.peer_id = peer_id or str(uuid.uuid4())
        self.host = host
        self.port = port
        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem

        self.connections: Dict[str, Connection] = {} # peer_id, Connection
        self._conn_lock = threading.Lock()
        
        self.server_sock: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None
        self.msg_handler = MessageHandler(self)
        
        #optional logger callable: logger(str)
        self.logger = logger
        
    # ---------------------------- server / incoming -----------------------------
    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(10)
        self.logger and self.logger(f"[Peer {self.peer_id}] listening on {self.host}:{self.port}")
        self._server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        
    def _accept_loop(self):
        while True:
            try:
                client_sock, addr = self.server_sock.accept() # type: ignore
            except Exception as e:
                self.logger and self.logger(f"[Peer] accept error: {e}")
                break
            # create connection wrapper and let it manage handshake/threads
            conn = Connection(sock=client_sock, local_peer=self)
            conn.start()
            # Note: registration happen when handshake payload arrives
            self.logger and self.logger(f"[Peer] accepted connection from {addr}")
            
    # ---------------------------- connection manager ---------------------------------
    def register_connection(self, conn: Connection):
        """
        Called by connection when handshake complete, so remote peer_id known
        """
        with self._conn_lock:
            if conn.remote_peer_id in self.connections:
                #replace existing conn
                try:
                    old = self.connections[conn.remote_peer_id]
                    old.close()
                except Exception:
                    pass
            assert conn.remote_peer_id is not None
            self.connections[conn.remote_peer_id] = conn
        self.logger and self.logger(f"[Peer {self.peer_id}] registered connection to {conn.remote_peer_id}")

    def connect_to(self, host: str, port: int) -> Optional[Connection]:
        try:
            conn = Connection.connect_outgoing(host, port, self)
            #registration occurs on handshake reply
            return conn
        except Exception as e:
            self.logger and self.logger(f"[Peer] connect_to error: {e}")
            return None
    
    def get_connection(self, peer_id: str) -> Optional[Connection]:
        with self._conn_lock:
            return self.connections.get(peer_id)
    
    def send_text(self, to_peer_id: str, text: str):
        conn = self.get_connection(to_peer_id)
        if conn is None:
            raise ValueError("not connected to peer")
        payload = {
            "type" : "text",
            "from" : self.peer_id,
            "content" : text,
            "ts": int(__import__("time").time())
        }
        conn.send_json(payload)
    
    def broadcast_peer_list(self):
        peers = list(self.connections.keys())
        payload = {
            "type" : "peer_list",
            "peers" : "peers",
            "from" : self.peer_id,
        }
        with self._conn_lock:
            for conn in list(self.connections.values()):
                conn.send_json(payload)
                
    # -------------------- incoming messages entrypoint ---------------------
    def handle_incoming_message(self, conn: Connection, plaintext: bytes):
        """
        Called by Connection when a decrypted messages is ready.
        """
        self.msg_handler.process_message(conn, plaintext)
    
    #--------------------------- shutdown ---------------------------------
    def stop(self):
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        with self._conn_lock:
            for c in list(self.connections.values()):
                try:
                    c.close()
                except Exception:
                    pass
        self.logger and self.logger(f"[Peer {self.peer_id}] stopped")
        
    # -------------------------- event ----------------------------
    def on_message(self, sender, content, ts, conn):
        pass

    def on_peer_list(self, peers):
        pass