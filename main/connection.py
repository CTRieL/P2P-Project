import socket
import threading
import struct
import json
import queue
from typing import Optional
from main.peer import Peer
from main.message_handler import MessageHandler
from main.encryption.hybrid_crypto import encrypt_message, decrypt_message # in proggress

LENGTH_PREFIX_FORMAT = "!I" #network byte order unsigned int (4 bytes)

def send_with_length(sock: socket.socket, data: bytes):
    header = struct.pack(LENGTH_PREFIX_FORMAT, len(data))
    sock.sendall(header + data)

def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_message_with_length(sock: socket.socket) -> Optional[bytes]:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(LENGTH_PREFIX_FORMAT, header)
    if length == 0:
        return b""
    return recv_exact(sock, length)


class Connection:
    """
    Represents a connection (incoming or outgoing) to a remote peer.
    Handles low-level recv loop, decryption, and an outgoing sender thread.
    """
    def __init__(self, 
                 sock: socket.socket, 
                 local_peer: Peer, 
                 remote_peer_id: Optional[str] = None, 
                 remote_public_key_pem: Optional[bytes] = None):
        
        self.sock = sock
        self.local_peer = local_peer
        self.remote_peer_id = remote_peer_id
        self.remote_public_key_pem = remote_public_key_pem
        self.alive = True
        
        self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._send_queue = queue.Queue()
        self._send_thread = threading.Thread(target=self._send_loop, daemon=True)
    
    @classmethod
    def connect_outgoing(cls, host: str, port: int, local_peer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        conn = cls(sock=sock, local_peer=local_peer)
        conn.start()
        conn.send_handshake()
        return conn
    
    def start(self):
        self._recv_thread.start()
        self._send_thread.start()
    
    def start_receiver_thread(self):
        # just alias for self.start, for debugging
        self.start()
    
    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        
    #-------------------- sending --------------------------------------
    def _send_loop(self):
        while self.alive:
            try:
                msg_bytes = self._send_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                #encrypt for remote (require remote public key)
                if self.remote_public_key_pem is None:
                    send_with_length(self.sock, msg_bytes)
                else:
                    enc = encrypt_message(msg_bytes, self.remote_public_key_pem)
                    send_with_length(self.sock, enc)
            except Exception as e:
                # if fail -> close & notify peer
                self.local_peer.logger and self.local_peer.logger(f"[Connection] send error: {e}")
                self.close()
                break
            
    def send_raw(self, data:bytes):
        """Put raw bytes to send queue (this will be encrypted if remote key known)"""
        self._send_queue.put(data)
    
    def send_json(self, obj: dict):
        b = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
        self.send_raw(b)
    
    def send_handshake(self):
        """Send handshake messsage (plaintext JSON) containing identity & public key PEM"""
        payload = {
            "type" : "handshake",
            "peer_id" : self.local_peer.peer_id,
            "public_key_pem" : self.local_peer.public_key_pem.decode() # if byte
        }
        send_with_length(self.sock, json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
        #doo not queue via send_queue! handshake is unencrypted so remote can read it before learn their key
        
    
    # -------------------------- recevie ------------------------
    def _receive_loop(self):
        while self.alive:
            try:
                data = recv_message_with_length(self.sock)
                if data is None:
                    #remote closed
                    self.local_peer.logger and self.local_peer.logger(f"[Connection] remote closed")
                    self.close()
                    break
                
                # try parse as JSON handshake plaintext first
                try:
                    # handshake is snet as plaintext JSON (no ecryption)
                    decoded = data.decode()
                    maybe = json.loads(decoded)
                    if maybe.get("type") == "handshake":
                        #handle handshake
                        self._handle_handshake_payload(maybe)
                        continue
                except Exception:
                    # if JSON handshake is not plaintext -> assume encrypted hybrid payload
                    pass
                
                # try decrypt using local private key -> return plaintext bytes
                try:
                    plaintext = decrypt_message(data, self.local_peer.private_key_pem)
                except Exception as e:
                    self.local_peer.logger and self.local_peer.logger(f"[Connection] decrypt error: {e}")
                    continue
                
                # deliver to peer for further handling
                try:
                    self.local_peer.handle_incoming_message(self, plaintext)
                except Exception as e:
                    self.local_peer.logger and self.local_peer.logger(f"[Connection] handler error: {e}")
            
            except Exception as e:
                self.local_peer.logger and self.local_peer.logger(f"[Connection] recevie loop fatal: {e}")
                self.close()
                break
            
    def _handle_handshake_payload(self, payload: dict):
        remote_id = payload.get("peer_id")
        remote_pub_pem_str = payload.get("public_key_pem")
        if not remote_id or not remote_pub_pem_str:
            return
        self.remote_peer_id = remote_id
        self.remote_public_key_pem = remote_pub_pem_str.encode()
        
        #register connection at local peer
        self.local_peer.register_connection(self)
        # respond with handshake if this was incoming (to make sure remote also knows out pubkey)
        # If we haven't send handshek yet, send one (avoid duplicate)
        # NOTE: we already send handshake for outgoing connections in connection_outgoing
        #for incoming connections, send handshake reply:
        try:
            if self.local_peer and self.local_peer.peer_id:
                # send handshake back (plaintext)
                payyload = {
                    "type" : "handshake",
                    "peer_id" : self.local_peer.peer_id,
                    "public_key_pem" : self.local_peer.public_key_pem.decode()
                }
                send_with_length(self.sock, json.dumps(payload, separators=(",",":"), ensure_ascii=False).encode())
        except Exception:
            pass