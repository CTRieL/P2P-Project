import json
import time
from typing import Any
from core.connection import Connection
from core.peer import Peer

class MessageHandler:
    """
    High-level message protocol handling. All plaintext messages come in as bytes.
    EXPECTING plaintext JSON messages with a 'type' field
    """
    
    def __init__(self, peer: Peer):
        self.peer = peer
        
    def process_message(self, conn: Connection, plaintext: bytes):
        try:
            data = json.loads(plaintext.decode())
        except Exception as e:
            # if not JSON -> ignore & log
            self.peer.logger and self.peer.logger(f"[MsgHandler] invalid JSON: {e}")
            return
        
        msg_type = data.get("type")
        if msg_type == "text":
            self._handle_text(conn, data)
        elif msg_type == "ping":
            self._handle_ping(conn, data)
        elif msg_type == "peer_list":
            self._handle_peer_list(conn, data)
        else:
            #unknown, can be for application-level messages
            self._handle_else(conn, data)
        
    def _handle_text(self, conn: Connection, data: dict):
        sender = data.get("from")
        content = data.get("content")
        ts = data.get("ts")
        self.peer.logger and self.peer.logger(f"[{self.peer.peer_id}] recv text from {sender}: {content} (ts={ts})")

        # the peer can call a callback or UI hook if present
        if hasattr(self.peer, "on_message"):
            try:
                self.peer.on_message(sender, content, ts, conn)
            except Exception as e:
                self.peer.logger and self.peer.logger(f"[MsgHandler] on_message callback error: {e}")

    def _handle_ping(self, conn: Connection, data: dict):
        reply = {
            "type" : "pong", 
            "ts": int(time.time()), 
            "from" : self.peer.peer_id
        }
        conn.send_json(reply)
    
    def _handle_peer_list(self, conn: Connection, data: dict):
        peers = data.get("peers", [])
        self.peer.logger and self.peer.logger(f"[{self.peer.peer_id}] received peer list: {peers}")

        # pass to peer discovery / book-keeping
        if hasattr(self.peer, "on_peer_list"):
            try:
                self.peer.on_peer_list(peers)
            except Exception as e:
                self.peer.logger and self.peer.logger(f"[MsgHandler] on_peer_list error: {e}")

    
    def _handle_else(self, conn: Connection, data: dict):
        # handler for other messages types
        mtype = data.get("type", "<no-type>")
        self.peer.logger and self.peer.logger(f"[{self.peer.peer_id}] unknown messages type {mtype} : {data}")