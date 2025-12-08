import threading
import time
from network import P2PNode
from security import Cipher

def main():
    print("=== P2P Messenger ===")
    SHARED_KEY = b'8_wDv1q3-v0jOQk9_ujZq_x4gQf8xXy9-zJk_Lv0oqs='
    cipher = Cipher(key=SHARED_KEY)
    
    port = int(input("Port Anda: "))
    peer_ip = input("IP Tujuan: ")
    peer_port = int(input("Port Tujuan: "))

    node = P2PNode(port, peer_ip, peer_port, cipher)

    server_thread = threading.Thread(target=node.start)
    server_thread.daemon = True #agar thread mati bila program ditutup
    server_thread.start()

    time.sleep(1)
    print("\nServer aktif! Ketik 'exit' untuk kealuar.\n")

    while True:
        msg = input("Anda: ")
        if msg.lower() == 'exit':
            break
        node.send_message(msg)

if __name__ == "__main__":
    main()