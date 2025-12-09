import threading
import time
import sys
from p2p.p2p import P2PMessenger

def main():
    if len(sys.argv) < 3:
        print("invalid command: python app.py <PORT> <USERNAME>")
        return
    
    print("=== P2P Messenger ===")
    app = P2PMessenger(int(sys.argv[1]), sys.argv[2])
    app.start()

if __name__ == "__main__":
    main()