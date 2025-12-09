import os
import sys
from p2p.p2p import P2PMessenger

def main():
    if len(sys.argv) < 3:
        print("invalid command: python app.py <PORT> <USERNAME> [OPTIONS]")
        print("Options:")
        print("  -v, --debug    Aktifkan mode log raw")
        return
    
    verbose_mode = False
    if len(sys.argv) > 3 and (sys.argv[3] == '-v' or sys.argv[3] == '--debug'):
        verbose_mode = True
    
    if verbose_mode:
        print("[!] Mode Verbose aktif!")
        
    if not os.path.exists('downloads'):
        os.makedirs('downloads')
        
    print("=== P2P Messenger ===")
    app = P2PMessenger(int(sys.argv[1]), sys.argv[2], verbose=verbose_mode)
    app.start()

if __name__ == "__main__":
    main()