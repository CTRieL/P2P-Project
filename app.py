import os
import sys
import threading
import time

from p2p.p2p import P2PMessenger
from gui import ChatGUI

def main():
    if len(sys.argv) < 3:
        print("invalid command: python app.py <PORT> <USERNAME> [OPTIONS]")
        print("Options:")
        print("  -v, --debug    Aktifkan mode log raw")
        print("  --gui          Aktifkan mode GUI") 
        return
    
    port = int(sys.argv[1])
    username = sys.argv[2]
    verbose_mode = False
    gui_mode = False
        
    verbose_mode = False
    if len(sys.argv) > 3:
        if '-v' in sys.argv or '--debug' in sys.argv:
            print("[!] Mode verbose aktif!")
            verbose_mode = True
        if '--gui' in sys.argv:
            print("[!] Mode GUI aktif")
            gui_mode = True
    
    if not os.path.exists('downloads'):
        os.makedirs('downloads')   
    
    messenger = P2PMessenger(port, username, verbose=verbose_mode)    
    if gui_mode:
        gui = ChatGUI(messenger)
        messenger.callback = gui.handle_p2p_event
        messenger.start_threads_only()

        cli_thread = threading.Thread(target=messenger.input_loop, daemon=True)
        cli_thread.start()
        
        gui.start()
        
    print("=== P2P Messenger ===")
    app = P2PMessenger(int(sys.argv[1]), sys.argv[2], verbose=verbose_mode)
    app.start()

if __name__ == "__main__":
    main()