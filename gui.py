import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading

from p2p.p2p import P2PMessenger

# --- KONFIGURASI WARNA ---
class COLORS: 
    BG_ROOT = "#313338"         
    BG_SIDEBAR = "#2b2d31"      
    BG_CHAT = "#313338"         
    BG_INPUT = "#383a40"        
    ACCENT = "#5865F2"          
    ACCENT_HOVER = "#4752c4"
    RED_DANGER = "#DA373C"
    TEXT_MAIN = "#dbdee1"       
    TEXT_SUB = "#949ba4"        
    BUBBLE_ME = "#5865F2"       
    BUBBLE_PEER = "#4e5058"     
    SCROLLBAR = "#1e1f22"       
    ITEM_HOVER = "#35373c"

# --- ATUR RESOLUSI TINGGI ---
try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1) 
except:
    pass

class ChatGUI:
    def __init__(self, messenger:P2PMessenger):
        self.messenger = messenger
        
        # Setup Root Window
        self.root = tk.Tk()
        self.root.title(f"P2P Messenger - {messenger.username}")
        self.root.geometry("1000x700")
        self.root.configure(bg=COLORS.BG_ROOT)
        
        self.font_main = ("Segoe UI Emoji", 11)
        self.font_bold = ("Segoe UI Emoji", 11, "bold")
        self.font_small = ("Segoe UI Emoji", 9)
        
        self.setup_styles()
        
        # --- LAYOUT UTAMA ---
        self.main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg="#202225", sashwidth=4, bd=0)
        self.main_pane.pack(fill=tk.BOTH, expand=True)
        
        # 1. PANEL KIRI (SIDEBAR)
        self.sidebar = tk.Frame(self.main_pane, bg=COLORS.BG_SIDEBAR, width=125)
        self.main_pane.add(self.sidebar, minsize=75)
        
        tk.Label(self.sidebar, text="Active Peers", font=("Segoe UI", 14, "bold"), 
                 bg=COLORS.BG_SIDEBAR, fg=COLORS.TEXT_MAIN, pady=20).pack(fill=tk.X, padx=15)
        
        # --- List Peer ---
        self.list_canvas_frame = tk.Frame(self.sidebar, bg=COLORS.BG_SIDEBAR)
        self.list_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=5)

        self.canvas = tk.Canvas(self.list_canvas_frame, bg=COLORS.BG_SIDEBAR, bd=0, highlightthickness=0)
        self.scrollbar_list = ttk.Scrollbar(self.list_canvas_frame, orient="vertical", command=self.canvas.yview)
        
        self.scrollable_frame = tk.Frame(self.canvas, bg=COLORS.BG_SIDEBAR)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=250)
        self.canvas.configure(yscrollcommand=self.scrollbar_list.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar_list.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.bind('<Configure>', self._on_canvas_configure)

        self.btn_refresh = tk.Button(self.sidebar, text="↻ Refresh List", font=self.font_bold,
            bg=COLORS.BG_INPUT, fg=COLORS.TEXT_MAIN, bd=0, activebackground=COLORS.BG_ROOT, activeforeground="white",
            cursor="hand2", command=self.refresh_peers_ui)
        self.btn_refresh.pack(fill=tk.X, padx=10, pady=20, ipady=5)

        # 2. PANEL KANAN (CHAT AREA)
        self.right_frame = tk.Frame(self.main_pane, bg=COLORS.BG_CHAT, width=1000)
        self.main_pane.add(self.right_frame, minsize=600)

        # --- Header Chat ---
        self.header_frame = tk.Frame(self.right_frame, bg=COLORS.BG_CHAT, height=60)
        self.header_frame.pack(side=tk.TOP, fill=tk.X)
        self.header_frame.pack_propagate(False)
        
        self.lbl_status = tk.Label(self.header_frame, text="Not Connected", font=("Segoe UI", 12, "bold"),
            bg=COLORS.BG_CHAT, fg=COLORS.TEXT_SUB)
        self.lbl_status.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Tombol Disconnect
        self.btn_disconnect = tk.Button(self.header_frame, text="Disconnect", font=("Segoe UI", 10, "bold"),
            bg=COLORS.RED_DANGER, fg="white", bd=0, cursor="hand2", state=tk.DISABLED,
            command=self.disconnect_action)
        self.btn_disconnect.pack(side=tk.RIGHT, padx=20, pady=15)

        tk.Frame(self.right_frame, bg="#202225", height=1).pack(fill=tk.X)

        # --- Input Area ---
        self.input_container = tk.Frame(self.right_frame, bg=COLORS.BG_CHAT, pady=20, padx=20)
        self.input_container.pack(side=tk.BOTTOM, fill=tk.X)

        self.btn_file = tk.Button(self.input_container, text="+", font=("Segoe UI", 16),
            bg=COLORS.BG_INPUT, fg=COLORS.TEXT_MAIN, bd=0, activebackground=COLORS.ACCENT, activeforeground="white",
            width=3, cursor="hand2", command=self.send_file_action)
        self.btn_file.pack(side=tk.LEFT, padx=(0, 10))

        self.entry_msg = tk.Entry(self.input_container, font=("Segoe UI", 12),
            bg=COLORS.BG_INPUT, fg=COLORS.TEXT_MAIN, insertbackground="white", bd=0, relief=tk.FLAT)
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10)
        self.entry_msg.bind("<Return>", self.send_msg_action)

        self.btn_send = tk.Button(self.input_container, text="➤", font=("Segoe UI", 12),
            bg=COLORS.ACCENT, fg="white", bd=0, activebackground=COLORS.ACCENT_HOVER, activeforeground="white",
            width=5, cursor="hand2", command=self.send_msg_action)
        self.btn_send.pack(side=tk.LEFT, padx=(10, 0), ipady=5)

        # --- Chat History ---
        self.chat_container = tk.Frame(self.right_frame, bg=COLORS.BG_CHAT)
        self.chat_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.scrollbar = ttk.Scrollbar(self.chat_container, orient="vertical")
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.chat_area = tk.Text(self.chat_container, font=self.font_main, bg=COLORS.BG_CHAT, fg=COLORS.TEXT_MAIN,
            bd=0, highlightthickness=0, state=tk.DISABLED, wrap=tk.WORD,
            yscrollcommand=self.scrollbar.set, padx=10, pady=10)
        self.chat_area.pack(fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.chat_area.yview)

        self.configure_tags()
        self.start_auto_refresh()

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas.find_all()[0], width=event.width)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vertical.TScrollbar", gripcount=0,
                        background=COLORS.BG_SIDEBAR, darkcolor=COLORS.BG_SIDEBAR, lightcolor=COLORS.BG_SIDEBAR,
                        troughcolor=COLORS.BG_CHAT, bordercolor=COLORS.BG_CHAT, arrowcolor=COLORS.TEXT_SUB)
        style.configure("Sash", sashthickness=4, sashpad=0, handlepad=0)

    def configure_tags(self):
        # [FIX] BUBBLE WIDTH ISSUE
        # Jangan set 'background' di tag alignment (me/peer). Biarkan transparan.
        # Warna background hanya dipasang di tag 'bubble_me'/'bubble_peer'.
        
        self.chat_area.tag_config('me', justify='right', 
                                  rmargin=10, lmargin1=100) # Hapus background di sini
        
        self.chat_area.tag_config('peer', justify='left', 
                                  lmargin1=10, rmargin=100) # Hapus background di sini
        
        self.chat_area.tag_config('sys', justify='center', foreground=COLORS.TEXT_SUB, font=("Segoe UI", 9, "italic"), spacing1=5, spacing3=5)
        
        # Pewarnaan teks bubble
        self.chat_area.tag_config('bubble_me', background=COLORS.ACCENT, foreground="white")
        self.chat_area.tag_config('bubble_peer', background=COLORS.BUBBLE_PEER, foreground="white")

    def start(self):
        self.root.mainloop()

    # --- LOGIC ---
    def refresh_peers_ui(self):
        active_peers = self.messenger.discovery.get_active_peers()
        for widget in self.scrollable_frame.winfo_children(): widget.destroy()
        if not active_peers:
            tk.Label(self.scrollable_frame, text="Searching...", bg=COLORS.BG_SIDEBAR, fg=COLORS.TEXT_SUB, font=self.font_small).pack(pady=20)
            return
        for peer_str in active_peers:
            try:
                parts = peer_str.split(" -> ")
                username = parts[0]
                ip, port = parts[1].split(":")
                self.create_peer_item(username, ip, port)
            except: continue

    def create_peer_item(self, username, ip, port):
        item_frame = tk.Frame(self.scrollable_frame, bg=COLORS.BG_SIDEBAR, cursor="hand2")
        item_frame.pack(fill=tk.X, pady=2, padx=5)
        
        avatar = tk.Label(item_frame, text=username[0].upper(), font=("Segoe UI", 12, "bold"), bg="#5865F2", fg="white", width=4, height=2)
        avatar.pack(side=tk.LEFT, padx=(5, 10), pady=5)
        
        text_frame = tk.Frame(item_frame, bg=COLORS.BG_SIDEBAR)
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5)
        
        tk.Label(text_frame, text=username, font=self.font_bold, bg=COLORS.BG_SIDEBAR, fg=COLORS.TEXT_MAIN, anchor="w").pack(fill=tk.X)
        tk.Label(text_frame, text=f"{ip}:{port}", font=self.font_small, bg=COLORS.BG_SIDEBAR, fg=COLORS.TEXT_SUB, anchor="w").pack(fill=tk.X)

        widgets = [item_frame, avatar, text_frame] + list(text_frame.winfo_children())
        for w in widgets:
            w.bind("<Button-1>", lambda e, i=ip, p=port, u=username: self.confirm_connect(i, p, u))
            w.bind("<Enter>", lambda e, f=item_frame: f.configure(bg=COLORS.ITEM_HOVER))
            w.bind("<Leave>", lambda e, f=item_frame: f.configure(bg=COLORS.BG_SIDEBAR))

    def start_auto_refresh(self):
        self.refresh_peers_ui()
        self.root.after(3000, self.start_auto_refresh)

    def confirm_connect(self, ip, port, username):
        if self.messenger.connected_peer_socket:
             if not messagebox.askyesno("Connect", f"Putus koneksi saat ini dan chat dengan {username}?"):
                 return
             self.messenger.disconnect()
        
        self.clear_chat_area()
        self.lbl_status.config(text=f"Connecting to {username}...", fg=COLORS.TEXT_SUB)
        threading.Thread(target=self.messenger.connect_to_peer, args=(ip, port)).start()

    def disconnect_action(self):
        if self.messenger.connected_peer_socket:
            if messagebox.askyesno("Disconnect", "Akhiri percakapan?"):
                self.messenger.disconnect() # Ini akan memicu event 'DISCONNECT'

    def clear_chat_area(self):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.delete("1.0", tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def send_msg_action(self, event=None):
        msg = self.entry_msg.get()
        if not msg.strip(): return
        if self.messenger.connected_peer_socket:
            try:
                encrypted = self.messenger.security.encrypt_chat(msg)
                self.messenger.send_packet(self.messenger.connected_peer_socket, {
                    "type": "MESSAGE", "sender": self.messenger.username, "content": encrypted
                })
                self.add_bubble(msg, "me")
                self.entry_msg.delete(0, tk.END)
            except Exception as e: self.add_system_msg(f"Error: {e}")
        else: self.add_system_msg("Belum terhubung.")

    def send_file_action(self):
        if not self.messenger.connected_peer_socket:
            messagebox.showwarning("Warning", "Belum terhubung!")
            return  
        filepath = filedialog.askopenfilename()
        if filepath:
            threading.Thread(target=self.messenger.send_file, args=(filepath,)).start()
            self.add_bubble(f"Mengirim file: {filepath}...", "me")

    # --- UI UPDATES ---
    def handle_p2p_event(self, event_type, data):
        self.root.after(0, lambda: self._process_event(event_type, data))

    def _process_event(self, event_type, data):
        if event_type == "CONNECTED":
            self.lbl_status.config(text=f"{data}", fg="#23a559")
            self.btn_disconnect.config(state=tk.NORMAL) # Aktifkan tombol disconnect
            self.clear_chat_area()
            self.add_system_msg(f"--- Enkripsi End-to-End Aktif ---")
            
        elif event_type == "DISCONNECT":
            self.lbl_status.config(text="Disconnected", fg=COLORS.TEXT_SUB)
            self.btn_disconnect.config(state=tk.DISABLED) # Matikan tombol disconnect
            self.add_system_msg("--- Koneksi Terputus ---")
            
        elif event_type == "MESSAGE":
            self.add_bubble(f"{data['text']}", "peer")

        elif event_type == "FILE":
            self.add_bubble(f"📎 File: {data['filename']}", "peer")

    def add_bubble(self, text, tag):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, "\n")
        
        # Spacer Logic agar bubble tidak nempel ke pinggir
        bubble_tag = "bubble_me" if tag == "me" else "bubble_peer"
        align_tag = "me" if tag == "me" else "peer"
        
        padded_text = f"  {text}  " 
        self.chat_area.insert(tk.END, padded_text, (align_tag, bubble_tag))
        self.chat_area.insert(tk.END, "\n", align_tag)
        
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)

    def add_system_msg(self, text):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, f"\n{text}\n", "sys")
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)