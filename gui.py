import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import socket
import threading
import json
import os

# Global variables
connections = {}
online_peers = set()
incoming_messages = {}  # ip -> list of messages
lock = threading.Lock()
PORT = 0
USERNAME = ""

# Save/load message history
def save_message(ip, msg, is_sent):
    filename = f"chat_{ip}.txt"
    with open(filename, "a", encoding="utf-8") as f:
        prefix = "[You]" if is_sent else f"[{ip}]"
        f.write(f"{prefix} {msg}\n")

def load_message_history(ip):
    filename = f"chat_{ip}.txt"
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            return f.read()
    return ""

# Client handler for receiving messages
def handle_client(sock, ip):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            msg = data.decode("utf-8")
            save_message(ip, msg, is_sent=False)
            with lock:
                if ip in incoming_messages:
                    incoming_messages[ip].append(msg)
                else:
                    incoming_messages[ip] = [msg]
        except:
            break
    with lock:
        online_peers.discard(ip)
        if ip in connections:
            del connections[ip]

# Accept incoming connections
def accept_connections(server_socket):
    while True:
        client_socket, addr = server_socket.accept()
        ip = addr[0]
        with lock:
            connections[ip] = client_socket
            online_peers.add(ip)
        threading.Thread(target=handle_client, args=(client_socket, ip), daemon=True).start()

# Send message to a peer
def send_message(ip, msg):
    if ip in connections:
        try:
            connections[ip].sendall(msg.encode("utf-8"))
            save_message(ip, msg, is_sent=True)
        except:
            pass

# Try to connect to all peers from config.json
def connect_to_peers():
    try:
        with open("config.json") as f:
            config = json.load(f)
    except:
        return

    for peer in config.get("peers", []):
        ip = peer["ip"]
        port = peer["port"]
        if ip == "127.0.0.1":
            continue
        if ip not in connections:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                connections[ip] = s
                with lock:
                    online_peers.add(ip)
                threading.Thread(target=handle_client, args=(s, ip), daemon=True).start()
            except:
                continue

# Main GUI class
class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Messenger")
        self.current_chat_ip = None
        self.setup_login()

    def setup_login(self):
        self.clear()
        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack()

        tk.Button(self.root, text="Start", command=self.start_app).pack(pady=10)

    def start_app(self):
        global PORT, USERNAME
        try:
            USERNAME = self.username_entry.get()
            PORT = int(self.port_entry.get())
        except:
            messagebox.showerror("Error", "Invalid port")
            return

        # Start server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", PORT))
        s.listen(5)
        threading.Thread(target=accept_connections, args=(s,), daemon=True).start()

        threading.Thread(target=connect_to_peers, daemon=True).start()
        self.setup_main()

    def setup_main(self):
        self.clear()
        tk.Label(self.root, text=f"Welcome {USERNAME}", font=("Arial", 14)).pack(pady=5)

        self.peer_listbox = tk.Listbox(self.root, width=40)
        self.peer_listbox.pack(pady=5)

        tk.Button(self.root, text="Refresh Online Users", command=self.refresh_peers).pack()
        tk.Button(self.root, text="Chat with Selected", command=self.open_chat).pack(pady=5)

    def refresh_peers(self):
        self.peer_listbox.delete(0, tk.END)
        connect_to_peers()
        with lock:
            for ip in sorted(online_peers):
                if ip != "127.0.0.1":
                    self.peer_listbox.insert(tk.END, ip)

    def open_chat(self):
        selection = self.peer_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select a user")
            return

        ip = self.peer_listbox.get(selection[0])
        self.current_chat_ip = ip

        self.clear()
        tk.Label(self.root, text=f"Chat with {ip}", font=("Arial", 12)).pack()

        self.chat_box = scrolledtext.ScrolledText(self.root, width=60, height=20)
        self.chat_box.pack()
        self.chat_box.insert(tk.END, load_message_history(ip))
        self.chat_box.config(state=tk.DISABLED)

        self.msg_entry = tk.Entry(self.root, width=50)
        self.msg_entry.pack(pady=5)

        tk.Button(self.root, text="Send", command=self.send_msg).pack()
        tk.Button(self.root, text="Back", command=self.setup_main).pack(pady=5)

        self.check_new_messages()

    def send_msg(self):
        msg = self.msg_entry.get()
        if not msg:
            return
        send_message(self.current_chat_ip, msg)
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, f"[You] {msg}\n")
        self.chat_box.config(state=tk.DISABLED)
        self.msg_entry.delete(0, tk.END)

    def check_new_messages(self):
        ip = self.current_chat_ip
        if ip in incoming_messages:
            self.chat_box.config(state=tk.NORMAL)
            for msg in incoming_messages[ip]:
                self.chat_box.insert(tk.END, f"[{ip}] {msg}\n")
            incoming_messages[ip] = []
            self.chat_box.config(state=tk.DISABLED)
        self.root.after(1000, self.check_new_messages)

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()
