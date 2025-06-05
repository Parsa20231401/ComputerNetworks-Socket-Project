import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
import threading
import json
import os
from datetime import datetime
from utils import onion_encrypt, onion_decrypt, calculate_checksum

connections = {}
PORT = 0
HISTORY_FILE = "history.txt"
PEERS_FILE = "config.json"
online_peers = set()
lock = threading.Lock()

current_chat_peer = None
incoming_messages = {}  # ip -> list of messages
USERNAME = ""

# === Backend functions from CLI logic reused ===
def save_message(msg):
    with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.now()} - {msg}\n")

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    return ""

def handle_client(conn, addr):
    ip = addr[0]
    with conn:
        with lock:
            online_peers.add(ip)
            connections[ip] = conn

        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break

                parts = data.split(b':', 3)
                if len(parts) < 4:
                    continue
                msg_type = parts[0].decode()
                filename = parts[1].decode()
                recv_checksum = parts[2].decode()
                payload = parts[3]

                decrypted = onion_decrypt(payload)
                real_checksum = calculate_checksum(decrypted)

                if recv_checksum != real_checksum:
                    continue

                if msg_type == "TEXT":
                    message = decrypted.decode('utf-8')
                    save_message(f"{ip}: {message}")
                    incoming_messages.setdefault(ip, []).append(message)
                elif msg_type == "FILE":
                    os.makedirs("media", exist_ok=True)
                    path = os.path.join("media", filename)
                    with open(path, 'wb') as f:
                        f.write(decrypted)
                    incoming_messages.setdefault(ip, []).append(f"[Received file: {filename}]")

            except Exception:
                break

    with lock:
        online_peers.discard(ip)
        connections.pop(ip, None)

def server_thread():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except:
            break

def connect_to_peer(ip, port):
    with lock:
        if ip in connections:
            return connections[ip]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        with lock:
            connections[ip] = s
            online_peers.add(ip)
        threading.Thread(target=listen_to_peer, args=(s, ip), daemon=True).start()
        return s
    except:
        return None

def listen_to_peer(sock, ip):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            parts = data.split(b':', 3)
            if len(parts) < 4:
                continue
            msg_type = parts[0].decode()
            filename = parts[1].decode()
            recv_checksum = parts[2].decode()
            payload = parts[3]

            decrypted = onion_decrypt(payload)
            real_checksum = calculate_checksum(decrypted)
            if recv_checksum != real_checksum:
                continue
            if msg_type == "TEXT":
                message = decrypted.decode('utf-8')
                save_message(f"{ip}: {message}")
                incoming_messages.setdefault(ip, []).append(message)
            elif msg_type == "FILE":
                os.makedirs("media", exist_ok=True)
                path = os.path.join("media", filename)
                with open(path, 'wb') as f:
                    f.write(decrypted)
                incoming_messages.setdefault(ip, []).append(f"[Received file: {filename}]")
    except:
        pass
    finally:
        with lock:
            connections.pop(ip, None)
            online_peers.discard(ip)

def broadcast_peers():
    with open(PEERS_FILE) as f:
        peer_config = json.load(f)
        for peer in peer_config["peers"]:
            ip, port = peer["ip"], peer["port"]
            if port != PORT:
                connect_to_peer(ip, port)

# === GUI ===
class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Messenger")
        self.current_peer = None
        self.setup_login()

    def setup_login(self):
        self.clear()
        tk.Label(self.root, text="Username:").pack()
        self.user_entry = tk.Entry(self.root)
        self.user_entry.pack()
        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack()
        tk.Button(self.root, text="Start", command=self.start_chat).pack(pady=10)

    def start_chat(self):
        global PORT, USERNAME
        try:
            USERNAME = self.user_entry.get()
            PORT = int(self.port_entry.get())
        except:
            messagebox.showerror("Error", "Invalid input")
            return
        threading.Thread(target=server_thread, daemon=True).start()
        broadcast_peers()
        self.main_ui()

    def main_ui(self):
        self.clear()
        self.notification_label = tk.Label(self.root, text="", fg="red")
        self.notification_label.pack()
        tk.Label(self.root, text=f"Welcome {USERNAME}", font=("Arial", 14)).pack(pady=5)
        self.peer_list = tk.Listbox(self.root, width=50)
        self.peer_list.pack(pady=5)
        tk.Button(self.root, text="Refresh", command=self.refresh_peers).pack()
        tk.Button(self.root, text="Chat", command=self.open_chat).pack(pady=5)
        tk.Button(self.root, text="History", command=self.show_history).pack()
        self.poll_incoming()

    def refresh_peers(self):
        self.peer_list.delete(0, tk.END)
        with lock:
            for ip in online_peers:
                self.peer_list.insert(tk.END, ip)

    def show_history(self):
        msg = load_history()
        messagebox.showinfo("Chat History", msg or "No messages.")

    def open_chat(self):
        sel = self.peer_list.curselection()
        if not sel:
            return
        ip = self.peer_list.get(sel[0])
        self.current_peer = ip
        self.clear()
        tk.Label(self.root, text=f"Chat with {ip}", font=("Arial", 12)).pack()
        self.text_area = scrolledtext.ScrolledText(self.root, width=60, height=20)
        self.text_area.pack()
        self.text_area.insert(tk.END, load_history())
        self.text_area.config(state=tk.DISABLED)
        self.msg_entry = tk.Entry(self.root, width=50)
        self.msg_entry.pack()
        tk.Button(self.root, text="Send", command=self.send_msg).pack()
        tk.Button(self.root, text="Send File", command=self.send_file).pack(pady=2)
        tk.Button(self.root, text="Back", command=self.main_ui).pack()
        self.check_new_msgs()

    def send_msg(self):
        msg = self.msg_entry.get()
        if not msg:
            return
        peer = self.current_peer
        if peer not in connections:
            messagebox.showerror("Error", "Not connected to peer")
            return
        content = msg.encode('utf-8')
        checksum = calculate_checksum(content)
        encrypted = onion_encrypt(content)
        header = f"TEXT::{checksum}:".encode('utf-8')
        try:
            connections[peer].sendall(header + encrypted)
            save_message(f"You -> {peer}: {msg}")
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, f"You: {msg}\n")
            self.text_area.config(state=tk.DISABLED)
        except:
            messagebox.showerror("Error", "Failed to send message")
        self.msg_entry.delete(0, tk.END)

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        peer = self.current_peer
        if peer not in connections:
            messagebox.showerror("Error", "Not connected")
            return
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            checksum = calculate_checksum(content)
            encrypted = onion_encrypt(content)
            filename = os.path.basename(file_path)
            header = f"FILE:{filename}:{checksum}:".encode('utf-8')
            connections[peer].sendall(header + encrypted)
            save_message(f"[You sent file: {filename}]")
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, f"[File sent: {filename}]\n")
            self.text_area.config(state=tk.DISABLED)
        except:
            messagebox.showerror("Error", "File sending failed")

    def check_new_msgs(self):
        peer = self.current_peer
        if peer in incoming_messages:
            self.text_area.config(state=tk.NORMAL)
            for msg in incoming_messages[peer]:
                self.text_area.insert(tk.END, f"{peer}: {msg}\n")
            incoming_messages[peer] = []
            self.text_area.config(state=tk.DISABLED)
        self.root.after(1000, self.check_new_msgs)

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
    def poll_incoming(self):
        for ip, messages in incoming_messages.items():
            if messages and ip != self.current_peer:
                self.notification_label.config(text=f"🔔 New message from {ip}")
                break
        else:
            self.notification_label.config(text="")
        self.root.after(1000, self.poll_incoming)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
