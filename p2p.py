import sys
import socket
import threading
import os
import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QFileDialog, QListWidget, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import QTimer
from utils import onion_encrypt, onion_decrypt, calculate_checksum

connections = {}
online_peers = set()
incoming_messages = {}  # ip -> list of messages
current_chat_peer = None
PORT = 0
USERNAME = ""
HISTORY_FILE = "history.txt"
PEERS_FILE = "config.json"
lock = threading.Lock()


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

            except:
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
        threading.Thread(target=handle_client, args=(s, (ip, port)), daemon=True).start()
        return s
    except:
        return None

def broadcast_peers():
    try:
        with open(PEERS_FILE) as f:
            config = json.load(f)
        for peer in config["peers"]:
            ip, port = peer["ip"], peer["port"]
            if port != PORT:
                connect_to_peer(ip, port)
    except:
        pass


class MessengerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("P2P Messenger - PyQt5")
        self.resize(600, 500)
        self.current_peer = None
        self.init_login_ui()

    def init_login_ui(self):
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter your port")
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_app)

        self.layout.addWidget(QLabel("Username:"))
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(QLabel("Port:"))
        self.layout.addWidget(self.port_input)
        self.layout.addWidget(self.start_button)

    def start_app(self):
        global PORT, USERNAME
        try:
            USERNAME = self.username_input.text()
            PORT = int(self.port_input.text())
        except:
            QMessageBox.critical(self, "Error", "Invalid input")
            return

        threading.Thread(target=server_thread, daemon=True).start()
        broadcast_peers()
        self.init_main_ui()

    def init_main_ui(self):
        for i in reversed(range(self.layout.count())):
            self.layout.itemAt(i).widget().setParent(None)

        self.label = QLabel(f"Welcome {USERNAME}")
        self.notification_label = QLabel("")
        self.user_list = QListWidget()
        self.refresh_btn = QPushButton("Refresh")
        self.chat_btn = QPushButton("Chat")
        self.history_btn = QPushButton("Show History")

        self.refresh_btn.clicked.connect(self.refresh_users)
        self.chat_btn.clicked.connect(self.open_chat_window)
        self.history_btn.clicked.connect(self.show_history)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.notification_label)
        self.layout.addWidget(self.user_list)
        self.layout.addWidget(self.refresh_btn)
        self.layout.addWidget(self.chat_btn)
        self.layout.addWidget(self.history_btn)

        self.notification_timer = QTimer()
        self.notification_timer.timeout.connect(self.check_notifications)
        self.notification_timer.start(1000)

    def refresh_users(self):
        self.user_list.clear()
        # try:
        #     with open(PEERS_FILE) as f:
        #         config = json.load(f)
        #     for peer in config["peers"]:
        #         ip, port = peer["ip"], peer["port"]
        #         if port == PORT:
        #             continue
        #         connect_to_peer(ip, port)
        # except Exception as e:
        #     QMessageBox.critical(self, "Error", f"Failed to read config: {e}")

        with lock:
            for ip in sorted(online_peers):
                # if ip != "127.0.0.1":
                self.user_list.addItem(ip)





    def show_history(self):
        msg = load_history()
        QMessageBox.information(self, "Chat History", msg or "No messages.")

    def check_notifications(self):
        for ip, msgs in incoming_messages.items():
            if msgs and ip != self.current_peer:
                self.notification_label.setText(f"🔔 New message from {ip}")
                return
        self.notification_label.setText("")

    def open_chat_window(self):
        selected = self.user_list.currentItem()
        if not selected:
            return
        ip = selected.text()
        self.current_peer = ip
        self.chat_window = ChatWindow(self, ip)
        self.chat_window.show()


class ChatWindow(QWidget):
    def __init__(self, parent, peer_ip):
        super().__init__()
        self.parent = parent
        self.peer_ip = peer_ip
        self.setWindowTitle(f"Chat with {peer_ip}")
        self.resize(600, 400)
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout()
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.msg_input = QLineEdit()
        self.send_btn = QPushButton("Send")
        self.file_btn = QPushButton("Send File")

        self.send_btn.clicked.connect(self.send_msg)
        self.file_btn.clicked.connect(self.send_file)

        hbox = QHBoxLayout()
        hbox.addWidget(self.msg_input)
        hbox.addWidget(self.send_btn)

        self.layout.addWidget(self.chat_area)
        self.layout.addLayout(hbox)
        self.layout.addWidget(self.file_btn)
        self.setLayout(self.layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_chat)
        self.timer.start(1000)

    def update_chat(self):
        msgs = incoming_messages.get(self.peer_ip, [])
        if msgs:
            for msg in msgs:
                self.chat_area.append(f"{self.peer_ip}: {msg}")
            incoming_messages[self.peer_ip] = []

    def send_msg(self):
        msg = self.msg_input.text()
        if not msg:
            return
        content = msg.encode('utf-8')
        checksum = calculate_checksum(content)
        encrypted = onion_encrypt(content)
        header = f"TEXT::{checksum}:".encode('utf-8')
        try:
            connections[self.peer_ip].sendall(header + encrypted)
            save_message(f"You -> {self.peer_ip}: {msg}")
            self.chat_area.append(f"You: {msg}")
        except:
            QMessageBox.critical(self, "Error", "Failed to send message")
        self.msg_input.clear()

    def send_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                content = f.read()
            filename = os.path.basename(path)
            checksum = calculate_checksum(content)
            encrypted = onion_encrypt(content)
            header = f"FILE:{filename}:{checksum}:".encode('utf-8')
            connections[self.peer_ip].sendall(header + encrypted)
            save_message(f"You sent file: {filename}")
            self.chat_area.append(f"You sent file: {filename}")
        except:
            QMessageBox.critical(self, "Error", "Failed to send file")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MessengerGUI()
    window.show()
    sys.exit(app.exec_())
