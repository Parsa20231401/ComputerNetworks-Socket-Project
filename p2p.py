import sys
import socket
import threading
import os
import json
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QFileDialog, QListWidget, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from PyQt5.QtMultimediaWidgets import QVideoWidget
from PyQt5.QtCore import QUrl
from utils import onion_encrypt, onion_decrypt, calculate_checksum

# Setup logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_filename = os.path.join(log_dir, f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.report")

logging.basicConfig(
    filename=log_filename,
    filemode='w',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info("P2P Messenger started.")

connections = {}
online_peers = set()
incoming_messages = {}
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

def recvall(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            break
        data += part
    return data

def handle_client(conn, addr):
    ip = addr[0]
    with conn:
        with lock:
            online_peers.add(ip)
            connections[ip] = conn

        while True:
            try:
                raw_len = recvall(conn, 4)
                if not raw_len:
                    break
                header_len = int.from_bytes(raw_len, 'big')
                header = json.loads(recvall(conn, header_len).decode())
                payload = recvall(conn, header['length'])

                logging.debug(f"Received encrypted payload from {ip}")

                decrypted = onion_decrypt(payload)
                real_checksum = calculate_checksum(decrypted)

                if header['checksum'] != real_checksum:
                    logging.warning(f"Checksum mismatch from {ip}")
                    continue

                if header['type'] == "TEXT":
                    message = decrypted.decode('utf-8')
                    logging.info(f"Received TEXT message from {ip}: {message}")
                    save_message(f"{ip}: {message}")
                    incoming_messages.setdefault(ip, []).append(message)
                elif header['type'] == "FILE":
                    os.makedirs("media", exist_ok=True)
                    path = os.path.join("media", header['filename'])
                    with open(path, 'wb') as f:
                        f.write(decrypted)
                    logging.info(f"Received FILE from {ip}: {header['filename']}")
                    incoming_messages.setdefault(ip, []).append(f"[Received file: {header['filename']}]")

            except Exception as e:
                logging.error(f"Error in client handler for {ip}: {e}")
                break

    with lock:
        online_peers.discard(ip)
        connections.pop(ip, None)
        logging.info(f"Disconnected from {ip}")

def server_thread():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    logging.info(f"Server listening on port {PORT}")
    while True:
        try:
            conn, addr = server.accept()
            logging.info(f"Accepted connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Error in server thread: {e}")
            break

def connect_to_peer(ip, port):
    with lock:
        if ip in connections:
            return connections[ip]
    try:
        logging.info(f"Trying to connect to peer: {ip}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        with lock:
            connections[ip] = s
            online_peers.add(ip)
        threading.Thread(target=handle_client, args=(s, (ip, port)), daemon=True).start()
        logging.info(f"Connected to peer: {ip}:{port}")
        return s
    except Exception as e:
        logging.warning(f"Failed to connect to {ip}:{port} - {e}")
        return None

def broadcast_peers():
    try:
        logging.info("Broadcasting to peers from config file.")
        with open(PEERS_FILE) as f:
            config = json.load(f)
        for peer in config["peers"]:
            ip, port = peer["ip"], peer["port"]
            if port != PORT:
                connect_to_peer(ip, port)
    except Exception as e:
        logging.error(f"Failed to broadcast peers: {e}")

# ادامه برنامه بدون تغییر اساسی، در صورت نیاز می‌توانیم logging را در سایر توابع GUI نیز اضافه کنیم.

# کدهای مربوط به GUI از این به بعد باقی می‌ماند... (همانند کد اصلی شما)

# در توابع send_msg و send_file نیز اضافه می‌شود:
# logging.info(f"Sending message to {self.peer_ip}: {msg}")
# logging.info(f"Sending file '{filename}' to {self.peer_ip}")
