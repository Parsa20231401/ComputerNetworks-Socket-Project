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
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from PyQt5.QtMultimediaWidgets import QVideoWidget
from PyQt5.QtCore import QUrl
from utils import onion_encrypt, onion_decrypt, calculate_checksum
import logging

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
log_filename = os.path.join(log_dir, f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.report")

logging.basicConfig(
    filename=log_filename,
    filemode='w',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info("securie chat started.")

connections = {}  # peer_id -> socket
incoming_messages = {}  # peer_id -> list of messages
peer_info = {}  # peer_id -> {'username': str, 'ip': str, 'port': int}
current_chat_peer = None
PORT = 0
USERNAME = ""
HISTORY_FILE = "history.txt"
PEERS_FILE = "config.json"
lock = threading.Lock()


def get_peer_id(ip, port):
    """ایجاد شناسه یکتا برای هر peer"""
    return f"{ip}:{port}"


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


def handle_incoming_connection(conn, addr):
    """فقط برای دریافت پیام‌ها استفاده می‌شود"""
    client_ip = addr[0]
    
    with conn:
        while True:
            try:
                raw_len = recvall(conn, 4)
                if not raw_len:
                    break
                    
                header_len = int.from_bytes(raw_len, 'big')
                header = json.loads(recvall(conn, header_len).decode())
                payload = recvall(conn, header['length'])

                decrypted = onion_decrypt(payload)
                real_checksum = calculate_checksum(decrypted)

                if header['checksum'] != real_checksum:
                    logging.warning(f"Checksum mismatch from {client_ip}")
                    continue

                # از header اطلاعات فرستنده را بخوانیم
                sender_port = header.get('sender_port', 0)
                sender_username = header.get('sender_username', 'Unknown')
                sender_peer_id = get_peer_id(client_ip, sender_port)

                # ذخیره اطلاعات فرستنده
                with lock:
                    peer_info[sender_peer_id] = {
                        'username': sender_username,
                        'ip': client_ip,
                        'port': sender_port
                    }

                if header['type'] == "TEXT":
                    message = decrypted.decode('utf-8')
                    save_message(f"{sender_peer_id} ({sender_username}): {message}")
                    incoming_messages.setdefault(sender_peer_id, []).append(message)
                    logging.info(f"Received message from {sender_peer_id}: {message}")

                elif header['type'] == "FILE":
                    os.makedirs("media", exist_ok=True)
                    path = os.path.join("media", header['filename'])
                    with open(path, 'wb') as f:
                        f.write(decrypted)
                    incoming_messages.setdefault(sender_peer_id, []).append(f"[Received file: {header['filename']}]")
                    logging.info(f"Received file from {sender_peer_id}: {header['filename']}")

            except Exception as e:
                logging.error(f"Error handling incoming connection from {client_ip}: {e}")
                break


def server_thread():
    """سرور برای دریافت اتصالات ورودی"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(10)
    logging.info(f"Server started on port {PORT}")
    
    while True:
        try:
            conn, addr = server.accept()
            logging.info(f"New incoming connection from {addr}")
            threading.Thread(target=handle_incoming_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Server error: {e}")
            break


def send_message_to_peer(peer_id, message_type, content, filename=""):
    """ارسال پیام به یک peer خاص"""
    try:
        peer = peer_info.get(peer_id)
        if not peer:
            logging.error(f"Peer info not found for {peer_id}")
            return False
            
        # ایجاد اتصال جدید برای ارسال
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((peer['ip'], peer['port']))
        
        # آماده‌سازی header
        if isinstance(content, str):
            content = content.encode('utf-8')
            
        checksum = calculate_checksum(content)
        encrypted = onion_encrypt(content)
        
        header = json.dumps({
            "type": message_type,
            "filename": filename,
            "checksum": checksum,
            "length": len(encrypted),
            "sender_port": PORT,
            "sender_username": USERNAME
        }).encode()
        
        # ارسال پیام
        sock.send(len(header).to_bytes(4, 'big'))
        sock.send(header)
        sock.send(encrypted)
        
        sock.close()
        logging.info(f"Message sent to {peer_id}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send message to {peer_id}: {e}")
        return False


def discover_peers():
    """کشف peer های موجود در شبکه"""
    try:
        with open(PEERS_FILE) as f:
            config = json.load(f)
        
        current_peer_id = get_peer_id("127.0.0.1", PORT)
        
        for peer in config["peers"]:
            ip, port = peer["ip"], peer["port"]
            peer_id = get_peer_id(ip, port)
            
            if peer_id != current_peer_id:
                # تست اتصال برای بررسی آنلاین بودن
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(2)  # 2 ثانیه timeout
                    result = test_sock.connect_ex((ip, port))
                    test_sock.close()
                    
                    if result == 0:  # اتصال موفق
                        with lock:
                            peer_info[peer_id] = {
                                'username': peer.get('username', 'Unknown'),
                                'ip': ip,
                                'port': port
                            }
                        logging.info(f"Discovered peer: {peer_id}")
                        
                except Exception as e:
                    logging.debug(f"Peer {peer_id} not reachable: {e}")
                    
    except Exception as e:
        logging.error(f"Failed to discover peers: {e}")


class MessengerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("securie chat")
        self.resize(700, 550)
        self.setStyleSheet("background-color: #f0f0f0;")
        self.current_peer = None
        self.init_login_ui()

    def styled_button(self, text):
        btn = QPushButton(text)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #0078D7;
                color: white;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005A9E;
            }
        """)
        return btn

    def init_login_ui(self):
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        title = QLabel("Welcome to securie chat")
        title.setFont(QFont("Segoe UI", 18))
        title.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setStyleSheet("padding: 6px; border-radius: 4px;")

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter your port (e.g., 12345, 12346, 12347)")
        self.port_input.setStyleSheet("padding: 6px; border-radius: 4px;")

        self.start_button = self.styled_button("Start Chat")
        self.start_button.clicked.connect(self.start_app)

        info_label = QLabel("Make sure to create config.json with all peer ports before starting!")
        info_label.setStyleSheet("color: #666; font-size: 10px;")
        info_label.setWordWrap(True)

        self.layout.addWidget(QLabel("Username:"))
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(QLabel("Port:"))
        self.layout.addWidget(self.port_input)
        self.layout.addWidget(info_label)
        self.layout.addWidget(self.start_button)

    def init_main_ui(self):
        for i in reversed(range(self.layout.count())):
            self.layout.itemAt(i).widget().setParent(None)

        header = QLabel(f"Logged in as {USERNAME} on port {PORT}")
        header.setFont(QFont("Segoe UI", 12))
        header.setAlignment(Qt.AlignCenter)

        self.notification_label = QLabel("")
        self.notification_label.setStyleSheet("color: red; font-weight: bold;")
        
        self.user_list = QListWidget()
        self.user_list.setStyleSheet("background: white; border-radius: 4px;")

        self.refresh_btn = self.styled_button("Refresh Online Users")
        self.chat_btn = self.styled_button("Start Chat")
        self.history_btn = self.styled_button("View Chat History")

        self.refresh_btn.clicked.connect(self.refresh_users)
        self.chat_btn.clicked.connect(self.open_chat_window)
        self.history_btn.clicked.connect(self.show_history)

        self.layout.addWidget(header)
        self.layout.addSpacing(10)
        self.layout.addWidget(self.notification_label)
        self.layout.addWidget(QLabel("Online Users:"))
        self.layout.addWidget(self.user_list)
        self.layout.addSpacing(10)
        self.layout.addWidget(self.refresh_btn)
        self.layout.addWidget(self.chat_btn)
        self.layout.addWidget(self.history_btn)

        self.notification_timer = QTimer()
        self.notification_timer.timeout.connect(self.check_notifications)
        self.notification_timer.start(1000)
        
        # بلافاصله کشف peer ها
        self.refresh_users()

    def start_app(self):
        global PORT, USERNAME
        try:
            USERNAME = self.username_input.text().strip()
            PORT = int(self.port_input.text().strip())
            
            if not USERNAME:
                QMessageBox.critical(self, "Error", "Please enter a username")
                return
            if PORT < 1024 or PORT > 65535:
                QMessageBox.critical(self, "Error", "Port must be between 1024 and 65535")
                return
                
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid port number")
            return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error: {e}")
            return

        try:
            # شروع سرور
            threading.Thread(target=server_thread, daemon=True).start()
            # کمی صبر کنیم تا سرور شروع شود
            threading.Timer(1.0, discover_peers).start()
            self.init_main_ui()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start server: {e}")

    def refresh_users(self):
        self.user_list.clear()
        discover_peers()
        
        current_peer_id = get_peer_id("127.0.0.1", PORT)
        
        with lock:
            for peer_id, info in peer_info.items():
                if peer_id != current_peer_id:
                    display_text = f"{info['username']} ({peer_id})"
                    self.user_list.addItem(display_text)
                    self.user_list.item(self.user_list.count() - 1).setData(Qt.UserRole, peer_id)

    def show_history(self):
        msg = load_history()
        QMessageBox.information(self, "Chat History", msg or "No messages.")

    def check_notifications(self):
        for peer_id, msgs in incoming_messages.items():
            if msgs and peer_id != self.current_peer:
                username = peer_info.get(peer_id, {}).get('username', 'Unknown')
                self.notification_label.setText(f"🔔 New message from {username}")
                return
        self.notification_label.setText("")

    def open_chat_window(self):
        selected = self.user_list.currentItem()
        if not selected:
            QMessageBox.information(self, "Selection", "Please select a user to chat with")
            return
            
        peer_id = selected.data(Qt.UserRole)
        self.current_peer = peer_id
        
        self.chat_window = ChatWindow(self, peer_id)
        self.chat_window.show()


class ChatWindow(QWidget):
    def __init__(self, parent, peer_id):
        super().__init__()
        self.parent = parent
        self.peer_id = peer_id
        peer_info_data = peer_info.get(peer_id, {})
        username = peer_info_data.get('username', 'Unknown')
        self.setWindowTitle(f"Chat with {username}")
        self.resize(600, 400)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("background-color: #fafafa;")
        self.layout = QVBoxLayout()
        
        # نمایش اطلاعات peer
        peer_info_data = peer_info.get(self.peer_id, {})
        username = peer_info_data.get('username', 'Unknown')
        info_label = QLabel(f"Chatting with: {username} ({self.peer_id})")
        info_label.setFont(QFont("Segoe UI", 10))
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("background-color: #e0e0e0; padding: 5px; border-radius: 3px;")
        
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet("background-color: white; padding: 6px; border-radius: 4px;")

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type your message here...")
        self.msg_input.setStyleSheet("padding: 6px; border-radius: 4px;")
        self.msg_input.returnPressed.connect(self.send_msg)

        self.send_btn = self.parent.styled_button("Send")
        self.file_btn = self.parent.styled_button("Send File")

        self.send_btn.clicked.connect(self.send_msg)
        self.file_btn.clicked.connect(self.send_file)

        hbox = QHBoxLayout()
        hbox.addWidget(self.msg_input)
        hbox.addWidget(self.send_btn)

        self.layout.addWidget(info_label)
        self.layout.addWidget(self.chat_area)
        self.layout.addLayout(hbox)
        self.layout.addWidget(self.file_btn)
        self.setLayout(self.layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_chat)
        self.timer.start(500)

    def update_chat(self):
        msgs = incoming_messages.get(self.peer_id, [])
        if msgs:
            peer_info_data = peer_info.get(self.peer_id, {})
            username = peer_info_data.get('username', 'Unknown')
            
            for msg in msgs:
                if msg.startswith("[Received file: ") and any(msg.endswith(ext + "]") for ext in [".jpg", ".png", ".jpeg"]):
                    filename = msg.split("[Received file: ")[1][:-1]
                    img_path = os.path.join("media", filename)
                    if os.path.exists(img_path):
                        self.chat_area.append(f"{username}: <img src='{img_path}' width='200'>")
                    else:
                        self.chat_area.append(f"{username}: [Image file missing: {filename}]")
                elif msg.startswith("[Received file: ") and any(msg.endswith(ext + "]") for ext in [".mp4", ".MP4",".avi", ".mov"]):
                    filename = msg.split("[Received file: ")[1][:-1]
                    video_path = os.path.join("media", filename)
                    if os.path.exists(video_path):
                        self.chat_area.append(f"{username}: [Playing video: {filename}]")
                        self.play_video(video_path)
                    else:
                        self.chat_area.append(f"{username}: [Video file missing: {filename}]")
                else:
                    self.chat_area.append(f"{username}: {msg}")
            incoming_messages[self.peer_id] = []

    def play_video(self, path):
        self.video_window = QWidget()
        self.video_window.setWindowTitle("Video Player")
        self.video_window.resize(640, 480)
        layout = QVBoxLayout()
        self.video_widget = QVideoWidget()
        layout.addWidget(self.video_widget)
        self.video_window.setLayout(layout)

        self.media_player = QMediaPlayer(None, QMediaPlayer.VideoSurface)
        self.media_player.setVideoOutput(self.video_widget)
        self.media_player.setMedia(QMediaContent(QUrl.fromLocalFile(os.path.abspath(path))))
        self.media_player.play()

        self.video_window.show()

    def send_msg(self):
        msg = self.msg_input.text().strip()
        if not msg:
            return
            
        if send_message_to_peer(self.peer_id, "TEXT", msg):
            save_message(f"You -> {self.peer_id}: {msg}")
            self.chat_area.append(f"You: {msg}")
            self.msg_input.clear()
        else:
            QMessageBox.critical(self, "Error", "Failed to send message")

    def send_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not path:
            return
            
        try:
            filename = os.path.basename(path)
            with open(path, 'rb') as f:
                content = f.read()
                
            if send_message_to_peer(self.peer_id, "FILE", content, filename):
                save_message(f"You sent file to {self.peer_id}: {filename}")
                self.chat_area.append(f"You sent file: {filename}")
            else:
                QMessageBox.critical(self, "Error", "Failed to send file")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read file: {e}")

    def closeEvent(self, event):
        self.parent.current_peer = None
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MessengerGUI()
    window.show()
    sys.exit(app.exec_())