import socket
import threading
import json
import os
from datetime import datetime
from utils import onion_encrypt, onion_decrypt, calculate_checksum

connections = {}         # key: ip -> value: socket object
PORT = 12345
HISTORY_FILE = "history.txt"
PEERS_FILE = "config.json"
online_peers = set()
lock = threading.Lock()

current_chat_peer = None  # آدرس IP کاربری که با او در حال چت هستیم
incoming_messages = {}    # پیام‌های دریافتی برای کاربران دیگر

def load_peers():
    if os.path.exists(PEERS_FILE):
        with open(PEERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_message(msg):
    with open(HISTORY_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.now()} - {msg}\n")

def show_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            print("📜 Chat History:")
            print(f.read())
    else:
        print("No chat history yet.")

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

                parts = data.split(b':', 3)  # Split into max 4 parts
                if len(parts) < 4:
                    print("⚠️ Invalid message format - not enough parts")
                    continue

                msg_type = parts[0].decode()
                filename = parts[1].decode()
                recv_checksum = parts[2].decode()
                payload = parts[3]

                decrypted = onion_decrypt(payload)
                real_checksum = calculate_checksum(decrypted)

                if recv_checksum != real_checksum:
                    print("⚠️ پیام آسیب دیده (checksum mismatch)")
                    continue

                if msg_type == "TEXT":
                    message = decrypted.decode('utf-8')
                    if ip == current_chat_peer:
                        print(f"\n💬 {ip} says: {message}")
                        save_message(f"{ip}: {message}")
                    else:
                        incoming_messages.setdefault(ip, []).append(message)
                        print(f"\n🔔 اعلان: پیام جدید از {ip}")
                elif msg_type == "FILE":
                    os.makedirs("media", exist_ok=True)
                    path = os.path.join("media", filename)
                    with open(path, 'wb') as f:
                        f.write(decrypted)
                    print(f"\n📁 فایل {filename} از {ip} دریافت شد.")

            except Exception as e:
                print(f"خطا در دریافت از {ip}: {e}")
                break

    with lock:
        online_peers.discard(ip)
        connections.pop(ip, None)

def server_thread():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    print(f"🔌 Listening on port {PORT}...")
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"Server error: {e}")
            break

def connect_to_peer(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        with lock:
            connections[ip] = s
            online_peers.add(ip)
        return s
    except Exception as e:
        print(f"❌ Failed to connect to {ip}:{port} - {e}")
        return None

def choose_peer():
    with lock:
        peers = list(online_peers)

    if not peers:
        print("❌ No online users available to chat")
        return None

    print("👥 Online users: ")
    for i, peer in enumerate(peers):
        print(f"[{i}] {peer}")

    try:
        choice = input("Enter the number of user to chat: ")
        idx = int(choice)
        if 0 <= idx < len(peers):
            return peers[idx]
        print("❌ Invalid selection")
        return None
    except:
        print("❌ Invalid input")
        return None

def chat_with(peer_ip, peer_port):
    global current_chat_peer
    current_chat_peer = peer_ip
    
    
    # Check if we already have a connection
    with lock:
        conn = connections.get(peer_ip)
    
    if not conn:
        conn = connect_to_peer(peer_ip, peer_port)
        if not conn:
            print("❌ Connection failed.")
            current_chat_peer = None
            return

    print(f"💬 Chatting with {peer_ip}:{peer_port}. Type /sendfile filepath to send a file or /exit to quit.")

    # Show unread messages if any
    if peer_ip in incoming_messages:
        print("\n📥 Unread messages:")
        for msg in incoming_messages[peer_ip]:
            print(f"{peer_ip}: {msg}")
        del incoming_messages[peer_ip]

    while True:
        try:
            msg = input("You: ")
            if msg == "/exit":
                break
            elif msg.startswith("/sendfile "):
                filepath = msg.split(" ", 1)[1]
                if not os.path.exists(filepath):
                    print("❌ File not found.")
                    continue
                with open(filepath, 'rb') as f:
                    content = f.read()

                checksum = calculate_checksum(content)
                encrypted = onion_encrypt(content)
                header = f"FILE:{os.path.basename(filepath)}:{checksum}:".encode('utf-8')
                conn.send(header + encrypted)
                print(f"📤 Sent file: {os.path.basename(filepath)}")
            else:    
                content = msg.encode('utf-8')
                checksum = calculate_checksum(content)
                encrypted = onion_encrypt(content)
                header = f"TEXT::{checksum}:".encode('utf-8')
                conn.send(header + encrypted)
            # print(f"Sent message format: {header + encrypted}") ############
        except Exception as e:
            print(f"Error sending message: {e}")
            break

    current_chat_peer = None

def main():
    global PORT

    username = input("Enter your username: ")
    PORT = int(input("Enter your listening port (e.g., 12345): "))

    # Start TCP server
    threading.Thread(target=server_thread, daemon=True).start()

    # Load peer list from config
    try:
        with open("config.json") as f:
            peer_config = json.load(f)
        peers = peer_config["peers"]
    except Exception as e:
        print(f"Error loading config: {e}")
        return

    # Connect to all other peers in the list (excluding self)
    for peer in peers:
        ip = peer["ip"]
        port = peer["port"]
        if port == PORT:
            continue  # Skip self
        threading.Thread(target=connect_to_peer, args=(ip, port), daemon=True).start()

    # Main menu
    while True:
        print("\n===== MENU =====")
        print("1. Show online users")
        print("2. Start chat")
        print("3. Show chat history")
        print("4. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            with lock:
                online_list = list(online_peers)
            print("\nOnline users:")
            for ip in online_list:
                print(f"- {ip}")
        elif choice == "2":
            with lock:
                online_list = list(online_peers)
            if not online_list:
                print("❌ No online users available")
                continue
            
            print("Select a user to chat with:")
            for i, ip in enumerate(online_list):
                print(f"{i + 1}. {ip}")
            
            try:
                idx = int(input("Enter number: ")) - 1
                if 0 <= idx < len(online_list):
                    selected_ip = online_list[idx]
                    # Find the port for this IP
                    selected_port = next((p["port"] for p in peers if p["ip"] == selected_ip), PORT)
                    chat_with(selected_ip, selected_port)
                else:
                    print("❌ Invalid selection")
            except:
                print("❌ Invalid input")
        elif choice == "3":
            show_history()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()