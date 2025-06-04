import socket
import threading
import json
import os
from datetime import datetime
from utils import onion_encrypt, onion_decrypt, calculate_checksum



PORT = 12345
HISTORY_FILE = "history.txt"
PEERS_FILE = "config.json"
online_peers = set()
lock = threading.Lock()

def load_peers():
    if os.path.exists(PEERS_FILE):
        with open(PEERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_message(msg):
    with open(HISTORY_FILE, 'a') as f:
        f.write(f"{datetime.now()} - {msg}\n")

def show_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            print("📜 Chat History:")
            print(f.read())
    else:
        print("No chat history yet.")

def handle_client(conn, addr):
    with conn:
        lock.acquire()
        online_peers.add(addr[0])
        lock.release()

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                msg = data.decode()
                print(f"\n{addr[0]} says: {msg}")
                save_message(f"{addr[0]}: {msg}")
            except:
                break
        lock.acquire()
        online_peers.discard(addr[0])
        lock.release()
        
        
        


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
                print("⚠️ پیام آسیب دیده (checksum mismatch)")
                continue

            if msg_type == "TEXT":
                print(f"\n{addr[0]} says: {decrypted.decode()}")
                save_message(f"{addr[0]}: {decrypted.decode()}")
            elif msg_type == "FILE":
                os.makedirs("media", exist_ok=True)
                path = os.path.join("media", filename)
                with open(path, 'wb') as f:
                    f.write(decrypted)
                print(f"\n📁 فایل {filename} از {addr[0]} دریافت شد و در پوشه media ذخیره شد.")

        except Exception as e:
            print(f"خطا در دریافت: {e}")
            break

            
        
        
        

def server_thread():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', PORT))
    server.listen(5)
    print(f"🔌 Listening on port {PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def connect_to_peer(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, PORT))
        threading.Thread(target=listen_to_peer, args=(s, ip), daemon=True).start()
        return s
    except Exception as e:
        print(f"❌ Failed to connect to {ip}: {e}")
        return None

def listen_to_peer(sock, ip):
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            msg = data.decode()
            print(f"\n{ip} says: {msg}")
            save_message(f"{ip}: {msg}")
    except:
        pass
    finally:
        lock.acquire()
        online_peers.discard(ip)
        lock.release()





def choose_peer():
    lock.acquire()
    peers = list(online_peers)
    lock.release()

    if not peers:
        print("❌ هیچ کاربر آنلاینی برای چت وجود ندارد.")
        return None

    print("👥 کاربران آنلاین:")
    for i, peer in enumerate(peers):
        print(f"[{i}] {peer}")

    choice = input("شماره کاربر برای چت را وارد کنید: ")
    try:
        idx = int(choice)
        return peers[idx]
    except:
        print("❌ انتخاب نامعتبر.")
        return None

def chat_with(peer_ip):
    conn = connect_to_peer(peer_ip)
    if not conn:
        print("❌ اتصال برقرار نشد.")
        return

    print(f"💬 چت با {peer_ip}. برای ارسال فایل: /sendfile filepath")
    while True:
        msg = input("📤 your message ")
        if msg == "/exit":
            break
        elif msg.startswith("/sendfile "):
            filepath = msg.split(" ", 1)[1]
            if not os.path.exists(filepath):
                print("❌ فایل یافت نشد.")
                continue
            with open(filepath, 'rb') as f:
                content = f.read()

            # اضافه کردن چک‌سام و رمزنگاری
            checksum = calculate_checksum(content)
            encrypted = onion_encrypt(content)
            header = f"FILE:{os.path.basename(filepath)}:{checksum}:".encode()
            conn.send(header + encrypted)
        else:
            content = msg.encode()
            checksum = calculate_checksum(content)
            encrypted = onion_encrypt(content)
            header = f"TEXT::{checksum}:".encode()
            conn.send(header + encrypted)

    conn.close()






def main():
    threading.Thread(target=server_thread, daemon=True).start()
    show_history()

    peers = load_peers()
    connections = []
    for ip in peers:
        conn = connect_to_peer(ip)
        if conn:
            connections.append(conn)
            lock.acquire()
            online_peers.add(ip)
            lock.release()

    name = input("Enter your name: ")

    while True:
        print("\n📝 دستورات:")
        print("  /online")
        print("  /chat")
        print("  /exit")
        cmd = input(">> ")

        if cmd == "/online":
            print("🟢 کاربران آنلاین:")
            for peer in online_peers:
                print(f" - {peer}")
        elif cmd == "/chat":
            selected = choose_peer()
            if selected:
                chat_with(selected)
        elif cmd == "/exit":
            break




if __name__ == "__main__":
    main()
