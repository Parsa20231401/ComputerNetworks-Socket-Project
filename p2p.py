import socket
import threading
import json
import os
from datetime import datetime

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
        msg = input()
        if msg.lower() == "/online":
            print("🟢 Online users:")
            for peer in online_peers:
                print(f" - {peer}")
        elif msg.lower() == "/exit":
            break
        else:
            full_msg = f"{name}: {msg}"
            save_message(full_msg)
            for conn in connections:
                try:
                    conn.send(msg.encode())
                except:
                    continue

if __name__ == "__main__":
    main()
