import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import threading
import json
import socket
from p2p import chat_with, main, online_peers, connections, handle_client, lock

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P2P Messenger")
        self.username = ""
        self.port = 0

        # Initialize GUI
        self.setup_login()

    def setup_login(self):
        self.clear_window()

        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack()

        tk.Button(self.root, text="Start", command=self.start_app).pack(pady=10)

    def start_app(self):
        self.username = self.username_entry.get()
        self.port = int(self.port_entry.get())
        if not self.username or not self.port:
            messagebox.showerror("Error", "Please enter a username and port.")
            return

        threading.Thread(target=main, daemon=True).start()  # Call your existing main()
        self.setup_main_menu()

    def setup_main_menu(self):
        self.clear_window()
        tk.Label(self.root, text=f"Welcome {self.username}", font=("Arial", 14)).pack(pady=5)

        self.peer_listbox = tk.Listbox(self.root, width=40)
        self.peer_listbox.pack(pady=5)

        tk.Button(self.root, text="Refresh Online Users", command=self.refresh_peers).pack()
        tk.Button(self.root, text="Chat with Selected", command=self.open_chat).pack(pady=5)

        self.status_label = tk.Label(self.root, text="", fg="green")
        self.status_label.pack()

    def refresh_peers(self):
        self.peer_listbox.delete(0, tk.END)

        try:
            with open("config.json") as f:
                config = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read config: {e}")
            return

        for peer in config["peers"]:
            ip = peer["ip"]
            port = peer["port"]
            if ip == "127.0.0.1":  # skip self
                continue

            # Try to connect if not already
            if ip not in connections:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((ip, port))
                    connections[ip] = s
                    with lock:
                        online_peers.add(ip)
                    threading.Thread(target=handle_client, args=(s, ip), daemon=True).start()
                except Exception as e:
                    continue  # can't connect = offline

        # Display online users
        for ip in sorted(online_peers):
            self.peer_listbox.insert(tk.END, ip)

    def open_chat(self):
        selection = self.peer_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select a user to chat with.")
            return

        selected_ip = self.peer_listbox.get(selection[0])
        selected_port = None
        # Find port from config
        with open("config.json") as f:
            config = json.load(f)
            for p in config["peers"]:
                if p["ip"] == selected_ip:
                    selected_port = p["port"]
                    break

        if not selected_port:
            messagebox.showerror("Error", "Port not found for selected user.")
            return

        threading.Thread(target=chat_with, args=(selected_ip, selected_port), daemon=True).start()
        self.status_label.config(text=f"Chat started with {selected_ip}:{selected_port}")

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()


# Entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()
