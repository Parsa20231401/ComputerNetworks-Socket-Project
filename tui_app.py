from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Static, RichLog
from textual.containers import ScrollableContainer
from datetime import datetime
import threading
import asyncio

class ChatApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #chat_log {
        height: 80%;
        border: solid $accent;
        padding: 1;
    }
    #input_container {
        height: 20%;
        padding: 1;
    }
    """

    def __init__(self, network_instance):
        super().__init__()
        self.network = network_instance
        self.current_peer = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="chat_log")
        with ScrollableContainer(id="input_container"):
            yield Input(placeholder="Type message...", id="message_input")
            yield Button("Send", id="send_button")
            yield Button("Connect to Peer", id="connect_button")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "P2P Chat"
        self.query_one("#message_input").focus()
        # Start network in background
        threading.Thread(target=self.network.start_network, daemon=True).start()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "send_button":
            self.send_message()
        elif event.button.id == "connect_button":
            self.connect_to_peer()

    async def on_input_submitted(self, event: Input.Submitted):
        self.send_message()

    def send_message(self):
        input_widget = self.query_one("#message_input")
        message = input_widget.value
        if message and self.current_peer:
            self.network.send_chat_message(self.current_peer, message)
            self.query_one("#chat_log").write(f"[You] {message}")
            input_widget.value = ""

    def connect_to_peer(self):
        peers = self.network.get_online_peers()
        if not peers:
            self.query_one("#chat_log").write("No peers available")
            return
        
        self.query_one("#chat_log").write("Select peer:")
        for i, peer in enumerate(peers):
            self.query_one("#chat_log").write(f"{i+1}. {peer}")
        
        # This would need a proper dialog implementation
        self.current_peer = peers[0]  # Simplified - should get user input
        self.query_one("#chat_log").write(f"Connected to {self.current_peer}")

    def display_message(self, sender, message):
        self.query_one("#chat_log").write(f"[{sender}] {message}")