from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Static, RichLog
from textual.containers import ScrollableContainer
from datetime import datetime
import threading
from p2p import P2PBackend  # Import your existing backend

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

    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.backend.set_message_callback(self.update_chat)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="chat_log", markup=True)
        with ScrollableContainer(id="input_container"):
            yield Input(placeholder="Type your message...", id="message_input")
            yield Button("Send", id="send_button")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "P2P Chat"
        self.query_one("#message_input").focus()
        
        # Start backend in a thread
        threading.Thread(target=self.backend.start, daemon=True).start()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send_button":
            self.send_message()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.send_message()

    def send_message(self):
        input_widget = self.query_one("#message_input")
        message = input_widget.value
        if message:
            self.backend.send_message(message)
            input_widget.value = ""

    def update_chat(self, sender, message):
        chat_log = self.query_one("#chat_log")
        timestamp = datetime.now().strftime("%H:%M:%S")
        chat_log.write(f"[b][{timestamp}] {sender}:[/b] {message}")