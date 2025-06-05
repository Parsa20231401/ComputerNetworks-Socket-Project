from p2p import P2PBackend
from tui_app import ChatApp

def main():
    backend = P2PBackend()
    app = ChatApp(backend)
    app.run()

if __name__ == "__main__":
    main()