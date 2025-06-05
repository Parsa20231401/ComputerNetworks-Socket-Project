
from p2p import start_network, get_online_peers, send_chat_message
from tui_app import ChatApp

def main():
    # Create a network instance with the required methods
    network = type('Network', (), {
        'start_network': start_network,
        'get_online_peers': get_online_peers,
        'send_chat_message': send_chat_message
    })()
    
    app = ChatApp(network)
    app.run()

if __name__ == "__main__":
    main()
    