import socket

def tcp_client(host, port, message):
    """Sends a message to a TCP server and receives response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(message.encode())
            data = s.recv(1024) # Receive up to 1024 bytes
            print(f"Received from {host}:{port}: {data.decode('utf-8', errors='ignore')}")
            return data.decode('utf-8', errors='ignore')
        except ConnectionRefusedError:
            print(f"Connection refused by {host}:{port}")
        except socket.timeout:
            print(f"Connection to {host}:{port} timed out")
        except Exception as e:
            print(f"An error occurred: {e}")
        return None

if __name__ == "__main__":
    # Example usage: Connect to a dummy server (you can set up a local netcat listener: nc -lvnp 12345)
    print("--- TCP Client Example ---")
    tcp_client("127.0.0.1", 12345, "Hello CTF!")