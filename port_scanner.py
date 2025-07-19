import socket
import concurrent.futures

def scan_port(host, port, timeout=1):
    """Checks if a single port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return True
            else:
                return False
    except Exception:
        return False

def port_scanner(host, start_port, end_port, max_workers=100):
    """Scans a range of ports on a given host."""
    print(f"Scanning ports {start_port}-{end_port} on {host}...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    print(f"Port {port}: OPEN")
            except Exception as exc:
                print(f"Port {port} generated an exception: {exc}")
    
    if open_ports:
        print(f"\nScan complete. Open ports on {host}: {sorted(open_ports)}")
    else:
        print(f"\nScan complete. No open ports found on {host} in the range {start_port}-{end_port}.")
    return open_ports

if __name__ == "__main__":
    # Example Usage: Scan common ports on localhost
    print("--- Port Scanner Example ---")
    port_scanner("127.0.0.1", 1, 1024)
    # You can also scan a specific range, e.g., port_scanner("scanme.nmap.org", 20, 100)