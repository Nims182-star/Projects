import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import argparse

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
        sock.close()
    except:
        pass
    return None

def scan(target, start_port, end_port):
    open_ports = []
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Hostname {target} could not be resolved.")
        sys.exit()

    print(f"Scanning target: {ip}")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    print("\nOpen ports:")
    for port in open_ports:
        try:
            service = socket.getservbyport(port)
        except:
            service = "Unknown"
        print(f"Port {port}: {service}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Network Scanner")
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    args = parser.parse_args()

    scan(args.target, args.start, args.end)
