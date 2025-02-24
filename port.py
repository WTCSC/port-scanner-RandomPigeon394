import argparse
import ipaddress
import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor

def ping_host(ip):
    """Pings a host and returns its status."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-W", "1", ip]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return ip, "UP"
        else:
            return ip, "DOWN"
    except Exception as e:
        return ip, "ERROR"

def scan_ports(ip, ports):
    """Scans a list of ports on a given IP address and returns open ones."""
    open_ports = []
    for port in ports:
        command = ["nc", "-zv", "-w", "1", ip, str(port)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if "succeeded" in result.stderr:
            open_ports.append(port)

    return ip, open_ports

def scan_ips(ip_list, ports, max_threads=50):
    """Scans IPs for availability and then scans open ports for UP hosts."""
    print("\nStarting scan...\n")
    ip_status = {}

    # Ping scan
    with ThreadPoolExecutor(max_threads) as executor:
        ping_results = executor.map(ping_host, ip_list)

    for ip, status in ping_results:
        if status == "UP":
            ip_status[ip] = status  # Only UP hosts

    # Port scan for ONLY UP hosts (I made it so that it lists UP hosts only just so that it makes it easier to read and test)
    open_ports_by_ip = {}
    up_hosts = list(ip_status.keys())

    if ports and up_hosts:
        print("\nStarting port scan on UP hosts...\n")
        with ThreadPoolExecutor(max_threads) as executor:
            port_scan_results = executor.map(lambda ip: scan_ports(ip, ports), up_hosts)

        for ip, open_ports in port_scan_results:
            open_ports_by_ip[ip] = open_ports

    # Print the output in the format
    print("\nScan Results:\n")
    for ip in up_hosts:
        print(f"{ip}  (UP)")
        for port in open_ports_by_ip.get(ip, []):
            print(f"  - Port {port}   (OPEN)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast network scanner with port scanning.")
    parser.add_argument("-n", "--network", help="Network to scan in CIDR format (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--ips", nargs="+", help="Specific IPs to scan (e.g., 192.168.1.1 192.168.1.10)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443,1-100)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")

    args = parser.parse_args()

    if args.network:
        network = ipaddress.ip_network(args.network, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]  # Get all IPs
    elif args.ips:
        ip_list = args.ips  # Use the ursers IP addresses
    else:
        print("Error: You must provide a network range (-n) or specific IPs (-i).")
        exit(1)

    if args.ports:
        # Parse the port input so that the script can understand the users input
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                start_port, end_port = map(int, part.split("-"))
                ports.extend(range(start_port, end_port + 1))
            else:
                ports.append(int(part))
    else:
        ports = []

    scan_ips(ip_list, ports, args.threads)
