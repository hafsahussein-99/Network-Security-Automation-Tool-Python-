import socket
import sys
import concurrent.futures
from datetime import datetime

# Common ports mapped to standard services for vulnerability cross-referencing
COMMON_PORTS = {
    21: "FTP (Check for anonymous login / outdated software)",
    22: "SSH (Check for weak credentials / brute-force vulnerability)",
    23: "Telnet (Unencrypted text protocol - high risk)",
    25: "SMTP (Mail relay configurations)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server - Check for outdated server headers)",
    110: "POP3 (Email routing)",
    139: "NetBIOS (File sharing vectors)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Look out for EternalBlue/CVE-2017-0144 vulnerabilities)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop - potential BlueKeep exploit vector)"
}

def banner_grab(s):
    """Attempts to grab the service banner information safely."""
    try:
        return s.recv(1024).decode('utf-8', errors='ignore').strip()
    except Exception:
        return "No banner returned (Service active but hidden)"

def scan_port(target_ip, port):
    """Scans a single port, performs input verification, and handles banner extraction."""
    try:
        # Construct socket with a fast timeout to prevent application hanging
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            banner = banner_grab(s)
            service_desc = COMMON_PORTS.get(port, "Unknown Service")
            print(f"[+] Port {port} is OPEN | Service: {service_desc}")
            if banner:
                print(f"    --> Banner: {banner}")
            s.close()
            return (port, True, banner)
        s.close()
    except socket.error:
        pass  # Quietly catch network hiccups to prevent thread crashing
    return (port, False, None)

def main():
    print("=" * 60)
    print("     NETWORK SECURITY AUTOMATION TOOL - PORT SCANNER")
    print("=" * 60)
    
    # Input Sanitization and Verification
    target_input = input("Enter Target Host IP or Domain: ").strip()
    if not target_input:
        print("[-] Error: Host field cannot be empty.")
        sys.exit(1)
        
    try:
        target_ip = socket.gethostbyname(target_input)
        print(f"[*] Resolving Target: {target_ip}")
    except socket.gaierror:
        print("[-] Error: Could not resolve hostname. Invalid IP address layout.")
        sys.exit(1)

    print(f"[*] Scan started at: {str(datetime.now())}")
    print("[*] Evaluating critical security-sensitive network entry points...")
    print("-" * 60)

    # Multi-threaded execution framework using standard ThreadPoolExecutor
    ports_to_scan = list(COMMON_PORTS.keys())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            future.result()

    print("-" * 60)
    print("[*] Scan operations finalized successfully.")
    print("=" * 60)

if __name__ == "__main__":
    main()
