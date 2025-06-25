import socket
import ssl
import http.client
import requests

def httpProbe(target, port, verbose=False):
    try:
        url = f"http://{target}:{port}/"
        if port == 443:
            url = f"https://{target}/"

        if verbose:
            print(f"[*] Probing HTTP(s) URL: {url}")

        response = requests.get(url, timeout=3)
        server = response.headers.get("Server", "Unknown Server")
        status_line = f"HTTP/{response.raw.version/10:.1f} {response.status_code} {response.reason}"
        body_snippet = response.text[:200].replace('\n', ' ').replace('\r', '')

        banner = f"{status_line}\nServer: {server}\nBody Snippet: {body_snippet}"
        return banner

    except requests.exceptions.RequestException as e:
        return f"HTTP request failed: {e}"
    
def smbProbe(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target, port))
            # Send basic SMB negotiation request (simplified)
            smb_request = bytes.fromhex(
                "00000085ff534d4272000000001801280000000000000000000000000000000000000000ffff0000"
                "00000000000000000000000000000000000000000000000000000000000000"
            )
            s.sendall(smb_request)
            data = s.recv(1024)
            if b"SMB" in data:
                return "SMB service detected (port 445)"
            return "Possible SMB response (unparsed)"
    except Exception as e:
        return f"SMB probe failed: {e}"

def sshProbe(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner or "No SSH banner received"
    except Exception as e:
        return f"SSH probe failed: {e}"

def ldapProbe(target, port):
    try:
        ldap_bind = bytes.fromhex(
            "30 1c 02 01 01 60 17 02 01 03 04 00 80 00 02 01 00 02 01 00 02 01 00"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            s.sendall(ldap_bind)
            data = s.recv(1024)
            return f"LDAP response: {data.hex()[:100]}"
    except Exception as e:
        return f"LDAP probe failed: {e}"

def dnsProbe(target, port=53):
    try:
        dns_query = bytes.fromhex(
            "AA AA 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6D 70 6C 65"
            "03 63 6F 6D 00 00 01 00 01"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(dns_query, (target, port))
            data, _ = s.recvfrom(512)
            return f"DNS response received: {data.hex()[:100]}"
    except Exception as e:
        return f"DNS probe failed: {e}"

PROBEDISPATCH = {
    22: sshProbe,
    53: dnsProbe,
    389: ldapProbe,
    445: smbProbe,
    80: httpProbe,
    443: httpProbe,
    8080: httpProbe,
    8000: httpProbe,
}

def grabBanner(target, port, verbose=False):
    # Handle HTTP(S) first
    if port in PROBEDISPATCH:
        return PROBEDISPATCH[port](target, port)

    banner = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))

            # === Protocol-Specific Probing ===
            if port == 21:  # FTP
                s.sendall(b"USER anonymous\r\n")


            elif port == 25:  # SMTP
                s.sendall(b"EHLO vulnscanner.local\r\n")

            elif port == 110:  # POP3
                s.sendall(b"USER test\r\n")

            elif port == 143:  # IMAP
                s.sendall(b"a login test test\r\n")

            elif port == 23:  # Telnet
                s.sendall(b"\n")

            elif port == 3306:  # MySQL
                pass  # Just wait for banner

            elif port == 5432:  # PostgreSQL
                ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                s.sendall(ssl_request)

            # Default probe
            s.sendall(b"\r\n")

            banner = s.recv(1024).decode(errors="ignore").strip()
            
            if verbose:
                print(f"[*] Raw banner from port {port}: {banner}")

            return banner or "No banner received"
    
    except Exception as e:
        if verbose:
            print(f"[!] Banner grab failed on port {port}: {e}")
        return f"Error: {e}"

def webProbe(ip, port):
    try:
        conn_class = http.client.HTTPConnection if port == 80 else http.client.HTTPSConnection
        conn = conn_class(ip, port, timeout=2)
        probe_paths = ["/", "/robots.txt", "/phpinfo.php", "/admin", "/nonexistent.aspx"]

        all_banners = []

        for path in probe_paths:
            try:
                conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
                response = conn.getresponse()
                banner = f"[{path}] {response.status} {response.reason} - Server: {response.getheader('Server')}, Powered-By: {response.getheader('X-Powered-By')}"
                all_banners.append(banner)
            except Exception as e:
                all_banners.append(f"[{path}] Error: {e}")

        conn.close()
        return "\n".join(all_banners)

    except Exception as e:
        return f"[HTTPS Error] {e}"
