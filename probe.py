import socket
import ssl
import http.client
import requests


def httpProbe(target, port, verbose=False):
    from urllib.parse import urljoin

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.79.1",
        "python-requests/2.31.0"
    ]

    protocols = ["http", "https"] if port in [80, 443, 8080, 8000] else ["http"]
    max_body = 300
    timeout = 3
    max_redirects = 3

    for proto in protocols:
        url = f"{proto}://{target}:{port}/"
        for agent in user_agents:
            headers = {"User-Agent": agent}
            try:
                if verbose:
                    print(f"[~] Trying {proto.upper()} {url} with UA '{agent}'")

                session = requests.Session()
                response = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)

                # Follow up to 3 redirects manually
                redirects = 0
                while response.status_code in [301, 302, 303, 307, 308] and redirects < max_redirects:
                    next_url = response.headers.get("Location")
                    if not next_url:
                        break
                    url = urljoin(url, next_url)
                    response = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                    redirects += 1

                server = response.headers.get("Server", "Unknown Server")
                powered_by = response.headers.get("X-Powered-By", "Unknown")
                status_line = f"{response.status_code} {response.reason}"
                body_snippet = response.text[:max_body].replace("\n", " ").replace("\r", "")

                return f"{proto.upper()} {url}\n{status_line}\nServer: {server}\nX-Powered-By: {powered_by}\nBody Snippet: {body_snippet}"

            except requests.exceptions.Timeout:
                continue  # Try next agent or protocol
            except requests.exceptions.SSLError as e:
                if proto == "https" and verbose:
                    print(f"[!] SSL Error: {e}")
                continue
            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"[!] Request failed: {e}")
                continue

    return "HTTP probe failed or no response"
    
def smbProbe(target, port=445, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))

            # NTLMSSP NEGOTIATE packet (extracts useful system data)
            negotiate_protocol_request = bytes.fromhex(
                "00000054"  # Message length
                "ff534d4272000000001801280000000000000000000000000000000000000000"
                "00000000ffffffff000000000000000000000000000000000000000000000000"
                "000000000000000000"
            )

            s.sendall(negotiate_protocol_request)
            data = s.recv(4096)

            if b"NTLMSSP" in data:
                return "SMB NTLMSSP negotiation received. Possible null session or guest access."
            return "SMB response received, but NTLMSSP not found."
    except Exception as e:
        return f"Enhanced SMB probe failed: {e}"

def sshProbe(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner or "No SSH banner received"
    except Exception as e:
        return f"SSH probe failed: {e}"

def ldapProbe(target, port=389, timeout=3):
    try:
        # Basic LDAP anonymous bind request (BER encoded)
        ldap_bind = bytes.fromhex(
            "30 1c 02 01 01 60 17 02 01 03 04 00 80 00 02 01 00 02 01 00 02 01 00"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            s.sendall(ldap_bind)
            data = s.recv(1024)

            if data:
                return f"LDAP bind response received: {data.hex()[:120]}"
            return "LDAP response empty."
    except Exception as e:
        return f"Enhanced LDAP probe failed: {e}"


def dnsProbe(target, port=53, timeout=3):
    try:
        query_id = b"\xaa\xaa"
        flags = b"\x01\x00"  # Standard query
        qdcount = b"\x00\x01"
        ancount = b"\x00\x00"
        nscount = b"\x00\x00"
        arcount = b"\x00\x00"
        domain_parts = b"\x07example\x03com\x00"  # example.com
        qtype = b"\x00\x01"
        qclass = b"\x00\x01"

        dns_query = query_id + flags + qdcount + ancount + nscount + arcount + domain_parts + qtype + qclass

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(dns_query, (target, port))
            data, _ = s.recvfrom(512)

            if data:
                return f"DNS response (hex): {data.hex()[:120]}"
            return "No DNS response."
    except Exception as e:
        return f"Enhanced DNS probe failed: {e}"


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
