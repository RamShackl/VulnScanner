import socket
import http.client
from probes.dns import dnsProbe
from probes.http import httpProbe
from probes.kerberos import kerberosStealthProbe
from probes.ldap import ldapStealthProbe
from probes.smb import smbStealthProbe
from probes.ssh import sshProbe

PROBEDISPATCH = {
    22: sshProbe,
    53: dnsProbe,
    389: ldapStealthProbe,
    80: httpProbe,
    445: smbStealthProbe,
    88: kerberosStealthProbe,
    464: kerberosStealthProbe,
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
