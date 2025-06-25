import socket
import ssl
import http.client

def grabBanner(ip, port, timeout=2):
    try:
        
        # Common HTTP/HTTPS probing
        if port == 80 or port == 443:
            return webProbe(ip, port)

        # Default banner grabbing for other ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            try:
                banner = s.recv(1024).decode(errors="ignore")
            except Exception:
                banner = ""

            if not banner:
                
                # Send basic probe depending on port

                # === FTP Probe ===
                if port == 21: 
                    s.sendall(b"USER anonymous\r\n")
                    try:
                        banner += "\n" + s.recv(1024).decode(errors="ignore").strip()
                    except:
                        pass
                
                # === MySQL Probe ===
                elif port == 3306:
                    try:
                        banner += "\n" + s.recv(1024).decode(errors="ignore").strip()
                    except:
                        pass  # MY SQL often sends version string upon connect.

                # === PostgreSQL Probe ===
                elif port == 5432:
                    # Send SSLRequest packet: 8 bytes: [int length=8] + [int 80877103]
                    try:
                        ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                        s.sendall(ssl_request)
                        resp = s.recv(1024)
                        if resp == b'S':
                            banner += "\nPostgreSQL supports SSL."
                        elif resp == b'N':
                            banner += "\nPostgreSQL does NOT support SSL."
                    except:
                        pass

                # === SMTP Probe ===
                elif port == 25: # SMTP
                    s.sendall(b"EHLO vulnscanner.local\r\n")

                # === POP3 Probe ===
                elif port == 110: # POP3
                    s.sendall(b"USER test\r\n")

                # === IMAP Probe ===
                elif port == 143: # IMAP
                    s.sendall(b"a login test test\r\n")

                # === Telnet Probe ===
                elif port == 23: # Telnet
                    s.sendall(b"\n")
                

                try:
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    pass

            if not banner:
                return "No banner received"
            return banner
    except Exception as e:
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
            except Exception as e:
                all_banners.append(f"[{path}] Error: {e}")

        conn.close()
        return "\n".join(all_banners)

    except Exception as e:
        return f"[HTTPS Error] {e}"