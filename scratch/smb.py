import socket
from impacket.smbconnection import SMBConnection

def smbProbe(target, port=445, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))

            # SMBv1 Negotiate Protocol Request
            negotiateProtocol= bytes.fromhex(
                "00000054"  # Message length
                "ff534d4272000000001801280000000000000000000000000000000000000000"
                "00000000ffffffff000000000000000000000000000000000000000000000000"
                "000000000000000000"
            )

            s.sendall(negotiateProtocol)
            
            try:
                data = s.recv(512)
                if b"SMB" in data:
                    return "SMB service detected (port 445)"
                return f"Unknown SMB response: {data.dex()[:80]}"
            except socket.timeout:
                return "SMB response timed out (no reply)"
    except ConnectionResetError:
            return "Connection reset by SMB server (likely hardened against probes)"
    except socket.timeout:
            return "Connection timed out (no SMB service response)"
    except Exception as e:
            return f"SMB probe failed: {e}"    



def smbNullprobe(target, verbose=False):
    try:
        conn = SMBConnection(target, target, sess_port=445, timeout=3)
        conn.login('', '')  # Null session login

        if verbose:
            print(f"[+] Null session succeeded on {target}")

        shares = conn.listShares()
        share_list = [f"{share['shi1_netname'].decode().strip()}" for share in shares]

        info = conn.getServerOS()
        domain = conn.getServerDomain()

        result = f"SMB Null Session Successful\n"
        result += f"Server OS: {info}\n"
        result += f"Domain: {domain}\n"
        result += "Shares:\n" + "\n".join(share_list)

        conn.close()
        return result

    except Exception as e:
        return f"SMB Null session failed: {e}"
