import socket

def smbStealthProbe(target, port=445, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            smb2_negotiate = bytes.fromhex("fe534d424000010000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000")
            s.sendall(smb2_negotiate)
            response = s.recv(1024)
            if b"\xfeSMB" in response:
                return f"SMBv2+ response received: {response.hex()[:80]}"
            return "SMB service responded, version unknown"
    except Exception as e:
        return f"SMB stealth probe failed: {e}"