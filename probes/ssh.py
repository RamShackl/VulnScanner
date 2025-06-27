import socket

def sshProbe(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner or "No SSH banner received"
    except Exception as e:
        return f"SSH probe failed: {e}"
