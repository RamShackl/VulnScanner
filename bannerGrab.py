import socket

def grabBanner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as e:
            s.settimeout(1)
            s.connect((ip, port))
            return s.recv(1024).decode(errors="ignore")
    except:
        return "No banner received."
    