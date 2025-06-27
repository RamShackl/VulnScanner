import socket

def ldapStealthProbe(target, port=389, timeout=2):
    bind_request = bytes.fromhex("30 1c 02 01 01 60 17 02 01 03 04 00 80 00 02 01 00 02 01 00 02 01 00")
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.sendall(bind_request)
            resp = s.recv(1024)
            return f"LDAP response: {resp.hex()[:120]}"
    except Exception as e:
        return f"LDAP stealth probe failed: {e}"
