import socket

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
