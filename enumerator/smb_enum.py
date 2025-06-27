from impacket.smbconnection import SMBConnection


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