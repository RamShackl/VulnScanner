import socket

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