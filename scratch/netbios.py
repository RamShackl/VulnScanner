import socket

def netbiosProbe(target, port, verbose=False):
    """
    Sends a NetBIOS name query to UDP port 137 to enumerate NetBIOS names.
    Returns a formatted string of NetBIOS names if successful.
    """
    try:
        # NetBIOS name query packet (standard NBNS query)
        # Transaction ID: 0x0000, Flags: 0x0010 (recursion desired)
        # Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs:0
        packet = b'\x00\x00' # Transaction ID
        packet += b'\x00\x10' # Flags (standard query, recursion desired)
        packet += b'\x00\x01' # Questions
        packet += b'\x00\x00' # Answer RRs
        packet += b'\x00\x00' # Authority RRs
        packet += b'\x00\x00' # Additional RRs

        # Query name: 32 bytes encoded NetBIOS name '*'
        # NBNS names are 16 bytes but encoded in a special way:
        # '*' means query all names
        query_name = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
        
        # Function to encode a NetBIOS name wildcard '*'abs
        def encodeNetBIOSname(name):
            # Pad or truncate to 15 chars (name length max)
            name = name.ljust(15)
            encoded = b''
            for c in name:
                # Encode each character as two ASCII letters
                n = ord(c)
                high = (n >> 4) + 0x41
                low = (n & 0x0F) + 0x41
                encoded += bytes ([high, low])

            # Add the NetBIOS suffix for 'Workstation Service' (0x00)
            encoded += b'\x41\x41' # Encoding of 0x00 suffix

            return encoded

        encodedName = encodeNetBIOSname('*')
        # Length byte of encoded name is 32 (0x20)
        nbname = b'\x20' + encodedName + b'\x00'

        packet += nbname
        # Query type: NBSTAT (0x0021)
        packet += b'\x00\x21'
        # Query class: IN (0x0001)
        packet += b'\x00\x01'

        if verbose:
            print(f"[*] Sending NetBIOS name query to {target}:{port}")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(packet, (target, port))
            data, _ = s.recvfrom(1024)

            # Parse the response for NetBIOS names
            # Response format: skip header (12 bytes), then variable name info

            # Check response length
            if len(data) < 57:
                return "No NetBIOS names found."

            # Number of names is 1byte at offset 56 (0x38)
            numNames = data[56]
            names = []

            offset = 57
            for _ in range(numNames):
                if offset + 18 > len(data):
                    break
                # Extract name (15 bytes)
                name = data[offset:offset+15].decode('ascii').strip()
                # Name type (1 byte)
                nameType = data[offset+15]
                # Flags (2 bytes)
                flags = struct.unpack('>H', data[offset+16:offset+18])[0]
                offset += 18

                names.append(f"{name} (Type: 0x{nameType:02X}, Flags: 0x{flages:04X})")

            return "NetBIOS Names:\n" + "\n".join(names)

    except Exception as e:
        return f"NetBIOS probe failed: {e}"
