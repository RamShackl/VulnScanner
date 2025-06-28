from impacket.krb5.asn1 import AS_REQ
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from pyasn1.codec.der.encoder import encode
import socket

def kerberosStealthProbe(target, realm="EXAMPLE.LOCAL", user="krbtgt"):
    try:
        username = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        req = AS_REQ()
        req['pvno'] = 5
        req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
        message = encode(req)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(message, (target, 88))
            data, _ = s.recvfrom(2048)
            return f"Kerberos response: {data.hex()[:120]}"
    except Exception as e:
        return f"Kerberos stealth probe failed: {e}"
