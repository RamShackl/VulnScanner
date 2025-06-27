from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.ldap.ldaptypes import ACCESS_MASK
from impacket.ldap.ldaptypes import ACE, ACL
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.ldap.ldaptypes import LDAPEntry
from impacket.ldap.ldaptypes import LdapEntry



def ldapEnumerate(target, domain='', username='', password='', verbose=False):
    try:
        ldap_server = ldap.LDAPConnection(f"ldap://{target}", baseDN=None)
        ldap_server.login('', '')  # Null bind

        res = ldap_server.search('', '(objectClass=*)', attributes=['defaultNamingContext'])
        domain_info = res[0]['attributes']['defaultNamingContext']

        if verbose:
            print(f"[+] LDAP Null Bind Succeeded on {target}")
            print(f"[+] Domain Info: {domain_info}")

        return f"LDAP Null Bind Succeeded\nDomain: {domain_info}"
    except Exception as e:
        return f"LDAP enumeration failed: {e}"

