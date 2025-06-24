import socket
from bannerGrab import grabBanner
from vulnDB import vulnLookup
from cveAPI import searchCVE
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMONPORTS = [
    # FTP / SSH / Telnet
    20, 21, 22, 23,

    # Email
    25, 110, 143, 465, 587, 993, 995,

    # DNS
    53,

    # Web
    80, 81, 443, 8080, 8443,

    # SMB / Windows
    135, 137, 138, 139, 445, 3389,

    # Databases
    1433, 1521, 3306, 5432, 6379,

    # Directory services / LDAP
    389, 636,

    # SNMP / NTP / RPC
    123, 161, 162, 111,

    # Dev tools
    3000, 5000, 8000, 8888,

    # Docker / Kubernetes
    2375, 2376, 6443,

    # Misc Common Services
    1723, 5900, 6000, 6667
]


def generateTargets(ip_or_cidr):
    try:
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [ip_or_cidr]




def scanTarget(target, verbose=False, port_list=None):
    if port_list is None:
        port_list = COMMONPORTS

    report = {"target": target, "openPorts":{}}

    for port in port_list:
        if verbose:
            print(f"[*] Scanning port {port}...")
    
    for port in COMMONPORTS:
        if verbose:
            print(f"[*] Checking port {port}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))

                if result == 0:
                    banner = grabBanner(target, port)
                    if verbose:
                        print(f"[+] Port {port} open: Banner: {banner.strip()}")
                    vulnInfo = None
                    matched_cves = []
                    for word in banner.lower().split():
                        if word in vulnLookup:
                            matched_cves.extend(vulnLookup[word][:2])  # Top 2 results


                    cveResults = searchCVE(banner.strip())
                    report["openPorts"][port] = {
                        "banner": banner.strip(),
                        "vulnerable": bool(cveResults or matched_cves),
                        "notes": f"Local DB matches: {len(matched_cves)}" if matched_cves else "None",
                        "CVE_results": [
                            {"id": cve.get("id"), "summary": cve.get("summary")}
                            for cve in cveResults
                        ]
                    }
        except Exception as e:
            if verbose:
                print(f"[!] Error on port {port}: {e}")
            continue 
    return report


def scanTargets(target_list, verbose=False, port_list=None):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(scanTarget, target, verbose, port_list): target 
            for target in target_list
        }
        for future in as_completed(futures):
            results.append(future.result())
    return results