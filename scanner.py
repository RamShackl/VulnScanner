import socket
from bannerGrab import grabBanner
from vulnDB import vulnLookup
from cveAPI import searchCVE
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMONPORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

def generateTargets(ip_or_cidr):
    try:
        network = ipaddress.ip_network(ip_or_cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [ip_or_cidr]




def scanTarget(target, verbose=False):
    report = {"target": target, "openPorts":{}}
    
    for port in COMMONPORTS:
        if verbose:
            print(f"[*] Checking port {port}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))

                if result == 0:
                    banner = bannerGrab(target, port)
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


def scanTargets(target_list, verbose=False):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scanTarget, target): target for target in target_list}
        for future in as_completed(futures):
            results.append(future.result())
        return results