import socket
from probe import grabBanner
from utils.vulnDB import vulnLookup
from utils.cveAPI import searchCVE
import ipaddress
from utils.serviceParser import parseBanner
from concurrent.futures import ThreadPoolExecutor, as_completed

# List of common ports which may be exploited and have known vulnerabilities.
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

    # Kerberos
    88, 464,

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

# Accepts inputs for scanning
def generateTargets(target_input):
    targets = []
    try:
        # Check for IP range / CIDR
        network = ipaddress.ip_network(target_input, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Not a CIDR - maybe a single IP or domain
        try:
            resolved_ip = socket.gethostbyname(target_input)
            targets = [resolved_ip]
        except socket.gaierror:
            print(f"[!] Could not resolve domain: {target_input}")
            return []

    return targets

# Reverse DNS to resolve hostnames (doesn't appear to work unless configured locally)
def resolveHostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Scan target function
def scanTarget(target, verbose=False, port_list=None, progress_callback=None):
    if port_list is None:
        port_list = COMMONPORTS

    # Hostname resolver (not working.)
    hostname = resolveHostname(target)
    report = {
        "target": target, 
        "hostname":hostname if hostname else "",
        "openPorts":{}
    }
   

    for port in port_list:

        # Specific timeouts for probes that may require more scanning time to get a response.
        if port in {53, 137, 138, 445}:
            timeout = 2.0
        elif port in {22, 80, 443}:
            timeout = 1.0
        else:
            timeout = 0.5

        # verbose output for debugging and flair
        if verbose:
            print(f"[*] Scanning {target} on port {port}...")

        # scan loop
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))

                # If response detected, attempts probes.
                if result == 0:
                    banner = grabBanner(target, port, verbose)
                    service, version = parseBanner(banner)

                    # verbose output for open ports, displays banner and service/version for vulnerability lookup
                    if verbose:
                        print(f"[+] Port {port} open")
                        print(f"    └─ Banner: {banner.strip()}")
                        if service and version:
                            print(f"    └─ Detected: {service} {version}")
                    
                    # Skips if vuln lookup indicates banner error or no useful info.
                    if banner.startswith("Error") or not banner.strip() or service is None:
                        if verbose:
                            print(f"[!] Skipping vulnerability check on port {port} due to missing banner or service.")
                        finalVulns = []

                        # Allows open ports to still be displayed whether or not they are vulnerable for further enumeration with other tools.
                        report["openPorts"][port] = {
                            "banner": banner.strip(),
                            "vulnerable": False,
                            "notes": "Banner unavailable or error during grab.",
                            "vulnerabilities_found": "No known vulnerabilities found."
                        }
                    else:
                        
                        # queries local nvdcve database for matches.
                        queries = []
                        if service and version:
                            queries = [
                                f"{service} {version}"
                                f"{service}/{version}"
                                f"{service}-{version}"
                                f"{service} version {version}"
                            ]
                        else:
                            queries = [banner.strip()]

                        # queries API database for matches
                        apiResults = []
                        for q in queries:
                            apiResults.extend(searchCVE(q))
                    
                        # 
                        seenIDs = set()
                        uniqueAPIresults = []
                        for cve in apiResults:
                            cid = cve.get("id")
                            if cid and cid not in seenIDs:
                                seenIDs.add(cid)
                                uniqueAPIresults.append(cve)

                        # checks vulnLookup for vulnerabilities
                        matched_cves = []
                        for word in banner.lower().split():
                            if word in vulnLookup:
                                matched_cves.extend(vulnLookup[word][:2])  # Top 2 results

                        allVulns = uniqueAPIresults + [{"id": cve, "summary": "From local DB"} for cve in matched_cves]

                        # Vulnerabilities
                        finalVulns = []
                        seenFinal = set()
                        for v in allVulns:
                            cid = v.get("id")
                            if cid and cid not in seenFinal:
                                seenFinal.add(cid)
                                finalVulns.append({
                                    "id": cid,
                                    "summary": v.get("summary", "No summary available")
                                })
                        if not finalVulns and verbose:
                            print(f"[#] Port {port} - No known vulnerabilities found.")

                        # Reports the vulnerable port/service
                        report["openPorts"][port] = {
                            "banner": banner.strip(),
                            "vulnerable": bool(finalVulns),
                            "notes": "None",
                            "vulnerabilities_found": finalVulns if finalVulns else "No known vulnerabilities found."
                        }

        # Error handling
        except Exception as e:
            if verbose:
                print(f"[!] Error on port {port}: {e}")
            continue 

        # Progress bar feedback
        if progress_callback:
            progress_callback()

    return report


# Multithreading function to allow for faster scanning.
def scanTargets(target_list, verbose=False, port_list=None, progress_callback=None):
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scanTarget, target, verbose=verbose, port_list=port_list, progress_callback=progress_callback): target
            for target in target_list
        }
        for future in as_completed(futures):
            results.append(future.result())
    return results
