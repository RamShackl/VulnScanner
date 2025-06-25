import re

def parseBanner(banner):
    """
    Attempt to extract the service name and version from a banner string.
    Returns a type: (service_name, version), or (None, None) if not found
    """

    banner = banner.lower()


    # Define some common service regex patterns
    patterns = [
        (r"(proftpd)[^\d]*(\d+(\.\d+)+[a-z]*)", "FTP"),
        (r"(vsftpd)[^\d]*(\d+(\.\d+)+[a-z]*)", "FTP"),
        (r"(openssh)[^\d]*(\d+(\.\d+)+[a-z]*)", "SSH"),
        (r"(apache)[^\d]*(\d+(\.\d+)+)", "HTTP"),
        (r"(nginx)[^\d]*(\d+(\.\d+)+)", "HTTP"),
        (r"(mysql)[^\d]*(\d+(\.\d+)+)", "MySQL"),
        (r"(postgre(?:sql)?)[^\d]*(\d+(\.\d+)+)", "PostgreSQL"),
        (r"(microsoft-iis)[^\d]*(\d+(\.\d+)+)", "HTTP"),
    ]

    for pattern, _ in patterns:
        match = re.search(pattern, banner)
        if match:
            service = match.group(1)
            version = match.group(2)
            return service, version
        
    return None, None