import socket
import requests


def httpProbe(target, port, verbose=False):
    from urllib.parse import urljoin

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.79.1",
        "python-requests/2.31.0"
    ]

    protocols = ["http", "https"] if port in [80, 443, 8080, 8000] else ["http"]
    max_body = 300
    timeout = 3
    max_redirects = 3

    for proto in protocols:
        url = f"{proto}://{target}:{port}/"
        for agent in user_agents:
            headers = {"User-Agent": agent}
            try:
                if verbose:
                    print(f"[~] Trying {proto.upper()} {url} with UA '{agent}'")

                session = requests.Session()
                response = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)

                # Follow up to 3 redirects manually
                redirects = 0
                while response.status_code in [301, 302, 303, 307, 308] and redirects < max_redirects:
                    next_url = response.headers.get("Location")
                    if not next_url:
                        break
                    url = urljoin(url, next_url)
                    response = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                    redirects += 1

                server = response.headers.get("Server", "Unknown Server")
                powered_by = response.headers.get("X-Powered-By", "Unknown")
                status_line = f"{response.status_code} {response.reason}"
                body_snippet = response.text[:max_body].replace("\n", " ").replace("\r", "")

                return f"{proto.upper()} {url}\n{status_line}\nServer: {server}\nX-Powered-By: {powered_by}\nBody Snippet: {body_snippet}"

            except requests.exceptions.Timeout:
                continue  # Try next agent or protocol
            except requests.exceptions.SSLError as e:
                if proto == "https" and verbose:
                    print(f"[!] SSL Error: {e}")
                continue
            except requests.exceptions.RequestException as e:
                if verbose:
                    print(f"[!] Request failed: {e}")
                continue

    return "HTTP probe failed or no response"
