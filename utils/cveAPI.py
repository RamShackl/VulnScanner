import requests

def searchCVE(serviceBanner):
    url = f"https://cve.circl.lu/api/search/{serviceBanner}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            results = response.json().get("results", [])
            return results[:3]
    except Exception as e:
        return [{"id": "CVE-LOOKUP-ERROR", "summary": str(e)}]
    return []