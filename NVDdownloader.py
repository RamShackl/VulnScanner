import os
import requests
import gzip
import shutil
from datetime import datetime

# Configurable year and URLs
YEARS_BACK = 5
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
EXTRA_FEEDS = ["modified", "recent"]

# Function to download NVD feed for setup - configurable to update to current version - can try to make this automatic one day.

def downloadNVDfeed(feed_name):
    gz_name = f"nvdcve-1.1-{feed_name}.json.gz"
    json_name = f"nvdcve-1.1-{feed_name}.json"
    url = f"{BASE_URL}/{gz_name}"

    if os.path.exists(json_name):
        print(f"[*] Already downloaded and extracted: {json_name}.")
        return json_name

    print(f"[v] Downloading: {gz_name}")
    try:
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()

        with open(gz_name, "wb") as f:
            shutil.copyfileobj(response.raw, f)

        print(f"[_] Extracting: {gz_name}")
        with gzip.open(gz_name, "rb") as f_in, open(json_name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        os.remove(gz_name)
        print(f"[*] Done: {json_name}")
        return json_name
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to download {feed_name}: {e}")
        return None

def downloadAllfeeds():
    feeds = EXTRA_FEEDS.copy()
    currentYear = datetime.now().year
    for y in range(currentYear - YEARS_BACK + 1, currentYear + 1):
        feeds.append(str(y))

    print(f"[~] Preparing to download {len(feeds)} feeds...")
    results = []
    for feed in feeds:
        result = downloadNVDfeed(feed)
        if result:
            results.append(result)

    print(f"[o] {len(results)} feeds downloaded successfully.")
    return results

# Main call.
if __name__ == "__main__":
    downloaded = downloadAllfeeds()
    print("[DEBUG] Result:", downloaded)