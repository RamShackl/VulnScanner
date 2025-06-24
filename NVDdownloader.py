import os
import requests
import gzip
import shutil

# Configurable year and URLs
YEAR = "2024"
FEED_URL = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{YEAR}.json.gz"
OUTPUT_GZ = f"nvdcve-1.1-{YEAR}.json,gz"
OUTPUT_JSON = f"nvdcve-1.1-{YEAR}.json"

def downloadNVDfeed():
    if os.path.exists(OUTPUT_JSON):
        print(f"[+] JSON file already exists: {OUTPUT_JSON}")
        return

    print(f"[+] Downloading {OUTPUT_GZ}...")
    response = requests.get(FEED_URL, stream=True)
    if response.status_code == 200:
        with open(OUTPUT_GZ, "wb") as f:
            shutil.copyfileobj(response.raw, f)
        print("[+] Download Complete.")

        print("[+] Extracting JSON ...")
        with gzip.open(OUTPUT_GZ, "rb") as f_in:
            with open(OUTPUT_JSON, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        print(f"[+] Extraction complete: {OUTPUT_JSON}")
        os.remove(OUTPUT_GZ)
        print(f"[+] Cleaned up compressed file.")
    else:
        print(f"[!] Failed to download feed. Status code: {response.status_code}")

