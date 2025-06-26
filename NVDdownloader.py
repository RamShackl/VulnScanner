import os
import requests
import gzip
import shutil

# Configurable year and URLs
YEAR = "2024"
FEED_URL = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{YEAR}.json.gz"
OUTPUT_GZ = f"nvdcve-1.1-{YEAR}.json.gz"
OUTPUT_JSON = f"nvdcve-1.1-{YEAR}.json"

# Function to download NVD feed for setup - configurable to update to current version - can try to make this automatic one day.
def downloadNVDfeed():
    if os.path.exists(OUTPUT_JSON):
        print(f"[+] JSON file already exists: {OUTPUT_JSON}")
        return OUTPUT_JSON
    
    # Terminal output to start and verify download start and success.
    print(f"[+] Downloading {OUTPUT_GZ}...")
    response = requests.get(FEED_URL, stream=True)
    if response.status_code == 200:
        with open(OUTPUT_GZ, "wb") as f:
            shutil.copyfileobj(response.raw, f)
        print("[+] Download Complete.")

        # More terminal output and start extraction.
        print("[+] Extracting JSON ...")
        with gzip.open(OUTPUT_GZ, "rb") as f_in:
            with open(OUTPUT_JSON, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Notify user of successful download/unzip and cleans up compressed files.
        print(f"[+] Extraction complete: {OUTPUT_JSON}")
        os.remove(OUTPUT_GZ)
        print(f"[+] Cleaned up compressed file.")
        return OUTPUT_JSON
    else:
        print(f"[!] Failed to download feed. Status code: {response.status_code}")
        return None

# Main call.
if __name__ == "__main__":
    result = downloadNVDfeed()
    print("[DEBUG] Result:", result)