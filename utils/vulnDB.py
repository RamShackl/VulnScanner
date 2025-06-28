import json
import os

VULN_DB_PATH = "nvdcve-1.1-2024.json"

def loadCVEdata():
    if not os.path.exists(VULN_DB_PATH):
        print(f"[!] CVE data file not found: {VULN_DB_PATH}")
        return {}

    with open(VULN_DB_PATH, "r") as f:
        cveData = json.load(f)

    lookupTable = {}

    for item in cveData["CVE_Items"]:
        cveID = item["cve"]["CVE_data_meta"]["ID"]
        descList = item["cve"]["description"]["description_data"]
        description = descList[0]["value"] if descList else ""
        for word in description.lower().split():
            if len(word) > 3:
                if word not in lookupTable:
                    lookupTable[word] = []
                lookupTable[word].append((cveID, description))
    
    return lookupTable

vulnLookup = loadCVEdata()
