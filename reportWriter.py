import json

def saveReport(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Report saved to {filename}")