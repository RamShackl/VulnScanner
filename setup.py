import subprocess
import sys
import os

def installRequirements():
    print("[*] Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("[+] Dependencies installed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Failed to install dependencies.")
        sys.exit(1)


def downloadNVD():
    print("[*] Downloading and extracting NVD vulnerability data...")
    try:
        subprocess.check_call([sys.executable, "NVDdownloader.py"])
        print("[+] NVD data downloaded.")
    except subprocess.CalledProcessError:
        print("[!] Failed to download NVD data.")
        sys.exit(1)

def checkFiles():
    if not os.path.exists("nvdcve-1.1-2024.json"):
        print("[!] NVD JSON file not found. Something went wrong.")
        sys.exit(1)


def main():
    print("=== VulnScanner Setup ===")
    installRequirements()
    downloadNVD()
    checkFiles()
    print("\n[$] Setup complete!")
    print("You can now run the scanner like this:\n")
    print("python3 main.py <target ip(s)> -o report.json\n")

if __name__ == "__main__":
    main()