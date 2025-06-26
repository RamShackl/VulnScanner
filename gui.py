import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import subprocess
import json
import signal
import sys

from scanner import generateTargets, scanTargets, scanTarget

# An attempt at a graceful GUI exit command via CTRL+Z
def signal_handler(sig, frame):
    print("Exiting, closing GUI windows...")
    root.destroy()  # root is your Tkinter main window
    sys.exit(0)

# Main VulnScannerGUI Class
class VulnScannerGUI:
    def __init__(self, root):
        # Window size, title
        self.root = root
        self.root.title("Python Vulnerability Scanner")
        self.root.geometry("800x600")
        # Title, and textbox for IP entry.
        self.target_label = ttk.Label(root, text="Target IP or CIDR:")
        self.target_label.pack(pady=5)
        self.target_entry = ttk.Entry(root, width=50)
        self.target_entry.pack()

        # Check button for verbose output (mostly to assure me it's working?)
        self.verbose_var = tk.BooleanVar()
        self.verbose_check = ttk.Checkbutton(root, text="Verbose Output", variable=self.verbose_var)
        self.verbose_check.pack()

        # Everything needs a start button.
        self.start_button = ttk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.start_button.pack(pady=10)

        # Report Viewer.
        self.view_button = ttk.Button(root, text="View Report", command=self.view_report)
        self.view_button.pack(pady=5)

        # Another boolean button to make it scan 1024 ports if you have all day.
        self.full_scan_var = tk.BooleanVar()
        self.full_scan_check = ttk.Checkbutton(root, text="Scan all well-known ports", variable=self.full_scan_var)
        self.full_scan_check.pack()
        
        # I assure you, if this output wasn't visable, you'd swear I failed.
        self.output_box = ScrolledText(root, height=25, bg="black", fg="lime", font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True)

        # Log text to ensure that all necessary databases, dependencies, and modules were installed properly.
        self.log("[~] Initializing Vulnerability Scanner...")
        self.ensure_nvd_data()
        self.log("[#] Setup complete. Ready to scan.")

    # Defining a print to log function to ensure data is readable.
    def print_to_log(self, *args, **kwargs):
        message = " ".join(str(arg) for arg in args)
        self.log(message)

    # ensuring that database is downloaded properly.
    def ensure_nvd_data(self):
        if not os.path.exists("nvdcve-1.1-2024.json"):
            self.log("[!] NVD database not found. Running setup.py...")
            try:
                subprocess.run(["python3", "setup.py"], check=True)
                self.log("[#] NVD data successfully downloaded.")
            except Exception as e:
                self.log(f"[X] Setup failed: {e}")
                messagebox.showerror("Setup Failed", str(e))
    

    def start_scan_thread(self):
        self.start_button.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.run_scan)
        thread.start()
    
    # Call in the big guns, and start scanning the designated network.
    def run_scan(self):
        target = self.target_entry.get()
        verbose = self.verbose_var.get()
        port_list = list(range(1, 1025)) if self.full_scan_var.get() else None


        if not target:
            messagebox.showwarning("Missing Target", "Please enter a valid IP or CIDR.")
            return

        self.log(f"[~] Starting scan for: {target}")
        targets = generateTargets(target)

        original_print = __builtins__.print
        __builtins__.print = self.print_to_log

        try:
            results = scanTargets(targets, verbose=verbose, port_list=port_list)
        finally:
            __builtins__.print = original_print

        # Save to a JSON for record keeping. Like making an output on nmap.
        with open("report.json", "w") as f:
            json.dump(results, f, indent=2)

        # Assurance that the scan ran successfully.
        self.log("[#] Scan complete. Report saved to report.json")
        self.start_button.config(state=tk.NORMAL)

    # I promise you need a verbose output. It'd drive you mad.
    def log(self, message):
        self.output_box.insert(tk.END, message + "\n")
        self.output_box.see(tk.END)

    # Function to call the JSON file. Highlights vulnerability. Doesn't make it easy to read, yet.
    def view_report(self):
        if not os.path.exists("report.json"):
            messagebox.showerror("No Report", "No report.json file found.")
            return

        try:
            with open("report.json", "r") as f:
                data = json.load(f)
        
        except Exception as e:
            messagebox.showerror("Error Reading Report", str(e))
            return

        report_window = tk.Toplevel(self.root)
        report_window.title("Scan Report - report.json")
        report_window.geometry("700x500")

        report_text = ScrolledText(report_window, bg="white", fg="black", font=("Courier", 10))
        report_text.pack(fill=tk.BOTH, expand=True)

        for result in data:
            target = result.get("target", "Unknown Target")
            report_text.insert(tk.END, f"\n[Target] {target}\n", "header")

            for port, info in result.get("openPorts", {}).items():
                banner = info.get("banner", "No banner")
                vuln = info.get("vulnerable", False)
                report_text.insert(tk.END, f" Port {port}: {banner}\n")

                if vuln:
                    report_text.insert(tk.END, "Vulnerabilities:\n", "vuln")
                    for cve in info.get("vulnerabilities_found", []):
                        report_text.insert(
                            tk.END,
                            f" -{cve.get('id')}: {cve.get('summary')}\n",
                            "vuln"
                        )
                else:
                    report_text.insert(tk.END, "No known vulnerabilities detected.\n")

        report_text.tag_config("vuln", foreground="red", font=("Courier", 10, "bold"))
        report_text.tag_config("header", foreground="blue", font=("Courier", 11, "bold"))

        report_text.config(state=tk.DISABLED)

# Main loop.
if __name__ == "__main__":
    global root
    root = tk.Tk()
    signal.signal(signal.SIGINT, signal_handler)
    app = VulnScannerGUI(root)
    root.mainloop()