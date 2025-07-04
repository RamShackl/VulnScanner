import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import subprocess
import json
import signal
import sys
from visualizer import visualize_network_interactive
from utils.reportWriter import saveReport
from scanner import generateTargets, scanTargets, COMMONPORTS

def signal_handler(sig, frame):
    print("Exiting, closing GUI windows...")
    root.destroy()  # root is your Tkinter main window
    sys.exit(0)

class VulnScannerGUI:
    def __init__(self, root):

        # Progress bar label
        self.progress_label = ttk.Label(root, text="Scan Progress:")
        self.progress_label.pack(pady=(10, 0))

        # Progress bar widget
        self.progress = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(pady=(0, 10))


        self.root = root
        self.root.title("Python Vulnerability Scanner")
        self.root.geometry("800x600")

        self.target_label = ttk.Label(root, text="Target IP or CIDR:")
        self.target_label.pack(pady=5)
        self.target_entry = ttk.Entry(root, width=50)
        self.target_entry.pack()

        self.verbose_var = tk.BooleanVar(value=True)
        self.verbose_check = ttk.Checkbutton(root, text="Verbose Output", variable=self.verbose_var)
        self.verbose_check.pack()

        self.start_button = ttk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.start_button.pack(pady=10)

        self.view_button = ttk.Button(root, text="View Report", command=self.view_report)
        self.view_button.pack(pady=5)

        self.visualize_button = tk.Button(root, text="Visualize Network", command=self.visualize_network)
        self.visualize_button.pack(pady=5)


        self.full_scan_var = tk.BooleanVar()
        self.full_scan_check = ttk.Checkbutton(root, text="Scan all well-known ports", variable=self.full_scan_var)
        self.full_scan_check.pack()

        self.show_debug = tk.BooleanVar(value=True)
        self.debug_toggle_button = tk.Checkbutton(root, text= "Hide Debug", variable=self.show_debug, command=self.toggle_debug)
        self.debug_toggle_button.pack()

        self.output_box = ScrolledText(root, height=25, bg="black", fg="lime", font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True)

        self.log("[~] Initializing Vulnerability Scanner...")
        self.ensure_nvd_data()
        self.log("[#] Setup complete. Ready to scan.")

    def toggle_debug(self):
        if self.show_debug.get():
            self.output_box.pack(fill=tk.BOTH, expand=True)
            self.debug_toggle_button.config(text="Hide Debug")
        else:
            self.output_box.pack_forget()
            self.debug_toggle_button.config(text="Show Debug")

        self.root.update_idletasks()
        self.root.minsize(self.root.winfo_width(), self.root.winfo_height())

    def print_to_log(self, *args, **kwargs):
        message = " ".join(str(arg) for arg in args)
        self.log(message)

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
    
    def run_scan(self):
        target = self.target_entry.get()
        verbose = self.verbose_var.get()
        port_list = list(range(1, 1025)) if self.full_scan_var.get() else None

        if not target:
            messagebox.showwarning("Missing Target", "Please enter a valid IP or CIDR.")
            return

        targets = generateTargets(target)
        total_tasks = len(targets) * (len(port_list) if port_list else len(COMMONPORTS))
        self.progress["maximum"] = total_tasks
        self.progress["value"] = 0

        # Define progress callback that updates the progress bar on the GUI thread
        def progress_callback():
            self.root.after(0, lambda: self.progress.step(1))

        self.log(f"[~] Starting scan for: {target}")

        original_print = __builtins__.print
        __builtins__.print = self.print_to_log

        try:
            # Pass the progress_callback to scanTargets
            results = scanTargets(targets, verbose=verbose, port_list=port_list, progress_callback=progress_callback)
        finally:
            __builtins__.print = original_print

        saveReport(results, verbosity="full") # or 'summary' for a brief report

        self.log("[#] Scan complete. Report saved to report.json")
        self.start_button.config(state=tk.NORMAL)

    def log(self, message):
        self.output_box.insert(tk.END, message + "\n")
        self.output_box.see(tk.END)

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
            report_text.insert(tk.END, f"--- OPEN PORTS ---\n", "subheader")

            for port, info in result.get("openPorts", {}).items():
                banner = info.get("banner", "No banner")
                vuln = info.get("vulnerable", False)
                report_text.insert(tk.END, f"  Port {port}: {banner}\n")

                if vuln:
                    report_text.insert(tk.END, "    Vulnerabilities:\n", "vuln")
                    for cve in info.get("vulnerabilities_found", []):
                        report_text.insert(
                            tk.END,
                            f"      -{cve.get('id')}: {cve.get('summary')}\n",
                            "vuln"
                        )
                else:
                    report_text.insert(tk.END, "    No known vulnerabilities detected.\n")

        report_text.tag_config("header", foreground="blue", font=("Courier", 11, "bold"))
        report_text.tag_config("subheader", foreground="gray", font=("Courier", 10, "bold"))
        report_text.tag_config("vuln", foreground="red", font=("Courier", 10, "bold"))
        report_text.tag_config("clean", foreground="green", font=("Courier", 10, "italic"))

        report_text.config(state=tk.DISABLED)

    def visualize_network(self):
        if not os.path.exists("report.json"):
            messagebox.showerror("No Report", "No report.json file found.")
            return

        try:
            with open("report.json", "r") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error Reading Report", str(e))
            return

        self.log("[~] Opening network visualizer...")
        visualize_network_interactive(data)
        self.log("[#] Network map written to network_map.html")

if __name__ == "__main__":
    global root
    root = tk.Tk()
    signal.signal(signal.SIGINT, signal_handler)
    app = VulnScannerGUI(root)
    root.mainloop()