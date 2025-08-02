import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time

nmap_scans = {
    "Ping Scan": "-sn",
    "Quick Scan": "-T4 -F",
    "Regular Scan": "",
    "Intense Scan": "-T4 -A -v",
    "Intense Scan + UDP": "-sS -sU -T4 -A -v",
    "Intense Scan (no ping)": "-T4 -A -v -Pn",
    "Ping Scan (UDP)": "-sn -PU",
    "Quick traceroute": "-sn --traceroute",
    "Full Port Scan": "-p-",
    "OS Detection": "-O",
    "Service Version Detection": "-sV",
    "Aggressive Scan": "-A",
    "TCP SYN Scan": "-sS",
    "UDP Scan": "-sU",
    "TCP Connect Scan": "-sT",
    "ACK Scan": "-sA",
    "Window Scan": "-sW",
    "FIN Scan": "-sF",
    "Idle Scan": "-sI",
    "NULL Scan": "-sN",
    "Xmas Scan": "-sX",
    "Custom Flags": ""
}

class NmapGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Advanced Nmap GUI - Kali Linux")
        self.root.geometry("900x650")
        self.root.resizable(False, False)

        self.light_mode = {
            "bg": "#f0f0f0", "fg": "#000000", "highlight": "#007acc", "error": "#cc0000"
        }
        self.dark_mode = {
            "bg": "#1e1e1e", "fg": "#dcdcdc", "highlight": "#33ff33", "error": "#ff3333"
        }
        self.theme = self.dark_mode
        self.build_ui()
        self.set_theme(self.theme)

    def build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        font = ("Times New Roman", 12)

        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.pack(fill='x')

        ttk.Label(self.frame, text="🎯 Target IP/Host:").grid(row=0, column=0, sticky='w', pady=5)
        self.target_entry = ttk.Entry(self.frame, width=40, font=font)
        self.target_entry.grid(row=0, column=1, padx=5)

        ttk.Label(self.frame, text="📡 Scan Type:").grid(row=1, column=0, sticky='w', pady=5)
        self.scan_type_var = tk.StringVar(value="Quick Scan")
        self.scan_menu = ttk.Combobox(self.frame, textvariable=self.scan_type_var, values=list(nmap_scans.keys()), state="readonly", width=35)
        self.scan_menu.grid(row=1, column=1, padx=5)

        ttk.Label(self.frame, text="🛠️ Custom Flags:").grid(row=2, column=0, sticky='w', pady=5)
        self.custom_flags_entry = ttk.Entry(self.frame, width=40, font=font)
        self.custom_flags_entry.grid(row=2, column=1, padx=5)

        self.save_var = tk.StringVar(value="None")
        ttk.Label(self.frame, text="💾 Save Output As:").grid(row=3, column=0, sticky='w', pady=5)
        self.save_option = ttk.Combobox(self.frame, textvariable=self.save_var, state="readonly", width=35)
        self.save_option['values'] = ("None", "Text (.txt)", "XML (.xml)")
        self.save_option.grid(row=3, column=1, padx=5)

        self.run_btn = ttk.Button(self.frame, text="🚀 Run Scan", command=self.run_scan_threaded)
        self.run_btn.grid(row=4, column=1, sticky='e', pady=10)

        self.theme_btn = ttk.Button(self.frame, text="🌙 Toggle Theme", command=self.toggle_theme)
        self.theme_btn.grid(row=4, column=0, sticky='w', pady=10)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill='x', padx=10, pady=(0, 5))

        self.output_frame = ttk.Frame(self.root)
        self.output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap='word', font=("Times New Roman", 11))
        self.output_text.pack(fill='both', expand=True)
        self.output_text.tag_config("cmd", font=("Times New Roman", 11, "bold"))
        self.output_text.tag_config("output", font=("Times New Roman", 11))
        self.output_text.tag_config("error", font=("Times New Roman", 11, "bold"))

    def set_theme(self, theme):
        self.root.configure(bg=theme["bg"])
        self.frame.configure(style="TFrame")
        self.output_text.configure(bg=theme["bg"], fg=theme["fg"], insertbackground=theme["highlight"])
        self.output_text.tag_config("cmd", foreground=theme["highlight"])
        self.output_text.tag_config("output", foreground=theme["fg"])
        self.output_text.tag_config("error", foreground=theme["error"])

    def toggle_theme(self):
        self.theme = self.dark_mode if self.theme == self.light_mode else self.light_mode
        self.set_theme(self.theme)

    def run_scan_threaded(self):
        thread = threading.Thread(target=self.run_scan)
        thread.start()

    def run_scan(self):
        target = self.target_entry.get().strip()
        scan_type = self.scan_type_var.get()
        custom_flags = self.custom_flags_entry.get().strip()

        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target IP/hostname.")
            return

        flags = nmap_scans[scan_type]
        command = ["nmap"]
        if scan_type == "Custom Flags":
            if not custom_flags:
                messagebox.showwarning("Missing Flags", "Enter custom Nmap flags.")
                return
            command += custom_flags.split()
        else:
            command += flags.split()

        save_mode = self.save_var.get()
        save_file = None

        if save_mode != "None":
            file_ext = ".txt" if "txt" in save_mode else ".xml"
            filetypes = [("Text Files", "*.txt")] if file_ext == ".txt" else [("XML Files", "*.xml")]
            save_file = filedialog.asksaveasfilename(defaultextension=file_ext, filetypes=filetypes)
            if file_ext == ".xml":
                command.append("-oX")
            else:
                command.append("-oN")
            command.append(save_file)

        command.append(target)

        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"[+] Running: {' '.join(command)}\n\n", "cmd")
        self.output_text.update()

        self.progress.start()

        try:
            result = subprocess.run(command, capture_output=True, text=True)
            self.output_text.insert(tk.END, result.stdout, "output")
            if result.stderr:
                self.output_text.insert(tk.END, f"\n[!] Error:\n{result.stderr}", "error")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[!] Failed to run Nmap:\n{e}", "error")

        self.output_text.config(state='disabled')
        self.progress.stop()

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapGUI(root)
    root.mainloop()