import customtkinter as ctk
import subprocess
import threading
from tkinter import messagebox, filedialog

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

class NmapGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ Advanced Nmap GUI - CustomTkinter Edition")
        self.geometry("950x800")
        self.after(100, lambda: self.wm_attributes("-zoomed", True))  # Maximize on Linux
        self.resizable(True, True)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.build_ui()

    def build_ui(self):
        font = ("Times New Roman", 14)

        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=20, fill="x")

        self.target_entry = self._add_label_entry("🎯 Target IP/Host:", 0, font)
        self.scan_menu = self._add_label_dropdown("📡 Scan Type:", list(nmap_scans.keys()), 1, font, "Quick Scan")
        self.custom_flags_entry = self._add_label_entry("🛠️ Custom Flags:", 2, font)
        self.save_option = self._add_label_dropdown("💾 Save Output As:", ["None", "Text (.txt)", "XML (.xml)"], 3, font, "None")

        self.run_btn = ctk.CTkButton(
            self.frame,
            text="🚀 Run Scan",
            command=self.run_scan_threaded,
            font=font,
            fg_color="#1f6aa5",
            hover_color="#FF4C4C"
        )
        self.run_btn.grid(row=4, column=1, pady=10, sticky="e")

        self.theme_btn = ctk.CTkButton(self.frame, text="🌗 Toggle Theme", command=self.toggle_theme, font=font)
        self.theme_btn.grid(row=4, column=0, pady=10, sticky="w")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.pack(fill="x", padx=20)
        self.progress.set(0)

        self.output_textbox = ctk.CTkTextbox(self, height=500, font=("Times New Roman", 13))
        self.output_textbox.pack(padx=20, pady=10, fill="both", expand=True)
        self.output_textbox.insert("0.0", "[+] Output will appear here...\n")
        self.output_textbox.configure(state="disabled")

        self.github_link = ctk.CTkLabel(self, text="🔗 https://github.com/ChurchBoyTechnologuru", text_color="gray", font=("Times New Roman", 12), cursor="hand2")
        self.github_link.pack(pady=(0, 10))
        self.github_link.bind("<Button-1>", lambda e: self.open_link())

    def _add_label_entry(self, label, row, font):
        ctk.CTkLabel(self.frame, text=label, font=font).grid(row=row, column=0, pady=5, sticky="w")
        entry = ctk.CTkEntry(self.frame, font=font, width=350)
        entry.grid(row=row, column=1, padx=5)
        return entry

    def _add_label_dropdown(self, label, values, row, font, default=""):
        ctk.CTkLabel(self.frame, text=label, font=font).grid(row=row, column=0, pady=5, sticky="w")
        var = ctk.StringVar(value=default)
        dropdown = ctk.CTkOptionMenu(self.frame, variable=var, values=values, font=font, width=350)
        dropdown.grid(row=row, column=1, padx=5)
        return dropdown

    def toggle_theme(self):
        mode = ctk.get_appearance_mode()
        ctk.set_appearance_mode("Light" if mode == "Dark" else "Dark")

    def run_scan_threaded(self):
        threading.Thread(target=self.run_scan).start()

    def run_scan(self):
        target = self.target_entry.get().strip()
        scan_type = self.scan_menu.get()
        custom_flags = self.custom_flags_entry.get().strip()
        save_mode = self.save_option.get()

        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target IP or hostname.")
            return

        flags = nmap_scans[scan_type]
        command = ["nmap"]

        if scan_type == "Custom Flags":
            if not custom_flags:
                messagebox.showwarning("Missing Flags", "Custom flags must be provided.")
                return
            command += custom_flags.split()
        else:
            command += flags.split()

        save_file = None
        if save_mode != "None":
            ext = ".txt" if "txt" in save_mode else ".xml"
            filetypes = [("Text Files", "*.txt")] if ext == ".txt" else [("XML Files", "*.xml")]
            save_file = filedialog.asksaveasfilename(defaultextension=ext, filetypes=filetypes)
            if ext == ".xml":
                command.append("-oX")
            else:
                command.append("-oN")
            command.append(save_file)

        command.append(target)

        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("0.0", "end")
        self.output_textbox.insert("end", "🧠 [Scanning...] Running:\n" + " ".join(command) + "\n\n")
        self.output_textbox.update()
        self.run_btn.configure(text="🛰️ Scanning...")
        self.progress.start()

        try:
            result = subprocess.run(command, capture_output=True, text=True)
            self.output_textbox.insert("end", result.stdout)
            if result.stderr:
                self.output_textbox.insert("end", f"\n[!] Error:\n{result.stderr}")
        except Exception as e:
            self.output_textbox.insert("end", f"\n[!] Exception:\n{e}")
        finally:
            self.output_textbox.configure(state="disabled")
            self.progress.stop()
            self.run_btn.configure(text="🚀 Run Scan")

    def open_link(self):
        import webbrowser
        webbrowser.open("https://github.com/ChurchBoyTechnologuru")

if __name__ == "__main__":
    app = NmapGUI()
    app.mainloop()
