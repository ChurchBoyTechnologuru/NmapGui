import customtkinter as ctk
import subprocess
from tkinter import filedialog
import threading

ctk.set_appearance_mode("dark")  # Use dark mode appearance

class NmapGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Nmap GUI")
        self.geometry("800x600")
        self.font = ("Times New Roman", 14)
        
        # Widgets
        self.target_label = ctk.CTkLabel(self, text="Target IP / Host:", font=self.font)
        self.target_label.pack(pady=(20, 5))
        self.target_entry = ctk.CTkEntry(self, font=self.font, width=400)
        self.target_entry.pack(pady=5)

        self.flags_label = ctk.CTkLabel(self, text="Nmap Flags (e.g. -sS -p 80):", font=self.font)
        self.flags_label.pack(pady=(20, 5))
        self.flags_entry = ctk.CTkEntry(self, font=self.font, width=400)
        self.flags_entry.pack(pady=5)

        self.output_format = ctk.CTkOptionMenu(self, values=["txt", "xml"], font=self.font)
        self.output_format.set("txt")
        self.output_format.pack(pady=(20, 10))

        self.run_button = ctk.CTkButton(self, text="Run Nmap Scan", command=self.run_nmap_thread, font=self.font)
        self.run_button.pack(pady=10)

        self.output_box = ctk.CTkTextbox(self, font=self.font, width=700, height=300)
        self.output_box.pack(pady=20)

        self.save_button = ctk.CTkButton(self, text="Save Report", command=self.save_report, font=self.font)
        self.save_button.pack(pady=(10, 20))

        self.learn_button = ctk.CTkButton(self, text="Learn Nmap", command=self.open_learn_nmap, font=self.font)
        self.learn_button.pack()

    def run_nmap_thread(self):
        threading.Thread(target=self.run_nmap).start()

    def run_nmap(self):
        target = self.target_entry.get().strip()
        flags = self.flags_entry.get().strip()
        if not target:
            self.output_box.insert("end", "Please enter a target IP or host.\n")
            return

        self.output_box.delete("1.0", "end")
        self.output_box.insert("end", f"Running: nmap {flags} {target}\n\n")

        try:
            result = subprocess.check_output(f"nmap {flags} {target}", shell=True, text=True)
            self.output_box.insert("end", result)
        except subprocess.CalledProcessError as e:
            self.output_box.insert("end", f"Error: {e}\n")

    def save_report(self):
        data = self.output_box.get("1.0", "end").strip()
        if not data:
            return
        file_type = self.output_format.get()
        file = filedialog.asksaveasfilename(defaultextension=f".{file_type}", filetypes=[(file_type.upper(), f"*.{file_type}")])
        if file:
            with open(file, "w") as f:
                f.write(data)

    def open_learn_nmap(self):
        try:
            subprocess.Popen(["python3", "learn_nmap.py"])
        except Exception as e:
            self.output_box.insert("end", f"Failed to open Learn Nmap: {e}\n")

if __name__ == "__main__":
    app = NmapGUI()
    app.mainloop()