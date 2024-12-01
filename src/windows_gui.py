import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import logging
from .windows_signer import WindowsIPASigner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WindowsSignerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("IPA Signer for Windows")
        self.window.geometry("800x500")
        
        # Create main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # IPA File
        ttk.Label(main_frame, text="IPA File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ipa_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.ipa_path, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2)
        
        # P12 Certificate
        ttk.Label(main_frame, text="P12 Certificate:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.p12_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.p12_path, width=60).grid(row=1, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_p12).grid(row=1, column=2)
        
        # Certificate Password
        ttk.Label(main_frame, text="Certificate Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.password, show="*", width=60).grid(row=2, column=1, padx=5)
        
        # Provisioning Profile
        ttk.Label(main_frame, text="Provisioning Profile:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.profile_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.profile_path, width=60).grid(row=3, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_profile).grid(row=3, column=2)
        
        # Output
        ttk.Label(main_frame, text="Output IPA:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.output_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_path, width=60).grid(row=4, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=4, column=2)
        
        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Log Text
        self.log_text = tk.Text(log_frame, height=10, width=80)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        # Sign Button
        ttk.Button(main_frame, text="Sign IPA", command=self.sign_ipa).grid(row=6, column=0, columnspan=3, pady=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=8, column=0, columnspan=3)
        
        # Configure logging to GUI
        self.log_handler = GUILogHandler(self.log_text)
        logger.addHandler(self.log_handler)
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa")]
        )
        if filename:
            self.ipa_path.set(filename)
            # Auto-set output path
            self.output_path.set(filename.replace(".ipa", "_signed.ipa"))
            
    def browse_p12(self):
        filename = filedialog.askopenfilename(
            title="Select P12 certificate",
            filetypes=[("P12 files", "*.p12")]
        )
        if filename:
            self.p12_path.set(filename)
            
    def browse_profile(self):
        filename = filedialog.askopenfilename(
            title="Select provisioning profile",
            filetypes=[("Provisioning profiles", "*.mobileprovision")]
        )
        if filename:
            self.profile_path.set(filename)
            
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save signed IPA as",
            defaultextension=".ipa",
            filetypes=[("IPA files", "*.ipa")]
        )
        if filename:
            self.output_path.set(filename)
            
    def sign_ipa_thread(self):
        try:
            self.status_var.set("Signing IPA...")
            self.progress.start()
            
            signer = WindowsIPASigner(
                self.ipa_path.get(),
                self.p12_path.get(),
                self.password.get(),
                self.profile_path.get() if self.profile_path.get() else None
            )
            
            signer.sign(self.output_path.get())
            
            self.progress.stop()
            self.status_var.set("IPA signed successfully!")
            messagebox.showinfo("Success", "IPA has been signed successfully!")
            
        except Exception as e:
            self.progress.stop()
            logger.error(f"Error signing IPA: {str(e)}")
            self.status_var.set("Error signing IPA")
            messagebox.showerror("Error", str(e))
            
    def sign_ipa(self):
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return
        if not self.p12_path.get():
            messagebox.showerror("Error", "Please select a P12 certificate")
            return
        if not self.output_path.get():
            messagebox.showerror("Error", "Please select output location")
            return
            
        # Run signing in a separate thread
        thread = threading.Thread(target=self.sign_ipa_thread)
        thread.daemon = True
        thread.start()
        
    def run(self):
        self.window.mainloop()

class GUILogHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record) + '\n'
        self.text_widget.insert(tk.END, msg)
        self.text_widget.see(tk.END)
        self.text_widget.update()

if __name__ == "__main__":
    app = WindowsSignerGUI()
    app.run()
