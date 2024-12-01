import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from pathlib import Path
from sign_ipa import sign_ipa, load_certificate
from tools.certificate import generate_development_certificate
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class SigningThread(threading.Thread):
    def __init__(self, ipa_path, cert_path, output_path, password, callback):
        super().__init__()
        self.ipa_path = ipa_path
        self.cert_path = cert_path
        self.output_path = output_path
        self.password = password
        self.callback = callback
        self.exception = None
        
    def run(self):
        try:
            sign_ipa(self.ipa_path, self.cert_path, self.output_path, self.password)
            self.callback(True, None)
        except Exception as e:
            self.exception = str(e)
            self.callback(False, str(e))

class IPASignerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("IPA Signer")
        self.window.geometry("800x600")
        self.window.resizable(True, True)
        
        # Configure grid
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(1, weight=1)
        
        # Create frames
        self.create_input_frame()
        self.create_log_frame()
        self.create_status_frame()
        
        # Initialize variables
        self.signing_thread = None
        
    def create_input_frame(self):
        input_frame = ttk.LabelFrame(self.window, text="Input", padding=10)
        input_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        
        # Configure grid
        input_frame.grid_columnconfigure(1, weight=1)
        
        # IPA File
        ttk.Label(input_frame, text="IPA File:").grid(row=0, column=0, sticky="w", pady=5)
        self.ipa_path = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.ipa_path).grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2)
        
        # Certificate
        ttk.Label(input_frame, text="Certificate:").grid(row=1, column=0, sticky="w", pady=5)
        self.cert_path = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.cert_path).grid(row=1, column=1, sticky="ew", padx=5)
        cert_btn_frame = ttk.Frame(input_frame)
        cert_btn_frame.grid(row=1, column=2)
        ttk.Button(cert_btn_frame, text="Browse", command=self.browse_cert).pack(side=tk.LEFT, padx=2)
        ttk.Button(cert_btn_frame, text="Generate", command=self.generate_cert).pack(side=tk.LEFT, padx=2)
        
        # Password
        ttk.Label(input_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.password = tk.StringVar(value="development")
        ttk.Entry(input_frame, textvariable=self.password, show="*").grid(row=2, column=1, sticky="ew", padx=5)
        
        # Output
        ttk.Label(input_frame, text="Output:").grid(row=3, column=0, sticky="w", pady=5)
        self.output_path = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.output_path).grid(row=3, column=1, sticky="ew", padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_output).grid(row=3, column=2)
        
        # Sign Button
        sign_btn = ttk.Button(input_frame, text="Sign IPA", command=self.sign_ipa)
        sign_btn.grid(row=4, column=0, columnspan=3, pady=10)
        
    def create_log_frame(self):
        log_frame = ttk.LabelFrame(self.window, text="Log", padding=10)
        log_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        # Configure grid
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        
        # Log text
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
    def create_status_frame(self):
        status_frame = ttk.Frame(self.window, padding=5)
        status_frame.grid(row=2, column=0, sticky="ew")
        
        # Progress bar
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack()
        
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.ipa_path.set(filename)
            # Auto-set output path
            output = str(Path(filename).with_stem(Path(filename).stem + "_signed"))
            self.output_path.set(output)
            self.log(f"Selected IPA: {filename}")
            
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select P12 certificate",
            filetypes=[("P12 files", "*.p12"), ("All files", "*.*")]
        )
        if filename:
            self.cert_path.set(filename)
            self.log(f"Selected certificate: {filename}")
            
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save signed IPA as",
            defaultextension=".ipa",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.output_path.set(filename)
            self.log(f"Output will be saved to: {filename}")
            
    def generate_cert(self):
        try:
            self.status_var.set("Generating certificate...")
            self.progress.start()
            
            # Generate in tools directory
            tools_dir = os.path.join(os.path.dirname(__file__), 'tools')
            private_key, certificate = generate_development_certificate(tools_dir)
            
            # Set certificate path
            cert_path = os.path.join(tools_dir, 'development.p12')
            self.cert_path.set(cert_path)
            
            self.status_var.set("Certificate generated!")
            self.log(f"Generated development certificate at: {cert_path}")
            self.log("Certificate password: development")
            
        except Exception as e:
            self.status_var.set("Failed to generate certificate")
            self.log(f"Error generating certificate: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate certificate: {str(e)}")
            
        finally:
            self.progress.stop()
            
    def validate_inputs(self):
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return False
            
        if not self.cert_path.get():
            messagebox.showerror("Error", "Please select or generate a certificate")
            return False
            
        if not self.output_path.get():
            messagebox.showerror("Error", "Please select an output location")
            return False
            
        return True
        
    def signing_complete(self, success, error):
        self.progress.stop()
        
        if success:
            self.status_var.set("Signing complete!")
            self.log(f"Successfully signed IPA: {self.output_path.get()}")
            messagebox.showinfo("Success", "IPA signed successfully!")
        else:
            self.status_var.set("Signing failed")
            self.log(f"Error signing IPA: {error}")
            messagebox.showerror("Error", f"Failed to sign IPA: {error}")
            
    def sign_ipa(self):
        if not self.validate_inputs():
            return
            
        self.status_var.set("Signing IPA...")
        self.progress.start()
        self.log("Starting signing process...")
        
        # Start signing in a separate thread
        self.signing_thread = SigningThread(
            self.ipa_path.get(),
            self.cert_path.get(),
            self.output_path.get(),
            self.password.get(),
            self.signing_complete
        )
        self.signing_thread.start()
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = IPASignerGUI()
    app.run()
