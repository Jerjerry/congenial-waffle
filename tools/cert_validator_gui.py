import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from cert_validator import CertificateValidator
import logging

class CertificateValidatorGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("iOS Certificate Validator")
        self.window.geometry("800x600")
        
        # Create main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Certificate Frame
        cert_frame = ttk.LabelFrame(main_frame, text="Certificate", padding="5")
        cert_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(cert_frame, text="P12 Certificate:").grid(row=0, column=0, sticky=tk.W)
        self.cert_path = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.cert_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(cert_frame, text="Browse", command=self.browse_cert).grid(row=0, column=2)
        
        ttk.Label(cert_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.password, show="*", width=50).grid(row=1, column=1, padx=5)
        
        ttk.Button(cert_frame, text="Validate Certificate", command=self.validate_cert).grid(row=2, column=0, columnspan=3, pady=5)
        
        # Provisioning Profile Frame
        profile_frame = ttk.LabelFrame(main_frame, text="Provisioning Profile", padding="5")
        profile_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(profile_frame, text="Profile:").grid(row=0, column=0, sticky=tk.W)
        self.profile_path = tk.StringVar()
        ttk.Entry(profile_frame, textvariable=self.profile_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(profile_frame, text="Browse", command=self.browse_profile).grid(row=0, column=2)
        
        ttk.Button(profile_frame, text="Validate Profile", command=self.validate_profile).grid(row=1, column=0, columnspan=3, pady=5)
        
        # Compatibility Check Button
        ttk.Button(main_frame, text="Check Compatibility", command=self.check_compatibility).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Results Frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.results_text = tk.Text(results_frame, height=15, width=80)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select P12 Certificate",
            filetypes=[("P12 files", "*.p12")]
        )
        if filename:
            self.cert_path.set(filename)
            
    def browse_profile(self):
        filename = filedialog.askopenfilename(
            title="Select Provisioning Profile",
            filetypes=[("Provisioning Profile", "*.mobileprovision")]
        )
        if filename:
            self.profile_path.set(filename)
            
    def log_result(self, title, valid, details):
        self.results_text.insert(tk.END, f"\n{'-'*20} {title} {'-'*20}\n")
        self.results_text.insert(tk.END, f"Status: {'✓ Valid' if valid else '✗ Invalid'}\n")
        
        if isinstance(details, dict):
            self.results_text.insert(tk.END, json.dumps(details, indent=2, default=str))
        else:
            self.results_text.insert(tk.END, str(details))
            
        self.results_text.insert(tk.END, "\n")
        self.results_text.see(tk.END)
        
    def validate_cert(self):
        if not self.cert_path.get():
            messagebox.showerror("Error", "Please select a certificate")
            return
            
        valid, details = CertificateValidator.validate_p12(
            self.cert_path.get(),
            self.password.get()
        )
        
        self.log_result("Certificate Validation", valid, details)
        
    def validate_profile(self):
        if not self.profile_path.get():
            messagebox.showerror("Error", "Please select a provisioning profile")
            return
            
        valid, details = CertificateValidator.validate_provisioning_profile(
            self.profile_path.get()
        )
        
        self.log_result("Profile Validation", valid, details)
        
    def check_compatibility(self):
        if not self.cert_path.get() or not self.profile_path.get():
            messagebox.showerror("Error", "Please select both certificate and profile")
            return
            
        valid, details = CertificateValidator.check_cert_profile_compatibility(
            self.cert_path.get(),
            self.profile_path.get(),
            self.password.get()
        )
        
        self.log_result("Compatibility Check", valid, details)
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = CertificateValidatorGUI()
    app.run()
