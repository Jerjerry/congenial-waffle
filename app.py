import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from sign_ipa import sign_ipa, load_certificate
from tools.certificate import generate_development_certificate

class IPASignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IPA Signer")
        self.root.geometry("600x400")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # IPA File Selection
        ttk.Label(main_frame, text="IPA File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ipa_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.ipa_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2)
        
        # Certificate Selection
        ttk.Label(main_frame, text="P12 Certificate:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.cert_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.cert_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_cert).grid(row=1, column=2)
        
        # Certificate Password
        ttk.Label(main_frame, text="Certificate Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar(value="development")
        ttk.Entry(main_frame, textvariable=self.password, show="*", width=50).grid(row=2, column=1, padx=5)
        
        # Output Path
        ttk.Label(main_frame, text="Output Path:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.output_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_path, width=50).grid(row=3, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=3, column=2)
        
        # Generate Certificate Button
        ttk.Button(
            main_frame, 
            text="Generate Development Certificate",
            command=self.generate_certificate
        ).grid(row=4, column=1, pady=20)
        
        # Sign Button
        ttk.Button(
            main_frame,
            text="Sign IPA",
            command=self.sign_ipa,
            style="Accent.TButton"
        ).grid(row=5, column=1, pady=10)
        
        # Progress
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=7, column=0, columnspan=3)
        
        # Configure style
        style = ttk.Style()
        style.configure("Accent.TButton", foreground="blue")
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.ipa_path.set(filename)
            # Auto-set output path
            output = filename.replace('.ipa', '_signed.ipa')
            self.output_path.set(output)
            
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select P12 certificate",
            filetypes=[("P12 files", "*.p12"), ("All files", "*.*")]
        )
        if filename:
            self.cert_path.set(filename)
            
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save signed IPA as",
            defaultextension=".ipa",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.output_path.set(filename)
            
    def generate_certificate(self):
        try:
            self.status_var.set("Generating development certificate...")
            self.progress.start()
            
            # Generate certificate in tools directory
            tools_dir = os.path.join(os.path.dirname(__file__), 'tools')
            private_key, certificate = generate_development_certificate(tools_dir)
            
            # Set certificate path
            cert_path = os.path.join(tools_dir, 'development.p12')
            self.cert_path.set(cert_path)
            
            self.status_var.set("Development certificate generated successfully!")
            messagebox.showinfo(
                "Success",
                f"Development certificate generated at:\n{cert_path}\n\nPassword: development"
            )
            
        except Exception as e:
            self.status_var.set(f"Error generating certificate: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate certificate: {str(e)}")
            
        finally:
            self.progress.stop()
            
    def sign_ipa(self):
        # Validate inputs
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return
            
        if not self.cert_path.get():
            messagebox.showerror("Error", "Please select a P12 certificate")
            return
            
        if not self.output_path.get():
            messagebox.showerror("Error", "Please select an output path")
            return
            
        try:
            self.status_var.set("Signing IPA...")
            self.progress.start()
            
            # Sign the IPA
            sign_ipa(
                self.ipa_path.get(),
                self.cert_path.get(),
                self.output_path.get(),
                self.password.get()
            )
            
            self.status_var.set("IPA signed successfully!")
            messagebox.showinfo(
                "Success",
                f"Signed IPA saved to:\n{self.output_path.get()}"
            )
            
        except Exception as e:
            self.status_var.set(f"Error signing IPA: {str(e)}")
            messagebox.showerror("Error", f"Failed to sign IPA: {str(e)}")
            
        finally:
            self.progress.stop()

def main():
    root = tk.Tk()
    app = IPASignerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
