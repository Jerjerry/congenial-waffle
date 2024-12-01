import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import logging

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.pysign import IPASigner
from tools.cert_utils import generate_self_signed_cert
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='signer.log'
)
logger = logging.getLogger(__name__)

class IPASignerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IPA Signer Tool")
        self.root.geometry("800x300")  # Increased width, reduced height
        
        # Configure grid weight
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")  # Increased padding
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure main frame grid weights
        main_frame.grid_columnconfigure(1, weight=1)  # Make the entry column expandable
        
        # IPA File Selection
        ttk.Label(main_frame, text="IPA File:").grid(row=0, column=0, sticky=tk.W, pady=10)  # Increased padding
        self.ipa_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.ipa_path, width=60).grid(row=0, column=1, padx=10, sticky=tk.EW)  # Made wider
        ttk.Button(main_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2, padx=(5, 0))
        
        # Certificate Selection
        ttk.Label(main_frame, text="P12 Certificate:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.cert_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.cert_path, width=60).grid(row=1, column=1, padx=10, sticky=tk.EW)
        ttk.Button(main_frame, text="Browse", command=self.browse_cert).grid(row=1, column=2, padx=(5, 0))
        
        # Certificate Password
        ttk.Label(main_frame, text="Certificate Password:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.cert_password = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.cert_password, show="*", width=30)
        password_entry.grid(row=2, column=1, padx=10, sticky=tk.W)
        ttk.Label(main_frame, text="(Leave blank if no password)").grid(row=2, column=2, sticky=tk.W, padx=(5, 0))
        
        # Sign Button - Centered
        sign_button = ttk.Button(main_frame, text="Sign IPA", command=self.sign_ipa, style='Accent.TButton')
        sign_button.grid(row=3, column=0, columnspan=3, pady=20)
        
        # Configure style for the accent button
        style = ttk.Style()
        style.configure('Accent.TButton', font=('Helvetica', 10, 'bold'))
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, length=400, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, pady=20)
        
        # Status Label
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=3)
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.ipa_path.set(filename)
            
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select P12 Certificate",
            filetypes=[("P12 files", "*.p12"), ("All files", "*.*")]
        )
        if filename:
            self.cert_path.set(filename)
            
    def sign_ipa(self):
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return
            
        if not self.cert_path.get():
            messagebox.showerror("Error", "Please select a P12 certificate")
            return
            
        try:
            self.progress.start()
            self.status_var.set("Signing IPA...")
            self.root.update()
            
            # Create output path
            input_path = self.ipa_path.get()
            output_path = os.path.splitext(input_path)[0] + "_signed.ipa"
            
            # Initialize signer
            signer = IPASigner()
            
            # Sign the IPA with all parameters
            signer.sign(
                ipa_path=input_path,
                p12_path=self.cert_path.get(),
                output_path=output_path,
                password=self.cert_password.get() or None  # Use None if no password provided
            )
            
            self.progress.stop()
            self.status_var.set("IPA signed successfully!")
            messagebox.showinfo(
                "Success",
                f"IPA signed successfully!\nOutput: {output_path}"
            )
            
        except Exception as e:
            logger.error(f"Failed to sign IPA: {str(e)}")
            self.progress.stop()
            self.status_var.set("Error signing IPA")
            messagebox.showerror("Error", f"Failed to sign IPA: {str(e)}")
            
def main():
    root = tk.Tk()
    app = IPASignerGUI(root)
    root.mainloop()
    
if __name__ == "__main__":
    main()
