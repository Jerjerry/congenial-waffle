import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from sign_ipa import sign_ipa  # Import our working script

class IPASignerGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("IPA Signer")
        self.window.geometry("600x400")
        
        # Create main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # IPA File
        ttk.Label(main_frame, text="IPA File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ipa_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.ipa_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2)
        
        # Certificate
        ttk.Label(main_frame, text="P12 Certificate:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.cert_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.cert_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_cert).grid(row=1, column=2)
        
        # Password
        ttk.Label(main_frame, text="Certificate Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.password, show="*", width=50).grid(row=2, column=1, padx=5)
        
        # Output
        ttk.Label(main_frame, text="Output IPA:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.output_path = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.output_path, width=50).grid(row=3, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=3, column=2)
        
        # Sign Button
        ttk.Button(main_frame, text="Sign IPA", command=self.sign_ipa).grid(row=4, column=0, columnspan=3, pady=20)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=3)
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA file",
            filetypes=[("IPA files", "*.ipa")]
        )
        if filename:
            self.ipa_path.set(filename)
            # Auto-set output path
            self.output_path.set(filename.replace(".ipa", "_signed.ipa"))
            
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select P12 certificate",
            filetypes=[("P12 files", "*.p12")]
        )
        if filename:
            self.cert_path.set(filename)
            
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
            sign_ipa(
                self.ipa_path.get(),
                self.cert_path.get(),
                self.output_path.get(),
                self.password.get() if self.password.get() else None
            )
            self.status_var.set("IPA signed successfully!")
            messagebox.showinfo("Success", "IPA has been signed successfully!")
        except Exception as e:
            self.status_var.set("Error signing IPA")
            messagebox.showerror("Error", str(e))
            
    def sign_ipa(self):
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return
        if not self.cert_path.get():
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

if __name__ == "__main__":
    app = IPASignerGUI()
    app.run()
