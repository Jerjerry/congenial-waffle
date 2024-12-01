import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
from pathlib import Path
import threading
from pysign import IPASigner
import webbrowser
from ttkthemes import ThemedTk

class SimpleSignerGUI:
    def __init__(self):
        self.window = ThemedTk(theme="arc")  # Modern theme
        self.window.title("IPA Signer")
        self.window.geometry("700x650")
        self.window.resizable(True, True)
        
        # Style
        self.style = ttk.Style()
        self.style.configure('Title.TLabel', font=('Helvetica', 24, 'bold'))
        self.style.configure('Subtitle.TLabel', font=('Helvetica', 10))
        self.style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        
        # Variables
        self.ipa_path = tk.StringVar()
        self.cert_path = tk.StringVar()
        self.bundle_id = tk.StringVar()
        self.cert_password = tk.StringVar()
        self.dylib_path = tk.StringVar()
        self.weak_dylib = tk.BooleanVar()
        self.status = tk.StringVar(value="Ready")
        
        # Create GUI
        self.create_gui()
        
    def create_gui(self):
        # Main frame with padding
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title = ttk.Label(main_frame, text="IPA Signer", style='Title.TLabel')
        title.grid(row=0, column=0, columnspan=3, pady=(0, 5))
        
        subtitle = ttk.Label(main_frame, text="Sign and modify your iOS applications", style='Subtitle.TLabel')
        subtitle.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        # Create sections
        current_row = self.create_required_section(main_frame, 2)
        current_row = self.create_optional_section(main_frame, current_row)
        current_row = self.create_dylib_section(main_frame, current_row)
        self.create_action_section(main_frame, current_row)
        
    def create_required_section(self, parent, row):
        # Required Files Section
        section_label = ttk.Label(parent, text="Required Files", style='Header.TLabel')
        section_label.grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 10))
        
        # IPA File
        ttk.Label(parent, text="IPA File:").grid(row=row+1, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.ipa_path)
        entry.grid(row=row+1, column=1, sticky="ew", padx=5)
        browse_btn = ttk.Button(parent, text="Browse", command=self.browse_ipa)
        browse_btn.grid(row=row+1, column=2, pady=5)
        
        # Certificate
        ttk.Label(parent, text="Certificate (p12):").grid(row=row+2, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.cert_path)
        entry.grid(row=row+2, column=1, sticky="ew", padx=5)
        browse_btn = ttk.Button(parent, text="Browse", command=self.browse_cert)
        browse_btn.grid(row=row+2, column=2, pady=5)
        
        return row + 3
        
    def create_optional_section(self, parent, row):
        # Optional Settings Section
        section_label = ttk.Label(parent, text="Optional Settings", style='Header.TLabel')
        section_label.grid(row=row, column=0, columnspan=3, sticky="w", pady=(20, 10))
        
        # Certificate Password
        ttk.Label(parent, text="Password:").grid(row=row+1, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.cert_password, show="*")
        entry.grid(row=row+1, column=1, columnspan=2, sticky="ew", pady=5)
        
        # Bundle ID
        ttk.Label(parent, text="Bundle ID:").grid(row=row+2, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.bundle_id)
        entry.grid(row=row+2, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Label(parent, text="Example: com.example.app").grid(row=row+3, column=1, sticky="w", pady=(0, 10))
        
        return row + 4
        
    def create_dylib_section(self, parent, row):
        # Dylib Section
        section_label = ttk.Label(parent, text="Dylib Injection", style='Header.TLabel')
        section_label.grid(row=row, column=0, columnspan=3, sticky="w", pady=(20, 10))
        
        # Dylib File
        ttk.Label(parent, text="Dylib:").grid(row=row+1, column=0, sticky="w", pady=5)
        entry = ttk.Entry(parent, textvariable=self.dylib_path)
        entry.grid(row=row+1, column=1, sticky="ew", padx=5)
        browse_btn = ttk.Button(parent, text="Browse", command=self.browse_dylib)
        browse_btn.grid(row=row+1, column=2, pady=5)
        
        # Weak Dylib Checkbox
        check = ttk.Checkbutton(parent, text="Inject as Weak Dylib", variable=self.weak_dylib)
        check.grid(row=row+2, column=1, sticky="w", pady=5)
        
        return row + 3
        
    def create_action_section(self, parent, row):
        # Action Section
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=0, columnspan=3, pady=20)
        frame.columnconfigure(0, weight=1)
        
        # Sign Button
        sign_btn = ttk.Button(frame, text="Sign IPA", command=self.sign_ipa, style='Accent.TButton')
        sign_btn.grid(row=0, column=0, pady=10)
        
        # Progress Bar
        self.progress = ttk.Progressbar(frame, length=400, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky="ew", pady=5)
        
        # Status Label
        status_label = ttk.Label(frame, textvariable=self.status)
        status_label.grid(row=2, column=0, pady=5)
        
        # Help Button
        help_btn = ttk.Button(frame, text="Help", command=self.show_help)
        help_btn.grid(row=3, column=0, pady=10)
        
    def browse_ipa(self):
        filename = filedialog.askopenfilename(
            title="Select IPA File",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
        )
        if filename:
            self.ipa_path.set(filename)
            
    def browse_cert(self):
        filename = filedialog.askopenfilename(
            title="Select Certificate",
            filetypes=[("P12 files", "*.p12"), ("All files", "*.*")]
        )
        if filename:
            self.cert_path.set(filename)
            
    def browse_dylib(self):
        filename = filedialog.askopenfilename(
            title="Select Dylib",
            filetypes=[("Dylib files", "*.dylib"), ("All files", "*.*")]
        )
        if filename:
            self.dylib_path.set(filename)
            
    def show_help(self):
        help_text = """IPA Signer Help

Required Files:
- IPA File: The iOS application you want to sign
- Certificate: Your signing certificate (.p12 file)

Optional Settings:
- Password: Certificate password if protected
- Bundle ID: New bundle identifier (e.g., com.example.app)

Dylib Injection:
- Dylib: Dynamic library to inject into the app
- Weak Dylib: Inject as optional dependency

For more information, visit our documentation."""
        
        messagebox.showinfo("Help", help_text)
            
    def sign_ipa(self):
        if not self.ipa_path.get():
            messagebox.showerror("Error", "Please select an IPA file")
            return
            
        if not self.cert_path.get():
            messagebox.showerror("Error", "Please select a certificate")
            return
            
        # Get output path
        output_path = filedialog.asksaveasfilename(
            title="Save Signed IPA",
            defaultextension=".ipa",
            filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")],
            initialfile="signed_" + os.path.basename(self.ipa_path.get())
        )
        
        if not output_path:
            return
            
        # Disable UI during signing
        self.toggle_ui(False)
        self.progress.start()
        
        # Start signing in a separate thread
        thread = threading.Thread(target=lambda: self._sign_ipa_thread(output_path))
        thread.daemon = True
        thread.start()
        
    def _sign_ipa_thread(self, output_path):
        try:
            self.status.set("Signing in progress...")
            
            # Prepare options
            options = {
                'password': self.cert_password.get() or None,
                'bundle_id': self.bundle_id.get() or None,
                'dylib_path': self.dylib_path.get() or None,
                'weak_dylib': self.weak_dylib.get()
            }
            
            # Create signer and sign
            signer = IPASigner()
            signer.sign(
                self.ipa_path.get(),
                self.cert_path.get(),
                output_path,
                **options
            )
            
            self.status.set("Success! Signed IPA saved as: " + output_path)
            messagebox.showinfo("Success", f"IPA signed successfully!\nOutput: {output_path}")
            
        except Exception as e:
            self.status.set("Error: " + str(e))
            messagebox.showerror("Error", f"Signing failed: {str(e)}")
            
        finally:
            # Re-enable UI
            self.window.after(0, lambda: self.toggle_ui(True))
            self.window.after(0, self.progress.stop)
            
    def toggle_ui(self, enabled):
        state = "normal" if enabled else "disabled"
        for child in self.window.winfo_children():
            for widget in child.winfo_children():
                if isinstance(widget, (ttk.Button, ttk.Entry, ttk.Checkbutton)):
                    widget.configure(state=state)
                    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = SimpleSignerGUI()
    app.run()
