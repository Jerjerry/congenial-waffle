import tkinter as tk
from tkinter import ttk, messagebox
import os
from cert_generator import CertificateGenerator

class CertificateGeneratorGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("iOS Certificate Generator")
        self.window.geometry("600x800")
        
        self.generator = CertificateGenerator()
        
        # Create main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Certificate Details
        cert_frame = ttk.LabelFrame(main_frame, text="Certificate Details", padding="5")
        cert_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(cert_frame, text="Common Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.common_name = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.common_name, width=40).grid(row=0, column=1, padx=5)
        
        ttk.Label(cert_frame, text="Organization:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.org_name = tk.StringVar(value="iOS Developer")
        ttk.Entry(cert_frame, textvariable=self.org_name, width=40).grid(row=1, column=1, padx=5)
        
        ttk.Label(cert_frame, text="Validity (days):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.valid_days = tk.StringVar(value="365")
        ttk.Entry(cert_frame, textvariable=self.valid_days, width=40).grid(row=2, column=1, padx=5)
        
        ttk.Label(cert_frame, text="P12 Password:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.password = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.password, show="*", width=40).grid(row=3, column=1, padx=5)
        
        # Provisioning Profile Details
        profile_frame = ttk.LabelFrame(main_frame, text="Provisioning Profile Details", padding="5")
        profile_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(profile_frame, text="App ID:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.app_id = tk.StringVar(value="com.example.app")
        ttk.Entry(profile_frame, textvariable=self.app_id, width=40).grid(row=0, column=1, padx=5)
        
        ttk.Label(profile_frame, text="Team ID:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.team_id = tk.StringVar()
        ttk.Entry(profile_frame, textvariable=self.team_id, width=40).grid(row=1, column=1, padx=5)
        
        # Device UDIDs
        ttk.Label(profile_frame, text="Device UDIDs:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.udids = tk.Text(profile_frame, height=5, width=40)
        self.udids.grid(row=2, column=1, padx=5, pady=2)
        ttk.Label(profile_frame, text="(One per line)").grid(row=3, column=1, sticky=tk.W)
        
        # Entitlements
        ttk.Label(profile_frame, text="Entitlements:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.entitlements = tk.Text(profile_frame, height=10, width=40)
        self.entitlements.grid(row=4, column=1, padx=5, pady=2)
        self.entitlements.insert('1.0', '''{
    "application-identifier": "TEAM_ID.APP_ID",
    "get-task-allow": true,
    "keychain-access-groups": ["TEAM_ID.*"],
    "com.apple.developer.team-identifier": "TEAM_ID"
}''')
        
        # Generate Button
        ttk.Button(main_frame, text="Generate Certificate & Profile", command=self.generate).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Log Frame
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = tk.Text(log_frame, height=10, width=70)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.update()
        
    def generate(self):
        try:
            # Validate inputs
            if not self.common_name.get():
                messagebox.showerror("Error", "Please enter a Common Name")
                return
                
            if not self.team_id.get():
                messagebox.showerror("Error", "Please enter a Team ID")
                return
                
            # Generate key pair
            self.log("Generating key pair...")
            private_key = self.generator.generate_key_pair()
            
            # Generate certificate
            self.log("Generating certificate...")
            certificate = self.generator.generate_certificate(
                private_key,
                self.common_name.get(),
                self.org_name.get(),
                int(self.valid_days.get())
            )
            
            # Export P12
            self.log("Exporting P12 certificate...")
            p12_path = self.generator.export_p12(
                private_key,
                certificate,
                "ios_developer",
                self.password.get()
            )
            
            # Get device UDIDs
            devices = [
                udid.strip()
                for udid in self.udids.get('1.0', tk.END).split('\n')
                if udid.strip()
            ]
            
            # Parse entitlements
            import json
            entitlements_str = self.entitlements.get('1.0', tk.END)
            entitlements_str = entitlements_str.replace('TEAM_ID', self.team_id.get())
            entitlements_str = entitlements_str.replace('APP_ID', self.app_id.get())
            entitlements = json.loads(entitlements_str)
            
            # Generate provisioning profile
            self.log("Generating provisioning profile...")
            profile_path = self.generator.generate_provisioning_profile(
                self.app_id.get(),
                self.team_id.get(),
                [certificate],
                devices,
                entitlements
            )
            
            self.log(f"\nSuccess! Files generated in {self.generator.output_dir}:")
            self.log(f"Certificate: {os.path.basename(p12_path)}")
            self.log(f"Profile: {os.path.basename(profile_path)}")
            
            messagebox.showinfo("Success", "Certificate and provisioning profile generated successfully!")
            
        except Exception as e:
            self.log(f"Error: {str(e)}")
            messagebox.showerror("Error", str(e))
            
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = CertificateGeneratorGUI()
    app.run()
