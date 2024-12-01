import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from profile_editor import ProvisioningProfileEditor
import logging

class ProfileEditorGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("iOS Profile Editor")
        self.window.geometry("800x600")
        
        self.editor = ProvisioningProfileEditor()
        
        # Create main frame
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Profile Frame
        profile_frame = ttk.LabelFrame(main_frame, text="Provisioning Profile", padding="5")
        profile_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(profile_frame, text="Profile:").grid(row=0, column=0, sticky=tk.W)
        self.profile_path = tk.StringVar()
        ttk.Entry(profile_frame, textvariable=self.profile_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(profile_frame, text="Browse", command=self.browse_profile).grid(row=0, column=2)
        
        # UDID Frame
        udid_frame = ttk.LabelFrame(main_frame, text="Add UDID", padding="5")
        udid_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(udid_frame, text="UDID:").grid(row=0, column=0, sticky=tk.W)
        self.udid = tk.StringVar()
        ttk.Entry(udid_frame, textvariable=self.udid, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(udid_frame, text="Add UDID", command=self.add_udid).grid(row=0, column=2)
        
        # Entitlements Frame
        entitlements_frame = ttk.LabelFrame(main_frame, text="Entitlements", padding="5")
        entitlements_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.entitlements_text = tk.Text(entitlements_frame, height=10, width=70)
        self.entitlements_text.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
        ttk.Button(entitlements_frame, text="Update Entitlements", command=self.update_entitlements).grid(row=1, column=0, columnspan=2)
        
        # Results Frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="5")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.results_text = tk.Text(results_frame, height=10, width=70)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        # Set default entitlements
        default_entitlements = {
            "inter-app-audio": True,
            "com.apple.developer.networking.networkextension": [
                "app-proxy-provider",
                "content-filter-provider",
                "packet-tunnel-provider",
                "dns-proxy",
                "dns-settings",
                "relay"
            ],
            "application-identifier": "J4FUC525X9.anardoni.export.*",
            "keychain-access-groups": [
                "J4FUC525X9.*",
                "com.apple.token"
            ],
            "get-task-allow": False,
            "com.apple.developer.team-identifier": "J4FUC525X9"
        }
        self.entitlements_text.insert(tk.END, json.dumps(default_entitlements, indent=2))
        
    def browse_profile(self):
        filename = filedialog.askopenfilename(
            title="Select Provisioning Profile",
            filetypes=[("Provisioning Profile", "*.mobileprovision")]
        )
        if filename:
            self.profile_path.set(filename)
            
    def log_result(self, title, success, details):
        self.results_text.insert(tk.END, f"\n{'-'*20} {title} {'-'*20}\n")
        self.results_text.insert(tk.END, f"Status: {'✓ Success' if success else '✗ Failed'}\n")
        
        if isinstance(details, dict):
            self.results_text.insert(tk.END, json.dumps(details, indent=2, default=str))
        else:
            self.results_text.insert(tk.END, str(details))
            
        self.results_text.insert(tk.END, "\n")
        self.results_text.see(tk.END)
        
    def add_udid(self):
        if not self.profile_path.get():
            messagebox.showerror("Error", "Please select a provisioning profile")
            return
            
        if not self.udid.get():
            messagebox.showerror("Error", "Please enter a UDID")
            return
            
        success, output_path, details = self.editor.add_udid(
            self.profile_path.get(),
            self.udid.get()
        )
        
        if success:
            messagebox.showinfo("Success", f"Modified profile saved to:\n{output_path}")
            
        self.log_result("Add UDID", success, details)
        
    def update_entitlements(self):
        if not self.profile_path.get():
            messagebox.showerror("Error", "Please select a provisioning profile")
            return
            
        try:
            entitlements = json.loads(self.entitlements_text.get("1.0", tk.END))
        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid entitlements JSON")
            return
            
        success, output_path, details = self.editor.update_entitlements(
            self.profile_path.get(),
            entitlements
        )
        
        if success:
            messagebox.showinfo("Success", f"Modified profile saved to:\n{output_path}")
            
        self.log_result("Update Entitlements", success, details)
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = ProfileEditorGUI()
    app.run()
