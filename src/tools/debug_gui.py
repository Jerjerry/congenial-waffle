import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import logging
import traceback
from pathlib import Path
import threading
from pysign import IPASigner

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SimpleSignerGUI:
    def __init__(self):
        logging.info("Initializing GUI...")
        try:
            self.window = tk.Tk()
            logging.debug("Created main window")
            
            self.window.title("IPA Signer (Debug)")
            self.window.geometry("600x500")
            logging.debug("Set window properties")
            
            # Variables
            self.ipa_path = tk.StringVar()
            self.cert_path = tk.StringVar()
            self.bundle_id = tk.StringVar()
            self.status = tk.StringVar(value="Ready")
            logging.debug("Initialized variables")
            
            # Create GUI
            self.create_gui()
            logging.info("GUI created successfully")
            
        except Exception as e:
            logging.error(f"Error in initialization: {str(e)}")
            logging.error(traceback.format_exc())
            raise
        
    def create_gui(self):
        try:
            # Main frame
            main_frame = ttk.Frame(self.window, padding="10")
            main_frame.grid(row=0, column=0, sticky="nsew")
            logging.debug("Created main frame")
            
            # Configure grid
            self.window.columnconfigure(0, weight=1)
            self.window.rowconfigure(0, weight=1)
            main_frame.columnconfigure(1, weight=1)
            logging.debug("Configured grid")
            
            # IPA File Selection
            ttk.Label(main_frame, text="IPA File:").grid(row=0, column=0, sticky="w", pady=5)
            ttk.Entry(main_frame, textvariable=self.ipa_path, width=50).grid(row=0, column=1, sticky="ew", padx=5)
            ttk.Button(main_frame, text="Browse", command=self.browse_ipa).grid(row=0, column=2, pady=5)
            logging.debug("Added IPA file selection")
            
            # Certificate Selection
            ttk.Label(main_frame, text="Certificate:").grid(row=1, column=0, sticky="w", pady=5)
            ttk.Entry(main_frame, textvariable=self.cert_path, width=50).grid(row=1, column=1, sticky="ew", padx=5)
            ttk.Button(main_frame, text="Browse", command=self.browse_cert).grid(row=1, column=2, pady=5)
            logging.debug("Added certificate selection")
            
            # Bundle ID
            ttk.Label(main_frame, text="Bundle ID:").grid(row=2, column=0, sticky="w", pady=5)
            ttk.Entry(main_frame, textvariable=self.bundle_id, width=50).grid(row=2, column=1, columnspan=2, sticky="ew", pady=5)
            logging.debug("Added bundle ID field")
            
            # Sign Button
            ttk.Button(main_frame, text="Sign IPA", command=self.sign_ipa).grid(row=3, column=0, columnspan=3, pady=20)
            logging.debug("Added sign button")
            
            # Progress Bar
            self.progress = ttk.Progressbar(main_frame, length=400, mode='indeterminate')
            self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)
            logging.debug("Added progress bar")
            
            # Status Label
            ttk.Label(main_frame, textvariable=self.status).grid(row=5, column=0, columnspan=3, pady=5)
            logging.debug("Added status label")
            
        except Exception as e:
            logging.error(f"Error creating GUI: {str(e)}")
            logging.error(traceback.format_exc())
            raise
            
    def browse_ipa(self):
        try:
            logging.info("Browsing for IPA file...")
            filename = filedialog.askopenfilename(
                title="Select IPA File",
                filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")]
            )
            if filename:
                self.ipa_path.set(filename)
                logging.info(f"Selected IPA file: {filename}")
        except Exception as e:
            logging.error(f"Error in browse_ipa: {str(e)}")
            logging.error(traceback.format_exc())
            
    def browse_cert(self):
        try:
            logging.info("Browsing for certificate...")
            filename = filedialog.askopenfilename(
                title="Select Certificate",
                filetypes=[("P12 files", "*.p12"), ("All files", "*.*")]
            )
            if filename:
                self.cert_path.set(filename)
                logging.info(f"Selected certificate: {filename}")
        except Exception as e:
            logging.error(f"Error in browse_cert: {str(e)}")
            logging.error(traceback.format_exc())
            
    def sign_ipa(self):
        try:
            logging.info("Starting signing process...")
            
            if not self.ipa_path.get():
                logging.warning("No IPA file selected")
                messagebox.showerror("Error", "Please select an IPA file")
                return
                
            if not self.cert_path.get():
                logging.warning("No certificate selected")
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
                logging.info("Signing cancelled - no output path selected")
                return
                
            logging.info(f"Output path: {output_path}")
            
            # Disable UI during signing
            self.toggle_ui(False)
            self.progress.start()
            
            # Start signing in a separate thread
            thread = threading.Thread(target=lambda: self._sign_ipa_thread(output_path))
            thread.daemon = True
            thread.start()
            logging.info("Started signing thread")
            
        except Exception as e:
            logging.error(f"Error in sign_ipa: {str(e)}")
            logging.error(traceback.format_exc())
            
    def _sign_ipa_thread(self, output_path):
        try:
            logging.info("Signing thread started")
            self.status.set("Signing in progress...")
            
            # Create signer and sign
            signer = IPASigner()
            signer.sign(
                self.ipa_path.get(),
                self.cert_path.get(),
                output_path,
                bundle_id=self.bundle_id.get() or None
            )
            
            logging.info("Signing completed successfully")
            self.status.set("Success! Signed IPA saved as: " + output_path)
            messagebox.showinfo("Success", f"IPA signed successfully!\nOutput: {output_path}")
            
        except Exception as e:
            logging.error(f"Error in signing thread: {str(e)}")
            logging.error(traceback.format_exc())
            self.status.set("Error: " + str(e))
            messagebox.showerror("Error", f"Signing failed: {str(e)}")
            
        finally:
            # Re-enable UI
            self.window.after(0, lambda: self.toggle_ui(True))
            self.window.after(0, self.progress.stop)
            logging.info("Signing thread finished")
            
    def toggle_ui(self, enabled):
        try:
            logging.debug(f"Toggling UI {'enabled' if enabled else 'disabled'}")
            state = "normal" if enabled else "disabled"
            for child in self.window.winfo_children():
                for widget in child.winfo_children():
                    if isinstance(widget, (ttk.Button, ttk.Entry)):
                        widget.configure(state=state)
        except Exception as e:
            logging.error(f"Error toggling UI: {str(e)}")
            logging.error(traceback.format_exc())
            
    def run(self):
        try:
            logging.info("Starting main event loop")
            self.window.mainloop()
            logging.info("Main event loop ended")
        except Exception as e:
            logging.error(f"Error in main event loop: {str(e)}")
            logging.error(traceback.format_exc())

if __name__ == "__main__":
    try:
        logging.info("Starting application")
        app = SimpleSignerGUI()
        app.run()
        logging.info("Application ended normally")
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        logging.error(traceback.format_exc())
        messagebox.showerror("Fatal Error", f"Application failed to start: {str(e)}\nCheck debug.log for details.")
