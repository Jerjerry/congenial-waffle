import os
import sys
import shutil
import zipfile
import plistlib
import tempfile
import subprocess
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IPAResigner:
    def __init__(self, ipa_path, cert_name, prov_profile_path=None, entitlements_path=None):
        self.ipa_path = ipa_path
        self.cert_name = cert_name  # Certificate name from Keychain
        self.prov_profile_path = prov_profile_path
        self.entitlements_path = entitlements_path
        self.temp_dir = None
        self.app_path = None
        self.payload_path = None
        
    def extract_ipa(self):
        """Extract IPA to temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        logger.info(f"Extracting IPA to {self.temp_dir}")
        
        with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
            zip_ref.extractall(self.temp_dir)
            
        self.payload_path = os.path.join(self.temp_dir, 'Payload')
        app_name = next(f for f in os.listdir(self.payload_path) if f.endswith('.app'))
        self.app_path = os.path.join(self.payload_path, app_name)
        
        logger.info(f"Extracted app: {self.app_path}")
        
    def remove_old_signature(self):
        """Remove existing code signature"""
        logger.info("Removing old signature...")
        
        # Remove _CodeSignature directory
        code_sign_dir = os.path.join(self.app_path, '_CodeSignature')
        if os.path.exists(code_sign_dir):
            shutil.rmtree(code_sign_dir)
            
        # Remove embedded provisioning profile
        embedded_prov = os.path.join(self.app_path, 'embedded.mobileprovision')
        if os.path.exists(embedded_prov):
            os.remove(embedded_prov)
            
    def update_provisioning_profile(self):
        """Copy new provisioning profile"""
        if self.prov_profile_path:
            logger.info("Updating provisioning profile...")
            shutil.copy2(
                self.prov_profile_path,
                os.path.join(self.app_path, 'embedded.mobileprovision')
            )
            
    def sign_frameworks(self):
        """Sign all frameworks and dylibs"""
        frameworks_path = os.path.join(self.app_path, 'Frameworks')
        if not os.path.exists(frameworks_path):
            return
            
        logger.info("Signing frameworks...")
        for item in os.listdir(frameworks_path):
            item_path = os.path.join(frameworks_path, item)
            if item.endswith('.framework') or item.endswith('.dylib'):
                self._sign_binary(item_path)
                
    def _sign_binary(self, binary_path, extra_args=None):
        """Sign a binary with codesign"""
        cmd = ['codesign', '-f', '-s', self.cert_name]
        
        if extra_args:
            cmd.extend(extra_args)
            
        cmd.append(binary_path)
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Signing failed for {binary_path}: {e.stderr.decode()}")
            raise
            
    def sign_app(self):
        """Sign the main application"""
        logger.info("Signing main application...")
        
        cmd = ['codesign', '-f', '-s', self.cert_name]
        
        # Add entitlements if provided
        if self.entitlements_path:
            cmd.extend(['--entitlements', self.entitlements_path])
            
        cmd.append(self.app_path)
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"App signing failed: {e.stderr.decode()}")
            raise
            
    def create_signed_ipa(self, output_path):
        """Create new IPA with signed contents"""
        logger.info("Creating signed IPA...")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.temp_dir)
                    zip_ref.write(file_path, arcname)
                    
    def cleanup(self):
        """Remove temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def resign(self, output_path):
        """Main resigning process"""
        try:
            self.extract_ipa()
            self.remove_old_signature()
            self.update_provisioning_profile()
            self.sign_frameworks()
            self.sign_app()
            self.create_signed_ipa(output_path)
            logger.info(f"Successfully signed IPA: {output_path}")
        finally:
            self.cleanup()
            
def main():
    if len(sys.argv) < 3:
        print("Usage: resign_ipa.py input.ipa 'Developer Certificate Name' [provisioning_profile] [entitlements]")
        sys.exit(1)
        
    ipa_path = sys.argv[1]
    cert_name = sys.argv[2]
    prov_profile = sys.argv[3] if len(sys.argv) > 3 else None
    entitlements = sys.argv[4] if len(sys.argv) > 4 else None
    
    output_path = ipa_path.replace('.ipa', '_signed.ipa')
    
    resigner = IPAResigner(ipa_path, cert_name, prov_profile, entitlements)
    resigner.resign(output_path)

if __name__ == '__main__':
    main()
