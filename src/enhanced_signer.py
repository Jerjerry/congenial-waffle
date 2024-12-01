import os
import shutil
import zipfile
import tempfile
from pathlib import Path
import logging
import hashlib
from typing import Optional, List, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from .tools.macho.structures import MachO
from .tools.macho.codesign import CodeSignatureBuilder
from .tools.cert_validator import CertificateValidator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SigningError(Exception):
    """Base class for signing errors"""
    pass

class CertificateError(SigningError):
    """Certificate related errors"""
    pass

class BinaryError(SigningError):
    """Binary processing errors"""
    pass

class IPAError(SigningError):
    """IPA processing errors"""
    pass

class SigningProgress:
    """Track signing progress and status"""
    def __init__(self):
        self.total_steps = 0
        self.current_step = 0
        self.current_operation = ""
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.signed_binaries: List[str] = []
        
    def update(self, operation: str):
        self.current_step += 1
        self.current_operation = operation
        logger.info(f"[{self.current_step}/{self.total_steps}] {operation}")
        
    def add_error(self, error: str):
        self.errors.append(error)
        logger.error(error)
        
    def add_warning(self, warning: str):
        self.warnings.append(warning)
        logger.warning(warning)
        
    def add_signed_binary(self, binary: str):
        self.signed_binaries.append(binary)

class EnhancedIPASigner:
    def __init__(self, ipa_path: str, p12_path: str, password: Optional[str] = None, 
                 prov_profile_path: Optional[str] = None, callback=None):
        self.ipa_path = ipa_path
        self.p12_path = p12_path
        self.password = password.encode() if password else b''
        self.prov_profile_path = prov_profile_path
        self.temp_dir = None
        self.app_path = None
        self.private_key = None
        self.certificate = None
        self.callback = callback
        self.progress = SigningProgress()
        self.binary_cache: Dict[str, bytes] = {}
        
    def validate_inputs(self) -> bool:
        """Validate all input files and certificates"""
        try:
            # Check IPA
            if not os.path.exists(self.ipa_path):
                raise IPAError(f"IPA file not found: {self.ipa_path}")
                
            if not zipfile.is_zipfile(self.ipa_path):
                raise IPAError(f"Invalid IPA file: {self.ipa_path}")
                
            # Validate certificate
            validator = CertificateValidator()
            valid, details = validator.validate_p12(self.p12_path, self.password)
            if not valid:
                raise CertificateError(f"Invalid certificate: {details}")
                
            # Validate provisioning profile if provided
            if self.prov_profile_path:
                valid, details = validator.validate_provisioning_profile(self.prov_profile_path)
                if not valid:
                    raise SigningError(f"Invalid provisioning profile: {details}")
                    
                # Check compatibility
                valid, details = validator.check_cert_profile_compatibility(
                    self.p12_path,
                    self.prov_profile_path,
                    self.password
                )
                if not valid:
                    raise SigningError(f"Certificate and profile not compatible: {details}")
                    
            return True
            
        except Exception as e:
            self.progress.add_error(str(e))
            return False
            
    def load_certificate(self):
        """Load P12 certificate and private key"""
        self.progress.update("Loading certificate")
        try:
            with open(self.p12_path, 'rb') as f:
                p12_data = f.read()
                
            try:
                self.private_key, self.certificate, _ = pkcs12.load_key_and_certificates(
                    p12_data,
                    self.password
                )
            except ValueError as e:
                raise CertificateError(f"Invalid P12 certificate or password: {str(e)}")
                
        except FileNotFoundError:
            raise CertificateError(f"P12 certificate file not found: {self.p12_path}")
        except Exception as e:
            raise CertificateError(f"Failed to load certificate: {str(e)}")
            
    def extract_ipa(self):
        """Extract IPA to temporary directory"""
        self.progress.update("Extracting IPA")
        self.temp_dir = tempfile.mkdtemp()
        
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
                
            payload_path = os.path.join(self.temp_dir, 'Payload')
            if not os.path.exists(payload_path):
                raise IPAError("Invalid IPA: No Payload directory found")
                
            apps = [f for f in os.listdir(payload_path) if f.endswith('.app')]
            if not apps:
                raise IPAError("Invalid IPA: No .app bundle found")
                
            self.app_path = os.path.join(payload_path, apps[0])
            
        except Exception as e:
            raise IPAError(f"Failed to extract IPA: {str(e)}")
            
    def remove_old_signature(self):
        """Remove existing code signature"""
        self.progress.update("Removing old signatures")
        
        code_sign_dir = os.path.join(self.app_path, '_CodeSignature')
        if os.path.exists(code_sign_dir):
            shutil.rmtree(code_sign_dir)
            
        embedded_prov = os.path.join(self.app_path, 'embedded.mobileprovision')
        if os.path.exists(embedded_prov):
            os.remove(embedded_prov)
            
    def update_provisioning_profile(self):
        """Copy new provisioning profile"""
        if self.prov_profile_path:
            self.progress.update("Updating provisioning profile")
            try:
                shutil.copy2(
                    self.prov_profile_path,
                    os.path.join(self.app_path, 'embedded.mobileprovision')
                )
            except Exception as e:
                raise SigningError(f"Failed to update provisioning profile: {str(e)}")
                
    def sign_binary(self, binary_path: str):
        """Sign a Mach-O binary using Python implementation"""
        try:
            if not os.path.exists(binary_path):
                raise BinaryError(f"Binary file not found: {binary_path}")
                
            # Check if we've already processed this file (by content hash)
            with open(binary_path, 'rb') as f:
                content = f.read()
                content_hash = hashlib.sha256(content).hexdigest()
                
            if content_hash in self.binary_cache:
                # We've already signed an identical binary, use cached version
                with open(binary_path, 'wb') as f:
                    f.write(self.binary_cache[content_hash])
                self.progress.add_signed_binary(binary_path)
                return
                
            if len(content) < 4:
                raise BinaryError(f"Binary file too small: {len(content)} bytes")
                
            # Parse Mach-O and create signature
            try:
                macho = MachO(content)
                builder = CodeSignatureBuilder(content)
                new_signature = builder.build(
                    self.certificate.public_bytes(serialization.Encoding.DER),
                    self.private_key
                )
                
                # Replace signature
                signed_binary = macho.replace_code_signature(new_signature)
                
                # Cache the signed binary
                self.binary_cache[content_hash] = signed_binary
                
                # Write signed binary
                with open(binary_path, 'wb') as f:
                    f.write(signed_binary)
                    
                self.progress.add_signed_binary(binary_path)
                
            except Exception as e:
                raise BinaryError(f"Failed to process Mach-O binary: {str(e)}")
                
        except Exception as e:
            self.progress.add_error(f"Failed to sign {binary_path}: {str(e)}")
            raise
            
    def _sign_frameworks(self, app_path: str):
        """Sign frameworks in the app bundle."""
        frameworks_path = os.path.join(app_path, "Frameworks")
        if not os.path.exists(frameworks_path):
            self.progress.add_warning("No Frameworks directory found")
            return
            
        signed_count = 0
        for fw_name in os.listdir(frameworks_path):
            fw_path = os.path.join(frameworks_path, fw_name)
            if not os.path.isdir(fw_path) and not fw_name.endswith('.dylib'):
                continue
                
            # Special cases to skip
            if fw_name in ["CydiaSubstrate.framework", "Spotilife.dylib"]:
                self.progress.update(f"Skipping {fw_name} - special case")
                continue
                
            # Get the actual binary path
            if fw_name.endswith('.framework'):
                binary_path = os.path.join(fw_path, os.path.splitext(fw_name)[0])
            else:
                binary_path = fw_path
                
            if not os.path.exists(binary_path):
                self.progress.add_warning(f"No binary found in framework: {fw_name}")
                continue
                
            try:
                self.sign_binary(binary_path)
                signed_count += 1
            except Exception as e:
                self.progress.add_error(f"Failed to sign {binary_path}: {str(e)}")
                raise
                
        self.progress.update(f"Signed binaries: {signed_count}")
        
    def sign_frameworks(self):
        self._sign_frameworks(self.app_path)
        
    def sign_app(self):
        """Sign the main application binary"""
        self.progress.update("Signing main application")
        binary_name = os.path.splitext(os.path.basename(self.app_path))[0]
        binary_path = os.path.join(self.app_path, binary_name)
        
        if not os.path.exists(binary_path):
            possible_paths = [
                os.path.join(self.app_path, 'MacOS', binary_name),
                os.path.join(self.app_path, binary_name + '_')
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    binary_path = path
                    break
            else:
                raise SigningError(f"Could not find main application binary in {self.app_path}")
                
        self.sign_binary(binary_path)
        
    def create_signed_ipa(self, output_path: str):
        """Create new IPA with signed contents"""
        self.progress.update("Creating signed IPA")
        
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.temp_dir)
                        zip_ref.write(file_path, arcname)
                        
        except Exception as e:
            raise SigningError(f"Failed to create signed IPA: {str(e)}")
            
    def cleanup(self):
        """Remove temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def sign(self, output_path: str) -> bool:
        """Main signing process"""
        try:
            # Set up progress tracking
            self.progress.total_steps = 7
            self.progress.current_step = 0
            
            # Validate everything first
            if not self.validate_inputs():
                return False
                
            # Perform signing steps
            self.load_certificate()
            self.extract_ipa()
            self.remove_old_signature()
            self.update_provisioning_profile()
            self.sign_frameworks()
            self.sign_app()
            self.create_signed_ipa(output_path)
            
            # Report success
            self.progress.update("Signing completed successfully")
            return len(self.progress.errors) == 0
            
        except Exception as e:
            self.progress.add_error(f"Signing failed: {str(e)}")
            return False
            
        finally:
            self.cleanup()
            if self.callback:
                self.callback(self.progress)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced IPA Signer for Windows')
    parser.add_argument('ipa_path', help='Path to input IPA')
    parser.add_argument('p12_path', help='Path to P12 certificate')
    parser.add_argument('--password', help='P12 certificate password')
    parser.add_argument('--profile', help='Path to provisioning profile')
    parser.add_argument('--output', help='Output IPA path')
    
    args = parser.parse_args()
    
    # Use input filename if no output specified
    if not args.output:
        input_name = os.path.splitext(args.ipa_path)[0]
        args.output = f"{input_name}_signed.ipa"
        
    def progress_callback(progress: SigningProgress):
        if progress.warnings:
            print("\nWarnings:")
            for warning in progress.warnings:
                print(f"- {warning}")
                
        if progress.errors:
            print("\nErrors:")
            for error in progress.errors:
                print(f"- {error}")
                
        print(f"\nSigned {len(progress.signed_binaries)} binaries")
        
    signer = EnhancedIPASigner(
        args.ipa_path,
        args.p12_path,
        args.password,
        args.profile,
        progress_callback
    )
    
    success = signer.sign(args.output)
    import sys
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
