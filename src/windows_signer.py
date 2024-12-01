import os
import shutil
import zipfile
import tempfile
from pathlib import Path
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from .tools.macho.structures import MachO
from .tools.macho.codesign import CodeSignatureBuilder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WindowsIPASigner:
    def __init__(self, ipa_path, p12_path, password=None, prov_profile_path=None):
        self.ipa_path = ipa_path
        self.p12_path = p12_path
        self.password = password.encode() if password else b''
        self.prov_profile_path = prov_profile_path
        self.temp_dir = None
        self.app_path = None
        self.private_key = None
        self.certificate = None
        
    def load_certificate(self):
        """Load P12 certificate and private key"""
        logger.info("Loading certificate...")
        try:
            with open(self.p12_path, 'rb') as f:
                p12_data = f.read()
                
            # Try to load with password
            try:
                self.private_key, self.certificate, _ = pkcs12.load_key_and_certificates(
                    p12_data,
                    self.password
                )
            except ValueError:
                # If that fails, try without password
                try:
                    self.private_key, self.certificate, _ = pkcs12.load_key_and_certificates(
                        p12_data,
                        b''
                    )
                except ValueError as e:
                    raise ValueError(f"Invalid P12 certificate or password. Error: {str(e)}")
                    
            logger.info("Certificate loaded successfully")
            
        except FileNotFoundError:
            raise ValueError(f"P12 certificate file not found: {self.p12_path}")
        except Exception as e:
            raise ValueError(f"Failed to load certificate: {str(e)}")
        
    def extract_ipa(self):
        """Extract IPA to temporary directory"""
        self.temp_dir = tempfile.mkdtemp()
        logger.info(f"Extracting IPA to {self.temp_dir}")
        
        with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
            zip_ref.extractall(self.temp_dir)
            
        payload_path = os.path.join(self.temp_dir, 'Payload')
        app_name = next(f for f in os.listdir(payload_path) if f.endswith('.app'))
        self.app_path = os.path.join(payload_path, app_name)
        
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
            
    def sign_binary(self, binary_path):
        """Sign a Mach-O binary using Python implementation"""
        logger.info(f"Signing binary: {binary_path}")
        try:
            # First check if file exists and is readable
            if not os.path.exists(binary_path):
                raise ValueError(f"Binary file not found: {binary_path}")
                
            # Read the binary data
            try:
                with open(binary_path, 'rb') as f:
                    binary_data = f.read()
                    
                if len(binary_data) < 4:
                    raise ValueError(f"Binary file too small: {len(binary_data)} bytes")
                    
                logger.info(f"Read binary file: {len(binary_data)} bytes")
                
                # Check file magic
                magic = binary_data[:4]
                logger.info(f"Binary magic: {magic.hex()}")
                
                # Parse Mach-O and create signature
                try:
                    macho = MachO(binary_data)
                    logger.info(f"Successfully parsed Mach-O binary: {len(macho.segments)} segments")
                    
                    builder = CodeSignatureBuilder(binary_data)
                    new_signature = builder.build(
                        self.certificate.public_bytes(serialization.Encoding.DER),
                        self.private_key
                    )
                    logger.info(f"Generated signature: {len(new_signature)} bytes")
                    
                    # Replace signature
                    signed_binary = macho.replace_code_signature(new_signature)
                    logger.info(f"Created signed binary: {len(signed_binary)} bytes")
                    
                    # Write signed binary
                    with open(binary_path, 'wb') as f:
                        f.write(signed_binary)
                        
                    logger.info(f"Successfully signed {os.path.basename(binary_path)}")
                    
                except Exception as e:
                    logger.error(f"Error processing Mach-O binary: {str(e)}")
                    logger.error(f"Binary details: size={len(binary_data)}, magic={magic.hex()}")
                    raise ValueError(f"Failed to process Mach-O binary: {str(e)}")
                    
            except IOError as e:
                raise ValueError(f"Failed to read binary file: {str(e)}")
                
        except Exception as e:
            logger.error(f"Failed to sign {binary_path}: {str(e)}")
            raise
            
    def sign_frameworks(self):
        """Sign all frameworks and dylibs"""
        frameworks_path = os.path.join(self.app_path, 'Frameworks')
        if not os.path.exists(frameworks_path):
            logger.info("No Frameworks directory found")
            return
            
        logger.info("Signing frameworks...")
        for item in os.listdir(frameworks_path):
            item_path = os.path.join(frameworks_path, item)
            if item.endswith('.framework'):
                # For frameworks, we need to find the actual binary
                framework_binary = os.path.join(item_path, item.split('.')[0])
                if os.path.exists(framework_binary):
                    logger.info(f"Found framework binary: {framework_binary}")
                    self.sign_binary(framework_binary)
                else:
                    # Try to find binary in other common locations
                    versions_path = os.path.join(item_path, 'Versions', 'Current')
                    if os.path.exists(versions_path):
                        binary_name = item.split('.')[0]
                        possible_paths = [
                            os.path.join(versions_path, binary_name),
                            os.path.join(item_path, 'Versions', 'A', binary_name)
                        ]
                        for path in possible_paths:
                            if os.path.exists(path):
                                logger.info(f"Found framework binary at: {path}")
                                self.sign_binary(path)
                                break
                        else:
                            logger.warning(f"Could not find binary for framework: {item}")
            elif item.endswith('.dylib'):
                logger.info(f"Found dynamic library: {item_path}")
                self.sign_binary(item_path)
                
    def sign_app(self):
        """Sign the main application binary"""
        logger.info("Signing main application...")
        binary_name = os.path.splitext(os.path.basename(self.app_path))[0]
        binary_path = os.path.join(self.app_path, binary_name)
        
        if not os.path.exists(binary_path):
            # Try to find binary in common alternate locations
            possible_paths = [
                os.path.join(self.app_path, 'MacOS', binary_name),
                os.path.join(self.app_path, binary_name + '_')
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    binary_path = path
                    break
            else:
                raise ValueError(f"Could not find main application binary in {self.app_path}")
                
        logger.info(f"Found main binary at: {binary_path}")
        self.sign_binary(binary_path)
        
    def create_signed_ipa(self, output_path):
        """Create new IPA with signed contents"""
        logger.info("Creating signed IPA...")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.temp_dir)
                    zip_ref.write(file_path, arcname)
                    
        logger.info(f"Created signed IPA: {output_path}")
        
    def cleanup(self):
        """Remove temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def sign(self, output_path):
        """Main signing process"""
        try:
            self.load_certificate()
            self.extract_ipa()
            self.remove_old_signature()
            self.update_provisioning_profile()
            self.sign_frameworks()
            self.sign_app()
            self.create_signed_ipa(output_path)
            logger.info("Signing completed successfully")
        finally:
            self.cleanup()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Sign IPA on Windows')
    parser.add_argument('ipa_path', help='Path to input IPA')
    parser.add_argument('p12_path', help='Path to P12 certificate')
    parser.add_argument('--password', help='P12 certificate password')
    parser.add_argument('--profile', help='Path to provisioning profile')
    parser.add_argument('--output', help='Output IPA path')
    
    args = parser.parse_args()
    
    output_path = args.output or args.ipa_path.replace('.ipa', '_signed.ipa')
    
    signer = WindowsIPASigner(
        args.ipa_path,
        args.p12_path,
        args.password,
        args.profile
    )
    
    signer.sign(output_path)

if __name__ == '__main__':
    main()
