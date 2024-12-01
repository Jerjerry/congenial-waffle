import os
import sys
import tempfile
import shutil
import zipfile
import plistlib
import logging
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from .macho.parser import MachOParser
from .macho.codesign import CodeSignatureBuilder
from .macho.dylib import DylibInjector

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('signer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class IPASigner:
    def __init__(self):
        self.temp_dir = None
        self.app_dir = None
        self.provision_file = None
        self.entitlements = {
            'application-identifier': '*',
            'get-task-allow': True,
            'keychain-access-groups': ['*'],
            'com.apple.developer.team-identifier': '*',
            'com.apple.security.application-groups': ['*'],
        }
        
    def load_p12(self, p12_path, password=None):
        """Load certificate and private key from .p12 file"""
        try:
            logger.info(f"Loading P12 file: {p12_path}")
            with open(p12_path, 'rb') as f:
                p12_data = f.read()
                
            if password:
                password = password.encode()
                
            # Load the PKCS12 certificate
            from cryptography.hazmat.primitives.serialization import pkcs12
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                p12_data, password
            )
            
            logger.info("Successfully loaded P12 certificate")
            return private_key, certificate
            
        except Exception as e:
            logger.error(f"Failed to load P12 file: {str(e)}")
            raise Exception(f"Failed to load P12 file: {str(e)}")
            
    def extract_ipa(self, ipa_path):
        """Extract IPA to temporary directory"""
        logger.info(f"Extracting IPA: {ipa_path}")
        self.temp_dir = tempfile.mkdtemp()
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
                
            # Find .app directory
            payload_dir = os.path.join(self.temp_dir, 'Payload')
            app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
            
            if not app_dirs:
                raise Exception("No .app directory found in IPA")
                
            self.app_dir = os.path.join(payload_dir, app_dirs[0])
            logger.info(f"Found app directory: {self.app_dir}")
            return self.app_dir
            
        except Exception as e:
            logger.error(f"Failed to extract IPA: {str(e)}")
            self.cleanup()
            raise Exception(f"Failed to extract IPA: {str(e)}")
            
    def update_info_plist(self, bundle_id=None, bundle_name=None):
        """Update Info.plist with new bundle ID and name"""
        try:
            info_plist_path = os.path.join(self.app_dir, 'Info.plist')
            logger.info(f"Updating Info.plist: {info_plist_path}")
            
            with open(info_plist_path, 'rb') as f:
                info_plist = plistlib.load(f)
                
            if bundle_id:
                logger.info(f"Setting bundle ID to: {bundle_id}")
                info_plist['CFBundleIdentifier'] = bundle_id
                
            if bundle_name:
                logger.info(f"Setting bundle name to: {bundle_name}")
                info_plist['CFBundleName'] = bundle_name
                info_plist['CFBundleDisplayName'] = bundle_name
                
            with open(info_plist_path, 'wb') as f:
                plistlib.dump(info_plist, f)
                
        except Exception as e:
            logger.error(f"Failed to update Info.plist: {str(e)}")
            raise Exception(f"Failed to update Info.plist: {str(e)}")
            
    def sign_binary(self, binary_path, private_key, certificate):
        """Sign a single binary file"""
        try:
            logger.info(f"Signing binary: {binary_path}")
            
            # Read the binary
            with open(binary_path, 'rb') as f:
                macho_data = f.read()
                
            # Parse the Mach-O binary
            parser = MachOParser(macho_data)
            
            # Build code signature
            builder = CodeSignatureBuilder(macho_data, private_key, certificate)
            signature = builder.build()
            
            # Write signed binary
            with open(binary_path, 'wb') as f:
                f.write(macho_data)
                f.write(signature)
                
            logger.info(f"Successfully signed binary: {binary_path}")
            
        except Exception as e:
            logger.error(f"Failed to sign binary: {str(e)}")
            raise Exception(f"Failed to sign binary: {str(e)}")
            
    def inject_dylib(self, binary_path, dylib_path, weak=False):
        """Inject dylib into binary"""
        try:
            logger.info(f"Injecting dylib {dylib_path} into {binary_path}")
            
            with open(binary_path, 'rb') as f:
                macho_data = f.read()
                
            injector = DylibInjector(macho_data)
            modified_data = injector.inject_dylib(dylib_path, weak)
            
            with open(binary_path, 'wb') as f:
                f.write(modified_data)
                
            logger.info("Successfully injected dylib")
            
        except Exception as e:
            logger.error(f"Failed to inject dylib: {str(e)}")
            raise Exception(f"Failed to inject dylib: {str(e)}")
            
    def create_signed_ipa(self, output_path):
        """Create signed IPA file"""
        try:
            logger.info(f"Creating signed IPA: {output_path}")
            
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.temp_dir)
                        zipf.write(file_path, arcname)
                        
            logger.info("Successfully created signed IPA")
            
        except Exception as e:
            logger.error(f"Failed to create signed IPA: {str(e)}")
            raise Exception(f"Failed to create signed IPA: {str(e)}")
            
    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            logger.info(f"Cleaning up temporary directory: {self.temp_dir}")
            shutil.rmtree(self.temp_dir)
            
    def sign(self, ipa_path, p12_path, output_path, password=None, bundle_id=None, 
            bundle_name=None, dylib_path=None, weak_dylib=False):
        """Main signing process"""
        try:
            logger.info("Starting signing process")
            # Load certificate and private key
            private_key, certificate = self.load_p12(p12_path, password)
            
            # Extract IPA
            self.extract_ipa(ipa_path)
            
            # Update Info.plist if needed
            if bundle_id or bundle_name:
                self.update_info_plist(bundle_id, bundle_name)
                
            # Find all binaries to sign
            binaries = []
            for root, _, files in os.walk(self.app_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Check if file is a Mach-O binary
                    try:
                        with open(file_path, 'rb') as f:
                            magic = f.read(4)
                            if magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                       b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
                                binaries.append(file_path)
                    except:
                        continue
                        
            logger.info(f"Found {len(binaries)} binaries to sign")
            
            # Inject dylib if provided
            if dylib_path:
                # Copy dylib to app bundle
                dylib_name = os.path.basename(dylib_path)
                target_dylib = os.path.join(self.app_dir, dylib_name)
                shutil.copy2(dylib_path, target_dylib)
                logger.info(f"Copied dylib to: {target_dylib}")
                
                # Inject into main executable
                info_plist_path = os.path.join(self.app_dir, 'Info.plist')
                with open(info_plist_path, 'rb') as f:
                    info_plist = plistlib.load(f)
                executable = info_plist.get('CFBundleExecutable')
                if executable:
                    main_binary = os.path.join(self.app_dir, executable)
                    self.inject_dylib(main_binary, f"@executable_path/{dylib_name}", weak_dylib)
                    binaries.append(target_dylib)
                    
            # Sign all binaries
            for binary in binaries:
                self.sign_binary(binary, private_key, certificate)
                
            # Create signed IPA
            self.create_signed_ipa(output_path)
            logger.info("Signing process completed successfully")
            
        except Exception as e:
            logger.error(f"Signing failed: {str(e)}")
            raise
            
        finally:
            self.cleanup()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: pysign.py input.ipa certificate.p12 output.ipa [options]")
        print("Options:")
        print("  -p, --password    Certificate password")
        print("  -b, --bundle-id   New bundle ID")
        print("  -n, --name        New bundle name")
        print("  -l, --dylib       Path to dylib to inject")
        print("  -w, --weak        Inject dylib as weak")
        sys.exit(1)
        
    ipa_path = sys.argv[1]
    p12_path = sys.argv[2]
    output_path = sys.argv[3]
    
    options = {
        'password': None,
        'bundle_id': None,
        'bundle_name': None,
        'dylib_path': None,
        'weak_dylib': False
    }
    
    i = 4
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ('-p', '--password'):
            options['password'] = sys.argv[i + 1]
            i += 2
        elif arg in ('-b', '--bundle-id'):
            options['bundle_id'] = sys.argv[i + 1]
            i += 2
        elif arg in ('-n', '--name'):
            options['bundle_name'] = sys.argv[i + 1]
            i += 2
        elif arg in ('-l', '--dylib'):
            options['dylib_path'] = sys.argv[i + 1]
            i += 2
        elif arg in ('-w', '--weak'):
            options['weak_dylib'] = True
            i += 1
        else:
            print(f"Unknown option: {arg}")
            sys.exit(1)
            
    signer = IPASigner()
    try:
        signer.sign(ipa_path, p12_path, output_path, **options)
        print(f"Successfully signed IPA: {output_path}")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
