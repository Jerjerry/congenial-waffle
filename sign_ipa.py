import logging
import os
import sys
from pathlib import Path
import traceback
import tempfile
import shutil
import zipfile
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

from tools.macho.codesign import CodeSignatureBuilder
from tools.macho.constants import *
from tools.macho.parser import MachOParser

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ipa_signer_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('ipa_signer')

def load_p12(p12_path: str, password: Optional[str] = None) -> Tuple[bytes, bytes]:
    """Load private key and certificate from P12 file."""
    try:
        logger.info(f"Loading P12 file: {p12_path}")
        with open(p12_path, 'rb') as f:
            p12_data = f.read()
            
        if password is None:
            password = b''
        elif isinstance(password, str):
            password = password.encode()
            
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_data,
            password
        )
        
        logger.info("Successfully loaded P12 certificate and private key")
        return private_key, certificate
        
    except Exception as e:
        logger.error(f"Failed to load P12 file: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def write_signature(binary_path: str, signature: bytes) -> bool:
    """Write code signature to binary."""
    try:
        logger.info(f"Writing signature to binary: {binary_path}")
        
        # Parse the binary
        parser = MachOParser(binary_path)
        
        # Find the __LINKEDIT segment
        linkedit_seg = None
        for segment in parser.segments:
            if segment.segname == "__LINKEDIT":
                linkedit_seg = segment
                break
                
        if not linkedit_seg:
            raise Exception("__LINKEDIT segment not found")
            
        # Calculate new segment size with signature
        new_size = linkedit_seg.filesize + len(signature)
        new_size = (new_size + 15) & ~15  # Align to 16 bytes
        
        # Read the entire file
        with open(binary_path, 'rb') as f:
            binary_data = bytearray(f.read())
            
        # Append signature at the end of __LINKEDIT
        signature_offset = linkedit_seg.fileoff + linkedit_seg.filesize
        binary_data[signature_offset:signature_offset] = signature
        
        # Update segment size
        size_offset = linkedit_seg.fileoff + 8  # Skip segname
        binary_data[size_offset:size_offset + 8] = new_size.to_bytes(8, byteorder='little')
        
        # Write back to file
        with open(binary_path, 'wb') as f:
            f.write(binary_data)
            
        logger.info("Successfully wrote signature to binary")
        return True
        
    except Exception as e:
        logger.error(f"Failed to write signature: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def sign_binary(binary_path: str, private_key, certificate) -> bool:
    try:
        logger.info(f"Signing binary: {binary_path}")
        
        # Read binary data
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
        
        # Create signature builder
        builder = CodeSignatureBuilder(binary_data, private_key, certificate)
        
        # Build signature
        signature = builder.build()
        logger.info(f"Built signature of size: {len(signature)} bytes")
        
        # Write signature to binary
        if not write_signature(binary_path, signature):
            raise Exception("Failed to write signature to binary")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to sign binary: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def create_signed_ipa(temp_dir: str, output_path: str) -> bool:
    """Create signed IPA from temp directory."""
    try:
        logger.info(f"Creating signed IPA: {output_path}")
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
                    
        logger.info("Successfully created signed IPA")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create signed IPA: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def sign_ipa(ipa_path: str, p12_path: str, output_path: Optional[str] = None) -> bool:
    try:
        logger.info(f"Starting IPA signing process")
        logger.info(f"IPA: {ipa_path}")
        logger.info(f"P12: {p12_path}")
        
        if output_path is None:
            output_path = ipa_path.replace('.ipa', '_signed.ipa')
            
        # Load P12 certificate and private key
        private_key, certificate = load_p12(p12_path)
        
        # Create temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract IPA
            logger.info("Extracting IPA...")
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find main app bundle
            payload_dir = os.path.join(temp_dir, 'Payload')
            app_bundles = [f for f in os.listdir(payload_dir) if f.endswith('.app')]
            if not app_bundles:
                raise Exception("No .app bundle found in IPA")
            
            app_bundle = os.path.join(payload_dir, app_bundles[0])
            logger.info(f"Found app bundle: {app_bundle}")
            
            # Find main binary (same name as .app without extension)
            binary_name = os.path.splitext(app_bundles[0])[0]
            binary_path = os.path.join(app_bundle, binary_name)
            
            if not os.path.exists(binary_path):
                raise Exception(f"Main binary not found: {binary_path}")
            
            logger.info(f"Found main binary: {binary_path}")
            
            # Sign the binary
            if not sign_binary(binary_path, private_key, certificate):
                raise Exception("Failed to sign main binary")
            
            # Create signed IPA
            if not create_signed_ipa(temp_dir, output_path):
                raise Exception("Failed to create signed IPA")
            
            logger.info(f"Successfully created signed IPA: {output_path}")
            return True
            
    except Exception as e:
        logger.error(f"Failed to sign IPA: {str(e)}")
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    ipa_path = "C:/Users/Admin/Downloads/SpotilifeC.v1.2.3_v8.6.42.ipa"
    p12_path = "C:/Users/Admin/Downloads/00008110-000650C82651801E.p12"
    output_path = "C:/Users/Admin/Downloads/SpotilifeC.v1.2.3_v8.6.42_signed.ipa"
    
    if sign_ipa(ipa_path, p12_path, output_path):
        print("IPA signing completed successfully")
        print(f"Signed IPA saved to: {output_path}")
    else:
        print("IPA signing failed - check logs for details")
