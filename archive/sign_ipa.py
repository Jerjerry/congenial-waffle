import os
import sys
import zipfile
import tempfile
import shutil
import logging
import argparse
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from tools.macho.structures import MachO
from tools.macho.codesign import CodeSignatureBuilder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_certificate(p12_path: str, password: Optional[str] = None) -> tuple:
    """Load certificate and private key from P12 file."""
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
    
    return private_key, certificate

def sign_binary(binary_path: str, certificate: bytes, private_key) -> None:
    """Sign a Mach-O binary."""
    try:
        logger.info(f"Reading binary: {binary_path}")
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
            
        logger.debug(f"Binary size: {len(binary_data)} bytes")
        
        try:
            logger.info("Parsing Mach-O binary...")
            macho = MachO(binary_data)
            logger.debug(f"Successfully parsed Mach-O binary with {len(macho.load_commands)} load commands")
        except ValueError as e:
            logger.error(f"Failed to parse Mach-O binary {binary_path}: {e}")
            raise ValueError(f"Invalid Mach-O binary {os.path.basename(binary_path)}: {e}")
            
        try:
            logger.info("Generating code signature...")
            builder = CodeSignatureBuilder(binary_data)
            new_signature = builder.build(certificate, private_key)
            logger.debug(f"Generated signature size: {len(new_signature)} bytes")
        except Exception as e:
            logger.error(f"Failed to generate code signature for {binary_path}: {e}")
            raise ValueError(f"Code signature generation failed for {os.path.basename(binary_path)}: {e}")
            
        try:
            logger.info("Replacing code signature...")
            signed_binary = macho.replace_code_signature(new_signature)
            logger.debug(f"Final binary size: {len(signed_binary)} bytes")
        except ValueError as e:
            logger.error(f"Failed to replace code signature in {binary_path}: {e}")
            raise ValueError(f"Code signature replacement failed for {os.path.basename(binary_path)}: {e}")
            
        logger.info("Writing signed binary...")
        with open(binary_path, 'wb') as f:
            f.write(signed_binary)
            
    except IOError as e:
        logger.error(f"IO error while signing {binary_path}: {e}")
        raise ValueError(f"Failed to read/write binary {os.path.basename(binary_path)}: {e}")

def sign_framework(framework_path: str, certificate: bytes, private_key) -> None:
    """Sign a framework directory."""
    framework_name = os.path.basename(framework_path).split('.')[0]
    binary_path = os.path.join(framework_path, framework_name)
    
    if os.path.exists(binary_path):
        try:
            sign_binary(binary_path, certificate, private_key)
        except ValueError as e:
            logger.warning(f"Failed to sign framework {framework_path}: {e}")
            raise
    else:
        logger.warning(f"Framework binary not found: {binary_path}")

def sign_ipa(ipa_path: str, p12_path: str, output_path: Optional[str] = None,
             password: Optional[str] = None) -> None:
    """Sign an IPA file."""
    if not output_path:
        output_path = ipa_path.replace('.ipa', '_signed.ipa')
        
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Extract IPA
            logger.info("Extracting IPA...")
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                
            # Load certificate
            logger.info("Loading certificate...")
            try:
                private_key, certificate = load_certificate(p12_path, password)
            except Exception as e:
                raise ValueError(f"Failed to load certificate: {e}")
                
            # Find app directory
            payload_dir = os.path.join(temp_dir, 'Payload')
            app_dir = None
            for item in os.listdir(payload_dir):
                if item.endswith('.app'):
                    app_dir = os.path.join(payload_dir, item)
                    break
                    
            if not app_dir:
                raise ValueError("No .app directory found in IPA")
                
            # Sign frameworks
            frameworks_dir = os.path.join(app_dir, 'Frameworks')
            if os.path.exists(frameworks_dir):
                logger.info("Signing frameworks...")
                for item in os.listdir(frameworks_dir):
                    if item.endswith('.framework'):
                        framework_path = os.path.join(frameworks_dir, item)
                        try:
                            sign_framework(framework_path, certificate, private_key)
                        except ValueError as e:
                            logger.warning(f"Failed to sign framework {item}: {e}")
                            # Continue with other frameworks
                    
            # Sign main binary
            logger.info("Signing main binary...")
            binary_name = os.path.splitext(os.path.basename(app_dir))[0]
            binary_path = os.path.join(app_dir, binary_name)
            sign_binary(binary_path, certificate, private_key)
            
            # Create new IPA
            logger.info("Creating signed IPA...")
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zip_ref.write(file_path, arcname)
                    
        except Exception as e:
            logger.error(f"Failed to sign IPA: {e}")
            raise
            
    logger.info(f"Signed IPA saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Sign iOS IPA file')
    parser.add_argument('ipa_path', help='Path to IPA file')
    parser.add_argument('p12_path', help='Path to P12 certificate file')
    parser.add_argument('--output', help='Output path for signed IPA')
    parser.add_argument('--password', help='P12 file password')
    
    args = parser.parse_args()
    
    try:
        sign_ipa(args.ipa_path, args.p12_path, args.output, args.password)
    except Exception as e:
        logger.error(f"Error signing IPA: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
