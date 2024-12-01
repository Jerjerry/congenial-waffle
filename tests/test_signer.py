import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
import logging
from src.enhanced_signer import EnhancedIPASigner, SigningProgress

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestIPASigner(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_files = {}
        
    def tearDown(self):
        """Clean up test environment"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
            
    def log_progress(self, progress: SigningProgress):
        """Log progress updates"""
        logger.info(f"\nOperation: {progress.current_operation}")
        if progress.warnings:
            logger.warning("Warnings:")
            for warning in progress.warnings:
                logger.warning(f"- {warning}")
        if progress.errors:
            logger.error("Errors:")
            for error in progress.errors:
                logger.error(f"- {error}")
                
    def verify_macho_binary(self, binary_path):
        """Verify a binary is a valid Mach-O file"""
        with open(binary_path, 'rb') as f:
            magic = f.read(4)
            # Check for Mach-O magic numbers
            valid_magic = [
                b'\xca\xfe\xba\xbe',  # Universal binary
                b'\xfe\xed\xfa\xce',  # x86_64
                b'\xfe\xed\xfa\xcf',  # ARM64
                b'\xce\xfa\xed\xfe'   # Reversed x86_64
            ]
            self.assertIn(magic, valid_magic, f"Invalid Mach-O magic: {magic.hex()}")
            
    def test_certificate_loading(self):
        """Test certificate loading and validation"""
        logger.info("\nTesting certificate loading...")
        
        # Test with invalid certificate
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(b'invalid cert data')
            invalid_cert = temp.name
            
        signer = EnhancedIPASigner(
            'dummy.ipa',
            invalid_cert,
            callback=self.log_progress
        )
        
        self.assertFalse(signer.validate_inputs())
        self.assertTrue(any('Invalid certificate' in err for err in signer.progress.errors))
        
        # Test with real certificate if available
        cert_path = os.getenv('TEST_P12_PATH')
        cert_pass = os.getenv('TEST_P12_PASS')
        
        if cert_path and os.path.exists(cert_path):
            signer = EnhancedIPASigner(
                'dummy.ipa',
                cert_path,
                cert_pass,
                callback=self.log_progress
            )
            try:
                signer.load_certificate()
                self.assertIsNotNone(signer.certificate)
                self.assertIsNotNone(signer.private_key)
            except Exception as e:
                self.fail(f"Failed to load valid certificate: {str(e)}")
                
    def test_ipa_extraction(self):
        """Test IPA extraction and validation"""
        logger.info("\nTesting IPA extraction...")
        
        # Create test IPA structure
        app_dir = os.path.join(self.test_dir, 'Payload', 'TestApp.app')
        os.makedirs(app_dir)
        
        # Create dummy binary
        with open(os.path.join(app_dir, 'TestApp'), 'wb') as f:
            # Write a minimal Mach-O header (ARM64)
            f.write(b'\xfe\xed\xfa\xcf' + b'\x00' * 100)
            
        # Create IPA
        ipa_path = os.path.join(self.test_dir, 'test.ipa')
        shutil.make_archive(ipa_path[:-4], 'zip', self.test_dir)
        os.rename(ipa_path[:-4] + '.zip', ipa_path)
        
        signer = EnhancedIPASigner(
            ipa_path,
            'dummy.p12',
            callback=self.log_progress
        )
        
        try:
            signer.extract_ipa()
            self.assertTrue(os.path.exists(signer.app_path))
            self.assertTrue(os.path.exists(os.path.join(signer.app_path, 'TestApp')))
        except Exception as e:
            self.fail(f"Failed to extract valid IPA: {str(e)}")
            
    def test_binary_signing(self):
        """Test binary signing process"""
        logger.info("\nTesting binary signing...")
        
        # We need a valid certificate for this test
        cert_path = os.getenv('TEST_P12_PATH')
        cert_pass = os.getenv('TEST_P12_PASS')
        
        if not cert_path or not os.path.exists(cert_path):
            logger.warning("Skipping binary signing test - no certificate available")
            return
            
        # Create test binary
        binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(binary_path, 'wb') as f:
            # Write a minimal Mach-O header (ARM64)
            f.write(b'\xfe\xed\xfa\xcf' + b'\x00' * 100)
            
        signer = EnhancedIPASigner(
            'dummy.ipa',
            cert_path,
            cert_pass,
            callback=self.log_progress
        )
        
        try:
            # Load certificate first
            signer.load_certificate()
            
            # Try to sign binary
            signer.sign_binary(binary_path)
            
            # Verify the binary is still valid Mach-O
            self.verify_macho_binary(binary_path)
            
        except Exception as e:
            self.fail(f"Binary signing failed: {str(e)}")
            
    def test_full_signing_process(self):
        """Test complete signing process"""
        logger.info("\nTesting full signing process...")
        
        # We need a valid certificate and IPA for this test
        cert_path = os.getenv('TEST_P12_PATH')
        cert_pass = os.getenv('TEST_P12_PASS')
        test_ipa = os.getenv('TEST_IPA_PATH')
        
        if not all([cert_path, os.path.exists(cert_path), 
                   test_ipa, os.path.exists(test_ipa)]):
            logger.warning("Skipping full signing test - missing certificate or IPA")
            return
            
        output_path = os.path.join(self.test_dir, 'signed.ipa')
        
        signer = EnhancedIPASigner(
            test_ipa,
            cert_path,
            cert_pass,
            callback=self.log_progress
        )
        
        success = signer.sign(output_path)
        
        self.assertTrue(success, "Signing process failed")
        self.assertTrue(os.path.exists(output_path), "Output IPA not created")
        self.assertGreater(os.path.getsize(output_path), 0, "Output IPA is empty")
        
        # Verify signed IPA structure
        temp_extract = tempfile.mkdtemp()
        try:
            import zipfile
            with zipfile.ZipFile(output_path, 'r') as zip_ref:
                zip_ref.extractall(temp_extract)
                
            payload_dir = os.path.join(temp_extract, 'Payload')
            self.assertTrue(os.path.exists(payload_dir), "No Payload directory in signed IPA")
            
            app_dir = next(Path(payload_dir).glob('*.app'), None)
            self.assertIsNotNone(app_dir, "No .app directory in signed IPA")
            
            # Verify main binary
            app_binary = next(app_dir.glob(app_dir.stem), None)
            if app_binary:
                self.verify_macho_binary(str(app_binary))
                
            # Verify frameworks if any
            frameworks_dir = app_dir / 'Frameworks'
            if frameworks_dir.exists():
                for framework in frameworks_dir.glob('*.framework'):
                    binary = framework / framework.stem
                    if binary.exists():
                        self.verify_macho_binary(str(binary))
                        
        finally:
            shutil.rmtree(temp_extract)

def main():
    # Set up test environment variables if files are available
    test_files = {
        'TEST_P12_PATH': 'path/to/test.p12',
        'TEST_P12_PASS': 'certificate_password',
        'TEST_IPA_PATH': 'path/to/test.ipa'
    }
    
    for key, value in test_files.items():
        if os.path.exists(value):
            os.environ[key] = value
            
    # Run tests
    unittest.main()
