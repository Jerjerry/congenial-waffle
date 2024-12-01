import os
import sys
import logging
from pathlib import Path
from src.enhanced_signer import EnhancedIPASigner

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_real_signing():
    """Test signing with real certificate and provisioning profile"""
    
    # Known working certificate and profile
    cert_path = r"C:\Users\Admin\Downloads\00008110-000650C82651801E.p12"
    profile_path = r"C:\Users\Admin\Downloads\00008110-000650C82651801E.mobileprovision"
    
    if not os.path.exists(cert_path):
        logger.error(f"Certificate not found: {cert_path}")
        return False
    if not os.path.exists(profile_path):
        logger.error(f"Provisioning profile not found: {profile_path}")
        return False
        
    def log_progress(progress):
        logger.info(f"\nOperation: {progress.current_operation}")
        if progress.warnings:
            logger.warning("Warnings:")
            for warning in progress.warnings:
                logger.warning(f"- {warning}")
        if progress.errors:
            logger.error("Errors:")
            for error in progress.errors:
                logger.error(f"- {error}")
        if progress.signed_binaries:
            logger.info(f"Signed binaries: {len(progress.signed_binaries)}")
            for binary in progress.signed_binaries:
                logger.debug(f"- {binary}")
    
    # Test with your IPA if provided
    ipa_path = input("Enter path to test IPA file: ").strip('"')
    if not os.path.exists(ipa_path):
        logger.error(f"IPA file not found: {ipa_path}")
        return False
        
    output_path = str(Path(ipa_path).parent / f"{Path(ipa_path).stem}_signed.ipa")
    
    logger.info("\nStarting signing test with:")
    logger.info(f"IPA: {ipa_path}")
    logger.info(f"Certificate: {cert_path}")
    logger.info(f"Profile: {profile_path}")
    logger.info(f"Output: {output_path}")
    
    try:
        signer = EnhancedIPASigner(
            ipa_path,
            cert_path,
            None,  # No password needed for this certificate
            profile_path,
            log_progress
        )
        
        success = signer.sign(output_path)
        
        if success:
            logger.info(f"\nSuccessfully signed IPA: {output_path}")
            logger.info(f"Output file size: {os.path.getsize(output_path):,} bytes")
            return True
        else:
            logger.error("Signing failed!")
            return False
            
    except Exception as e:
        logger.error(f"Error during signing: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    print("iOS IPA Signer Test")
    print("-" * 50)
    success = test_real_signing()
    sys.exit(0 if success else 1)
