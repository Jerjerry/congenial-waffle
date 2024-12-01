import logging
import os
import sys
from pathlib import Path
import traceback

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

from tools.macho.structures import CodeDirectory
from tools.macho.codesign import CodeSignatureBuilder
from tools.macho.constants import *

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ipa_signer_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('ipa_signer_test')

def test_codedirectory():
    try:
        logger.info("Testing CodeDirectory initialization")
        
        # Test basic initialization
        cd = CodeDirectory(
            magic=0xfade0c02,  # CSMAGIC_CODEDIRECTORY
            length=1000,  # Test value
            version=0x20400,
            flags=0x00000002 | 0x00000004,  # CS_ADHOC | CS_GET_TASK_ALLOW
            hashOffset=100,  # Test value
            identOffset=44,
            nSpecialSlots=0,
            nCodeSlots=1,
            codeLimit=1000,
            hashSize=32,
            hashType=2,  # CS_HASHTYPE_SHA256
            platform=0,
            pageSize=12,
            spare2=0,
            scatterOffset=0,
            teamOffset=0,
            spare3=0,
            codeLimit64=0,
            execSegBase=0,
            execSegLimit=0,
            execSegFlags=0,
            runtime=0,
            preEncryptOffset=0,
            identifier="test",
            teamId=None,
            hashes=[b"x" * 32]
        )
        logger.info("Basic CodeDirectory initialization successful")
        logger.debug(f"CodeDirectory fields: {vars(cd)}")
        
        # Test serialization
        cd_bytes = cd.to_bytes()
        logger.info(f"CodeDirectory serialization successful, size: {len(cd_bytes)}")
        
        # Test create method
        cd2 = CodeDirectory.create(
            identifier="test",
            code_limit=1000,
            code_hashes=[b"x" * 32]
        )
        logger.info("CodeDirectory.create() successful")
        logger.debug(f"Created CodeDirectory fields: {vars(cd2)}")
        
    except Exception as e:
        logger.error("Error during CodeDirectory testing:")
        logger.error(traceback.format_exc())
        return False
    
    return True

if __name__ == "__main__":
    success = test_codedirectory()
    if success:
        print("Test completed successfully")
    else:
        print("Test failed - check logs for details")
