import struct
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from typing import List, Optional
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CodeDirectory:
    MAGIC = 0xfade0c02  # CS_MAGIC_CODEDIRECTORY
    VERSION = 0x20400    # Current version
    
    def __init__(self, binary_data: bytes, identifier: str = "com.development.app"):
        self.binary_data = binary_data
        self.identifier = identifier.encode('utf-8')
        self.team_id = b""  # Empty team ID for development
        
        # Fixed header fields
        self.magic = self.MAGIC
        self.version = self.VERSION
        self.flags = 0x0         # None
        self.hash_size = 32      # SHA256 = 32 bytes
        self.hash_type = 2       # SHA256 = 2
        self.platform = 0        # Platform identifier (0 = iOS)
        self.page_size = 12      # 4096 bytes per page (2^12)
        self.spare2 = 0
        self.scatter_offset = 0
        self.team_offset = 0     # No team ID
        self.spare3 = 0
        self.code_limit_64 = len(binary_data)
        self.exec_seg_base = 0
        self.exec_seg_limit = 0
        self.exec_seg_flags = 0
        self.runtime = 0
        self.pre_encrypt_offset = 0
        
        # Calculate offsets and sizes
        self.header_size = 44    # Size of fixed header fields
        self.ident_offset = self.header_size
        self.n_special_slots = 0
        self.n_code_slots = (len(binary_data) + 4095) // 4096  # Number of pages
        
        # Calculate hash offset
        self.hash_offset = self.ident_offset + len(self.identifier) + 1
        self.hash_offset = (self.hash_offset + 7) & ~7  # Align to 8 bytes
        
        # Calculate total length
        self.length = self.hash_offset + (self.n_code_slots * self.hash_size)
        
    def calculate_hashes(self) -> List[bytes]:
        """Calculate SHA256 hashes for each page of the binary."""
        hashes = []
        page_size = 4096
        
        for i in range(self.n_code_slots):
            start = i * page_size
            end = min(start + page_size, len(self.binary_data))
            page_data = self.binary_data[start:end]
            if len(page_data) < page_size:
                # Pad last page if needed
                page_data += b'\x00' * (page_size - len(page_data))
            page_hash = hashlib.sha256(page_data).digest()
            hashes.append(page_hash)
            
        return hashes
        
    def build(self) -> bytes:
        """Build the CodeDirectory blob."""
        # Pack the header
        header = struct.pack('>IIIIIIIIIIIIIIIIIIIIII',
            self.magic,
            self.length,
            self.version,
            self.flags,
            self.hash_offset,
            self.ident_offset,
            self.n_special_slots,
            self.n_code_slots,
            self.code_limit_64,
            self.hash_size,
            self.hash_type,
            self.platform,
            self.page_size,
            self.spare2,
            self.scatter_offset,
            self.team_offset,
            self.spare3,
            self.code_limit_64 >> 32,
            self.exec_seg_base,
            self.exec_seg_limit,
            self.exec_seg_flags,
            self.runtime
        )
        
        # Build the directory
        result = bytearray(header)
        
        # Add identifier
        result.extend(self.identifier)
        result.append(0)  # Null terminator
        
        # Align to 8 bytes
        while len(result) % 8 != 0:
            result.append(0)
            
        # Add code hashes
        for hash_value in self.calculate_hashes():
            result.extend(hash_value)
            
        return bytes(result)

class CodeSignatureBuilder:
    def __init__(self, binary_data: bytes):
        self.binary_data = binary_data
        
    def build(self, certificate: bytes, private_key) -> bytes:
        """Build code signature."""
        # Create CodeDirectory
        cd = CodeDirectory(self.binary_data)
        cd_data = cd.build()
        
        # Sign the CodeDirectory
        signature = private_key.sign(
            cd_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Create SuperBlob
        magic = 0xfade0cc0  # CS_MAGIC_EMBEDDED_SIGNATURE
        count = 2  # CodeDirectory and Signature blobs
        
        # Calculate blob offsets
        header_size = 8
        index_size = count * 8
        
        cd_offset = header_size + index_size
        sig_offset = cd_offset + len(cd_data)
        total_size = sig_offset + len(signature) + 8  # +8 for signature blob header
        
        # Pack SuperBlob header
        superblob = struct.pack('>III',
            magic,
            total_size,
            count
        )
        
        # Pack blob index
        superblob += struct.pack('>II', 0, cd_offset)      # CodeDirectory slot
        superblob += struct.pack('>II', 1, sig_offset)     # Signature slot
        
        # Add CodeDirectory
        superblob += cd_data
        
        # Add signature
        sig_magic = 0xfade0b01  # CS_MAGIC_BLOBWRAPPER
        superblob += struct.pack('>II', sig_magic, len(signature) + 8)
        superblob += signature
        
        return superblob
