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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from typing import List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CodeDirectory:
    def __init__(self, identifier: str, hash_type: int = 2, platform: int = 0):
        self.magic = 0xfade0c02  # CS_MAGIC_CODEDIRECTORY
        self.version = 0x20400   # Current version
        self.flags = 0x0         # None
        self.hash_size = 32      # SHA256 = 32 bytes
        self.hash_type = hash_type  # SHA256 = 2
        self.platform = platform    # Platform identifier (0 = iOS)
        self.page_size = 12         # 4096 bytes per page (2^12)
        self.spare2 = 0
        self.scatter_offset = 0
        self.spare3 = 0
        self.code_limit_64 = 0
        self.exec_seg_base = 0
        self.exec_seg_limit = 0
        self.exec_seg_flags = 0
        self.runtime = 0
        self.pre_encrypt_offset = 0
        self.identifier = identifier.encode('utf-8')
        
        # Calculate offsets
        base_size = 44  # Size of fixed header fields
        self.ident_offset = base_size
        self.hash_offset = base_size + len(self.identifier) + 1
        self.length = self.hash_offset
        self.n_special_slots = 0
        self.n_code_slots = 0
        
    def build(self, code_slots: list, special_slots: list = None):
        if special_slots:
            self.n_special_slots = len(special_slots)
        self.n_code_slots = len(code_slots)
        
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
            0,  # Team ID offset (not used)
            self.spare3,
            self.code_limit_64 >> 32,
            self.exec_seg_base,
            self.exec_seg_limit,
            self.exec_seg_flags,
            self.runtime
        )
        
        # Build the full directory
        directory = bytearray(header)
        directory.extend(self.identifier)
        directory.extend(b'\x00')  # Null terminator
        
        if special_slots:
            for slot in special_slots:
                directory.extend(slot)
                
        for slot in code_slots:
            directory.extend(slot)
            
        return bytes(directory)

class CodeSignatureBuilder:
    def __init__(self, binary_data: bytes):
        self.binary_data = binary_data
        self.bundle_id = "com.development.app"
        
    def calculate_page_hashes(self, page_size: int = 4096) -> list:
        hashes = []
        total_pages = (len(self.binary_data) + page_size - 1) // page_size
        
        for i in range(total_pages):
            start = i * page_size
            end = min(start + page_size, len(self.binary_data))
            page_data = self.binary_data[start:end]
            if len(page_data) < page_size:
                # Pad last page if needed
                page_data = page_data + b'\x00' * (page_size - len(page_data))
            page_hash = hashlib.sha256(page_data).digest()
            hashes.append(page_hash)
            
        return hashes

    def build(self, certificate: bytes, private_key, entitlements: bytes = None) -> bytes:
        # Calculate code hashes
        code_hashes = self.calculate_page_hashes()
        
        # Create special slot hashes if we have entitlements
        special_slots = []
        if entitlements:
            info_hash = hashlib.sha256(b'').digest()  # Empty Info.plist hash
            special_slots.append(info_hash)
            requirements_hash = hashlib.sha256(b'').digest()  # Empty requirements
            special_slots.append(requirements_hash)
            entitlements_hash = hashlib.sha256(entitlements).digest()
            special_slots.append(entitlements_hash)
        
        # Create CodeDirectory
        code_directory = CodeDirectory(self.bundle_id)
        directory_data = code_directory.build(code_hashes, special_slots)
        
        # Create signature
        signature = sign_data(directory_data, certificate, private_key)
        
        # Build SuperBlob
        superblob = self.build_superblob(directory_data, signature, entitlements)
        return superblob
        
    def build_superblob(self, directory: bytes, signature: bytes, entitlements: bytes = None) -> bytes:
        # SuperBlob magic and header
        magic = 0xfade0cc0  # CS_MAGIC_EMBEDDED_SIGNATURE
        count = 2  # CodeDirectory and Signature
        if entitlements:
            count += 1
            
        # Calculate blob sizes and offsets
        header_size = 8
        index_size = 8 * count
        
        offset = header_size + index_size
        blobs = []
        indices = []
        
        # Add CodeDirectory
        cd_blob = directory
        indices.append((0xfade0c02, offset))  # CS_SLOT_CODEDIRECTORY
        blobs.append(cd_blob)
        offset += len(cd_blob)
        
        # Add signature
        sig_blob = signature
        indices.append((0xfade0c01, offset))  # CS_SLOT_SIGNATURE
        blobs.append(sig_blob)
        offset += len(sig_blob)
        
        # Add entitlements if present
        if entitlements:
            ent_blob = entitlements
            indices.append((0xfade7171, offset))  # CS_SLOT_ENTITLEMENTS
            blobs.append(ent_blob)
            offset += len(ent_blob)
            
        # Build the SuperBlob
        total_length = offset
        
        # Pack header
        result = struct.pack('>III', magic, total_length, count)
        
        # Pack indices
        for slot_type, blob_offset in sorted(indices):
            result += struct.pack('>II', slot_type, blob_offset)
            
        # Add blobs
        for blob in blobs:
            result += blob
            
        return result

def sign_data(data: bytes, certificate: bytes, private_key) -> bytes:
    # Create signature
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Create CMS signature
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Development")
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Development")
    ]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())
    
    # Sign the certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    
    # Pack as blob
    magic = 0xfade0b01  # CS_MAGIC_BLOBWRAPPER
    length = len(signature) + 8
    
    return struct.pack('>II', magic, length) + signature
