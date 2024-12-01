from typing import List, Tuple, Dict, Optional
import struct
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from .structures import CodeDirectory, BlobIndex, SuperBlob
from .constants import *

import logging
logger = logging.getLogger(__name__)

class CodeSignatureBuilder:
    def __init__(self, macho_data: bytes, private_key, certificate):
        self.macho_data = macho_data
        self.private_key = private_key
        self.certificate = certificate
        self.page_size = 4096  # Default page size
        
    def _calculate_code_hashes(self, code_limit: int) -> List[bytes]:
        """Calculate code hashes for each page of the binary."""
        hash_list = []
        
        # Calculate number of complete pages
        num_pages = (code_limit + self.page_size - 1) // self.page_size
        
        for i in range(num_pages):
            start = i * self.page_size
            end = min(start + self.page_size, code_limit)
            page_data = self.macho_data[start:end]
            
            # If this is the last page and it's not full, pad with zeros
            if len(page_data) < self.page_size:
                page_data = page_data + b'\0' * (self.page_size - len(page_data))
                
            # Create a new hash object for each page
            hasher = hashlib.sha256()
            hasher.update(page_data)
            hash_list.append(hasher.digest())
            
        return hash_list
        
    def _build_code_directory(self, identifier: str, code_limit: int, code_hashes: List[bytes]) -> bytes:
        """Build the Code Directory structure."""
        # Basic CodeDirectory fields
        cd_size = 44  # Base size up to platform field
        
        # Add identifier as null-terminated string
        identifier_bytes = identifier.encode('ascii', errors='ignore') + b'\0'
        identifier_offset = cd_size
        cd_size += len(identifier_bytes)
        
        # Align to 4 bytes
        cd_size = (cd_size + 3) & ~3
        
        # Add space for hash slots
        hash_size = 32  # SHA256
        hash_offset = cd_size
        cd_size += len(code_hashes) * hash_size
        
        # Build the CodeDirectory
        cd = bytearray()
        cd.extend(struct.pack('>I', CSMAGIC_CODEDIRECTORY))  # magic
        cd.extend(struct.pack('>I', cd_size))  # length
        cd.extend(struct.pack('>I', 0x20400))  # version
        cd.extend(struct.pack('>I', CS_ADHOC | CS_GET_TASK_ALLOW))  # flags
        cd.extend(struct.pack('>I', hash_offset))  # hashOffset
        cd.extend(struct.pack('>I', identifier_offset))  # identOffset
        cd.extend(struct.pack('>I', 0))  # nSpecialSlots
        cd.extend(struct.pack('>I', len(code_hashes)))  # nCodeSlots
        cd.extend(struct.pack('>I', code_limit))  # codeLimit
        cd.extend(struct.pack('>B', hash_size))  # hashSize
        cd.extend(struct.pack('>B', CS_HASHTYPE_SHA256))  # hashType
        cd.extend(struct.pack('>B', 0))  # platform
        cd.extend(struct.pack('>B', 12))  # pageSize (log2(page_size))
        cd.extend(struct.pack('>I', 0))  # spare2
        
        # Add identifier
        cd.extend(identifier_bytes)
        
        # Pad to alignment
        while len(cd) < hash_offset:
            cd.append(0)
            
        # Add code hashes
        for hash_value in code_hashes:
            cd.extend(hash_value)
            
        return bytes(cd)
        
    def _sign_code_directory(self, code_directory: bytes) -> bytes:
        """Create a CMS signature over the Code Directory."""
        # Hash the Code Directory
        cd_hash = hashes.Hash(hashes.SHA256())
        cd_hash.update(code_directory)
        cd_digest = cd_hash.finalize()
        
        # Sign the hash
        signature = self.private_key.sign(
            cd_digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # TODO: Create proper CMS structure
        # For now, just return the raw signature
        return signature
        
    def build(self) -> bytes:
        """Build the code signature data."""
        # Calculate code hashes
        code_limit = len(self.macho_data)
        code_hashes = self._calculate_code_hashes(code_limit)
        
        # Calculate base size and offsets
        base_size = 8  # SuperBlob header
        base_size += 8  # One BlobIndex
        
        # Create CodeDirectory
        identifier = "*"  # Default identifier
        cd = CodeDirectory(
            magic=CSMAGIC_CODEDIRECTORY,
            length=0,  # Will be calculated during to_bytes()
            version=0x20400,  # Latest version
            flags=CS_ADHOC | CS_GET_TASK_ALLOW,  # Enable debugging
            hashOffset=0,  # Will be calculated during to_bytes()
            identOffset=0,  # Will be calculated during to_bytes()
            nSpecialSlots=0,
            nCodeSlots=len(code_hashes),
            codeLimit=code_limit,
            hashSize=32,  # SHA256
            hashType=CS_HASHTYPE_SHA256,
            platform=0,  # Not platform specific
            pageSize=12,  # 4096 (2^12)
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
            identifier=identifier,
            hashes=code_hashes
        )
        
        # Convert CodeDirectory to bytes
        cd_data = cd.to_bytes()
        cd_offset = base_size
        
        # Create blob index for CodeDirectory
        cd_index = BlobIndex(
            type=CS_SLOTID_CODEDIRECTORY,
            offset=cd_offset
        )
        
        # Create SuperBlob
        sb = SuperBlob(
            magic=CSMAGIC_EMBEDDED_SIGNATURE,
            length=base_size + len(cd_data),
            count=1,
            blobs=[cd_index]
        )
        
        # Build the complete signature
        signature = bytearray()
        
        # Add SuperBlob header
        signature.extend(struct.pack('>I', sb.magic))
        signature.extend(struct.pack('>I', sb.length))
        signature.extend(struct.pack('>I', sb.count))
        
        # Add BlobIndex
        signature.extend(struct.pack('>II', cd_index.type, cd_index.offset))
        
        # Add CodeDirectory data
        signature.extend(cd_data)
        
        # Add code hashes
        for hash_value in code_hashes:
            signature.extend(hash_value)
        
        return bytes(signature)
        
    def verify(self, signature: bytes) -> bool:
        """Verify a code signature"""
        try:
            # Parse the superblob
            superblob = SuperBlob.from_bytes(signature)
            
            # Find the code directory
            cd_offset = None
            sig_offset = None
            for idx in superblob.index:
                if idx.type == CS_SLOTID_CODEDIRECTORY:
                    cd_offset = idx.offset
                elif idx.type == CS_SLOTID_SIGNATURE:
                    sig_offset = idx.offset
                    
            if cd_offset is None or sig_offset is None:
                return False
                
            # Get the code directory data
            cd_magic, cd_length = struct.unpack('>II', signature[cd_offset:cd_offset + 8])
            if cd_magic != CSMAGIC_CODEDIRECTORY:
                return False
            cd_data = signature[cd_offset:cd_offset + cd_length]
            
            # Get the signature blob
            sig_magic, sig_length = struct.unpack('>II', signature[sig_offset:sig_offset + 8])
            if sig_magic != CSMAGIC_BLOBWRAPPER:
                return False
            sig_data = signature[sig_offset + 8:sig_offset + sig_length]
            
            # Hash the code directory
            cd_hash = hashlib.sha256(cd_data).digest()
            
            # Verify the signature
            try:
                self.certificate.public_key().verify(
                    sig_data,
                    cd_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except:
                return False
                
        except:
            return False
