import struct
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class MachHeader:
    magic: int
    cputype: int
    cpusubtype: int
    filetype: int
    ncmds: int
    sizeofcmds: int
    flags: int
    reserved: int = 0  # Only present in 64-bit headers

    @classmethod
    def from_bytes(cls, data: bytes, is_64: bool = True) -> 'MachHeader':
        if is_64:
            fields = struct.unpack('<IIIIIIII', data[:32])
            return cls(
                magic=fields[0],
                cputype=fields[1],
                cpusubtype=fields[2],
                filetype=fields[3],
                ncmds=fields[4],
                sizeofcmds=fields[5],
                flags=fields[6],
                reserved=fields[7]
            )
        else:
            fields = struct.unpack('<IIIIIII', data[:28])
            return cls(
                magic=fields[0],
                cputype=fields[1],
                cpusubtype=fields[2],
                filetype=fields[3],
                ncmds=fields[4],
                sizeofcmds=fields[5],
                flags=fields[6]
            )

@dataclass
class LoadCommand:
    cmd: int
    cmdsize: int
    data: bytes

@dataclass
class SegmentCommand64:
    """64-bit segment command."""
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    nsects: int
    flags: int
    sections: List['Section64']

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SegmentCommand64':
        """Create from binary data."""
        if len(data) < 72:  # Minimum size of segment_command_64
            raise ValueError("Data too small for segment_command_64")
            
        segname = data[8:24].decode('utf-8').rstrip('\0')
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack('<QQQQ4I', data[24:72])
        
        # Parse sections
        sections = []
        offset = 72
        for _ in range(nsects):
            if offset + 80 > len(data):  # Size of section_64
                break
            sections.append(Section64.from_bytes(data[offset:offset + 80]))
            offset += 80
        
        return cls(
            segname=segname,
            vmaddr=vmaddr,
            vmsize=vmsize,
            fileoff=fileoff,
            filesize=filesize,
            maxprot=maxprot,
            initprot=initprot,
            nsects=nsects,
            flags=flags,
            sections=sections
        )

@dataclass
class Section64:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int = 0
    align: int = 0
    reloff: int = 0
    nreloc: int = 0
    flags: int = 0
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Section64':
        sectname = data[:16].decode('utf-8').rstrip('\0')
        segname = data[16:32].decode('utf-8').rstrip('\0')
        addr, size = struct.unpack('<QQ', data[32:48])
        offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3 = struct.unpack('<IIIIIIII', data[48:80])
        
        return cls(
            sectname=sectname,
            segname=segname,
            addr=addr,
            size=size,
            offset=offset,
            align=align,
            reloff=reloff,
            nreloc=nreloc,
            flags=flags,
            reserved1=reserved1,
            reserved2=reserved2,
            reserved3=reserved3
        )

@dataclass
class BlobIndex:
    type: int
    offset: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BlobIndex':
        type_, offset = struct.unpack('>II', data[:8])
        return cls(type=type_, offset=offset)

@dataclass
class SuperBlob:
    magic: int
    length: int
    count: int
    blobs: List[BlobIndex]

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SuperBlob':
        if len(data) < 12:
            raise ValueError("SuperBlob data too short")
            
        magic, length, count = struct.unpack('>III', data[:12])
        blobs = []
        
        offset = 12
        for _ in range(count):
            if offset + 8 > len(data):
                break
            blob = BlobIndex.from_bytes(data[offset:offset + 8])
            blobs.append(blob)
            offset += 8
            
        return cls(magic=magic, length=length, count=count, blobs=blobs)

@dataclass
class CodeDirectory:
    """Code Directory structure for code signing."""
    magic: int
    length: int
    version: int
    flags: int
    hashOffset: int
    identOffset: int
    nSpecialSlots: int
    nCodeSlots: int
    codeLimit: int
    hashSize: int
    hashType: int
    platform: int
    pageSize: int
    spare2: int
    scatterOffset: int
    teamOffset: int
    spare3: int
    codeLimit64: int
    execSegBase: int
    execSegLimit: int
    execSegFlags: int
    runtime: int
    preEncryptOffset: int
    identifier: str
    teamId: Optional[str] = None
    hashes: Optional[List[bytes]] = None

    @staticmethod
    def create(identifier: str, code_limit: int, code_hashes: List[bytes]) -> 'CodeDirectory':
        """Create a new CodeDirectory with calculated fields."""
        # Calculate sizes and offsets
        base_size = 44  # Size up to platform field
        identifier_bytes = identifier.encode('ascii', errors='ignore') + b'\0'
        identifier_offset = base_size
        hash_offset = base_size + ((len(identifier_bytes) + 3) & ~3)  # Align to 4 bytes
        total_size = hash_offset + (len(code_hashes) * 32)  # 32 is SHA256 hash size
        
        return CodeDirectory(
            magic=0xfade0c02,  # CSMAGIC_CODEDIRECTORY
            length=total_size,
            version=0x20400,  # Latest version
            flags=0x00000002 | 0x00000004,  # CS_ADHOC | CS_GET_TASK_ALLOW
            hashOffset=hash_offset,
            identOffset=identifier_offset,
            nSpecialSlots=0,
            nCodeSlots=len(code_hashes),
            codeLimit=code_limit,
            hashSize=32,  # SHA256
            hashType=2,  # CS_HASHTYPE_SHA256
            platform=0,
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
            teamId=None,
            hashes=code_hashes
        )

    def to_bytes(self) -> bytes:
        """Convert CodeDirectory to bytes."""
        data = bytearray()
        
        # Add header fields
        data.extend(struct.pack('>I', self.magic))
        data.extend(struct.pack('>I', self.length))
        data.extend(struct.pack('>I', self.version))
        data.extend(struct.pack('>I', self.flags))
        data.extend(struct.pack('>I', self.hashOffset))
        data.extend(struct.pack('>I', self.identOffset))
        data.extend(struct.pack('>I', self.nSpecialSlots))
        data.extend(struct.pack('>I', self.nCodeSlots))
        data.extend(struct.pack('>I', self.codeLimit))
        data.extend(struct.pack('>B', self.hashSize))
        data.extend(struct.pack('>B', self.hashType))
        data.extend(struct.pack('>B', self.platform))
        data.extend(struct.pack('>B', self.pageSize))
        data.extend(struct.pack('>I', self.spare2))
        data.extend(struct.pack('>I', self.scatterOffset))
        data.extend(struct.pack('>I', self.teamOffset))
        data.extend(struct.pack('>I', self.spare3))
        data.extend(struct.pack('>Q', self.codeLimit64))
        data.extend(struct.pack('>Q', self.execSegBase))
        data.extend(struct.pack('>Q', self.execSegLimit))
        data.extend(struct.pack('>Q', self.execSegFlags))
        data.extend(struct.pack('>Q', self.runtime))
        data.extend(struct.pack('>Q', self.preEncryptOffset))
        
        # Add identifier
        identifier_bytes = self.identifier.encode('ascii', errors='ignore') + b'\0'
        data.extend(identifier_bytes)
        
        # Pad to alignment
        while len(data) % 4 != 0:
            data.append(0)
        
        # Add hashes if present
        if self.hashes:
            for hash_value in self.hashes:
                data.extend(hash_value)
        
        return bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CodeDirectory':
        """Create CodeDirectory from bytes."""
        if len(data) < 44:
            raise ValueError("Data too small for CodeDirectory")
            
        # Parse fixed fields
        (magic, length, version, flags, 
         hashOffset, identOffset, nSpecialSlots, nCodeSlots,
         codeLimit, hashSize, hashType, platform, pageSize) = struct.unpack(
            '>IIIIIIII4B', data[:44]
        )
        
        spare2 = struct.unpack('>I', data[40:44])[0]
        
        # Get identifier
        if identOffset >= len(data):
            raise ValueError("Invalid identifier offset")
        end = data.find(b'\0', identOffset)
        if end == -1:
            end = len(data)
        identifier = data[identOffset:end].decode('ascii', errors='ignore')
        
        # Create instance
        return cls(
            magic=magic,
            length=length,
            version=version,
            flags=flags,
            hashOffset=hashOffset,
            identOffset=identOffset,
            nSpecialSlots=nSpecialSlots,
            nCodeSlots=nCodeSlots,
            codeLimit=codeLimit,
            hashSize=hashSize,
            hashType=hashType,
            platform=platform,
            pageSize=pageSize,
            spare2=spare2,
            scatterOffset=0,
            teamOffset=0,
            spare3=0,
            codeLimit64=0,
            execSegBase=0,
            execSegLimit=0,
            execSegFlags=0,
            runtime=0,
            preEncryptOffset=0,
            identifier=identifier
        )
