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
        cmd, cmdsize = struct.unpack('<II', data[:8])
        segname = data[8:24].decode('utf-8').rstrip('\0')
        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack('<QQQQ4I', data[24:72])
        
        sections = []
        offset = 72
        for _ in range(nsects):
            if offset + 80 > len(data):
                break
            section_data = data[offset:offset + 80]
            section = Section64.from_bytes(section_data)
            sections.append(section)
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

    def to_bytes(self) -> bytes:
        """Convert CodeDirectory to bytes."""
        # Calculate offsets and sizes
        base_size = 44  # Size up to platform field
        
        # Convert identifier to bytes and add null terminator
        identifier_bytes = self.identifier.encode('ascii', errors='ignore') + b'\0'
        identifier_offset = base_size
        total_size = base_size + len(identifier_bytes)
        
        # Align to 4 bytes
        total_size = (total_size + 3) & ~3
        
        # Create the basic structure
        data = bytearray()
        data.extend(struct.pack('>I', self.magic))  # magic
        data.extend(struct.pack('>I', total_size))  # length
        data.extend(struct.pack('>I', self.version))  # version
        data.extend(struct.pack('>I', self.flags))  # flags
        data.extend(struct.pack('>I', self.hashOffset))  # hashOffset
        data.extend(struct.pack('>I', identifier_offset))  # identOffset
        data.extend(struct.pack('>I', self.nSpecialSlots))  # nSpecialSlots
        data.extend(struct.pack('>I', self.nCodeSlots))  # nCodeSlots
        data.extend(struct.pack('>I', self.codeLimit))  # codeLimit
        data.extend(struct.pack('>B', self.hashSize))  # hashSize
        data.extend(struct.pack('>B', self.hashType))  # hashType
        data.extend(struct.pack('>B', self.platform))  # platform
        data.extend(struct.pack('>B', self.pageSize))  # pageSize
        data.extend(struct.pack('>I', self.spare2))  # spare2
        data.extend(struct.pack('>I', self.scatterOffset))  # scatterOffset
        data.extend(struct.pack('>I', self.teamOffset))  # teamOffset
        data.extend(struct.pack('>I', self.spare3))  # spare3
        data.extend(struct.pack('>Q', self.codeLimit64))  # codeLimit64
        data.extend(struct.pack('>Q', self.execSegBase))  # execSegBase
        data.extend(struct.pack('>Q', self.execSegLimit))  # execSegLimit
        data.extend(struct.pack('>Q', self.execSegFlags))  # execSegFlags
        data.extend(struct.pack('>Q', self.runtime))  # runtime
        data.extend(struct.pack('>Q', self.preEncryptOffset))  # preEncryptOffset
        
        # Add identifier
        data.extend(identifier_bytes)
        
        # Add padding to align
        while len(data) < total_size:
            data.append(0)
            
        return bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CodeDirectory':
        """Create CodeDirectory from bytes."""
        if len(data) < 44:  # Minimum size for base structure
            raise ValueError("Data too small for CodeDirectory")
            
        # Parse fixed fields
        magic, length, version, flags = struct.unpack('>IIII', data[:16])
        hashOffset, identOffset, nSpecialSlots, nCodeSlots = struct.unpack('>IIII', data[16:32])
        codeLimit, hashSize, hashType, platform, pageSize = struct.unpack('>IBBBB', data[32:40])
        spare2 = struct.unpack('>I', data[40:44])[0]
        
        # Get identifier
        if identOffset >= len(data):
            raise ValueError("Invalid identifier offset")
        end = data.find(b'\0', identOffset)
        if end == -1:
            end = len(data)
        identifier = data[identOffset:end].decode('ascii', errors='ignore')
        
        # Create instance with minimum required fields
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
