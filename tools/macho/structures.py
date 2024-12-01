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
            raise ValueError("Data too small for SuperBlob")
            
        magic, length, count = struct.unpack('>III', data[:12])
        
        blobs = []
        offset = 12
        for _ in range(count):
            if offset + 8 > len(data):
                break
            blob = BlobIndex.from_bytes(data[offset:offset + 8])
            blobs.append(blob)
            offset += 8
            
        return cls(
            magic=magic,
            length=length,
            count=count,
            blobs=blobs
        )

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
    hashes: List[bytes] = None

    @classmethod
    def from_bytes(cls, data: bytes) -> 'CodeDirectory':
        if len(data) < 44:
            raise ValueError("Data too small for CodeDirectory")
            
        magic, length, version, flags = struct.unpack('>IIII', data[:16])
        hashOffset, identOffset, nSpecialSlots, nCodeSlots = struct.unpack('>IIII', data[16:32])
        codeLimit, hashSize, hashType, platform, pageSize = struct.unpack('>IBBBB', data[32:40])
        spare2 = struct.unpack('>I', data[40:44])[0]
        
        # Get identifier string
        if identOffset:
            identifier = data[identOffset:].split(b'\0')[0].decode('utf-8')
        else:
            identifier = ""
            
        # Get team ID if present
        teamId = None
        if version >= 0x20200:
            teamOffset = struct.unpack('>I', data[88:92])[0]
            if teamOffset:
                teamId = data[teamOffset:].split(b'\0')[0].decode('utf-8')
                
        # Get hashes
        hashes = []
        if hashOffset:
            hash_start = hashOffset - (nSpecialSlots * hashSize)
            for i in range(nSpecialSlots + nCodeSlots):
                if hash_start + (i * hashSize) + hashSize > len(data):
                    break
                hash_data = data[hash_start + (i * hashSize):hash_start + (i * hashSize) + hashSize]
                hashes.append(hash_data)
                
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
            identifier=identifier,
            teamId=teamId,
            hashes=hashes
        )
