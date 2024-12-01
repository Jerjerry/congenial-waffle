import struct
from typing import List, Tuple, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class MachOHeader:
    def __init__(self, data: bytes):
        self.magic, self.cputype, self.cpusubtype, self.filetype, \
        self.ncmds, self.sizeofcmds, self.flags = struct.unpack_from('>IIIIIII', data)
        self.is_64bit = self.magic == 0xfeedfacf
        self.size = 32 if not self.is_64bit else 32

class LoadCommand:
    def __init__(self, data: bytes, offset: int = 0):
        self.cmd, self.cmdsize = struct.unpack_from('>II', data, offset)
        self.data = data[offset:offset + self.cmdsize]
        
    def get_data(self) -> bytes:
        return self.data

class SegmentCommand:
    def __init__(self, data: bytes, offset: int = 0, is_64bit: bool = False):
        if is_64bit:
            self.cmd, self.cmdsize, self.segname, \
            self.vmaddr, self.vmsize, self.fileoff, self.filesize, \
            self.maxprot, self.initprot, self.nsects, self.flags = \
                struct.unpack_from('>II16sQQQQIIII', data, offset)
        else:
            self.cmd, self.cmdsize, self.segname, \
            self.vmaddr, self.vmsize, self.fileoff, self.filesize, \
            self.maxprot, self.initprot, self.nsects, self.flags = \
                struct.unpack_from('>II16sIIIIIIII', data, offset)
                
        self.segname = self.segname.decode('utf-8').rstrip('\x00')
        self.sections: List[Section] = []
        
    def add_section(self, section: 'Section'):
        self.sections.append(section)

class Section:
    def __init__(self, data: bytes, offset: int = 0, is_64bit: bool = False):
        if is_64bit:
            self.sectname, self.segname, \
            self.addr, self.size, self.offset, \
            self.align, self.reloff, self.nreloc, \
            self.flags, self.reserved1, self.reserved2 = \
                struct.unpack_from('>16s16sQQIIIIIII', data, offset)
        else:
            self.sectname, self.segname, \
            self.addr, self.size, self.offset, \
            self.align, self.reloff, self.nreloc, \
            self.flags, self.reserved1, self.reserved2 = \
                struct.unpack_from('>16s16sIIIIIIIII', data, offset)
                
        self.sectname = self.sectname.decode('utf-8').rstrip('\x00')
        self.segname = self.segname.decode('utf-8').rstrip('\x00')

class MachO:
    def __init__(self, data: bytes):
        self.data = data
        self.header = MachOHeader(data)
        self.load_commands: List[LoadCommand] = []
        self.segments: List[SegmentCommand] = []
        
        offset = self.header.size
        for _ in range(self.header.ncmds):
            cmd = LoadCommand(data, offset)
            self.load_commands.append(cmd)
            
            if cmd.cmd in [0x19, 0x1a]:  # LC_SEGMENT or LC_SEGMENT_64
                segment = SegmentCommand(data, offset, self.header.is_64bit)
                self.segments.append(segment)
                
                # Parse sections
                sect_offset = offset + (72 if not self.header.is_64bit else 80)
                for _ in range(segment.nsects):
                    section = Section(data, sect_offset, self.header.is_64bit)
                    segment.add_section(section)
                    sect_offset += 68 if not self.header.is_64bit else 80
                    
            offset += cmd.cmdsize
            
    def find_segment(self, name: str) -> Optional[SegmentCommand]:
        for segment in self.segments:
            if segment.segname == name:
                return segment
        return None
        
    def find_section(self, segname: str, sectname: str) -> Optional[Section]:
        segment = self.find_segment(segname)
        if segment:
            for section in segment.sections:
                if section.sectname == sectname:
                    return section
        return None
        
    def get_code_signature(self) -> Optional[bytes]:
        for cmd in self.load_commands:
            if cmd.cmd == 0x1d:  # LC_CODE_SIGNATURE
                offset, size = struct.unpack_from('>II', cmd.data, 8)
                return self.data[offset:offset + size]
        return None
        
    def replace_code_signature(self, new_signature: bytes) -> bytes:
        result = bytearray(self.data)
        for cmd in self.load_commands:
            if cmd.cmd == 0x1d:  # LC_CODE_SIGNATURE
                offset, size = struct.unpack_from('>II', cmd.data, 8)
                if len(new_signature) > size:
                    raise ValueError("New signature is larger than the original")
                result[offset:offset + len(new_signature)] = new_signature
                # Zero out remaining space if new signature is smaller
                if len(new_signature) < size:
                    result[offset + len(new_signature):offset + size] = b'\x00' * (size - len(new_signature))
                return bytes(result)
        raise ValueError("No code signature found in binary")
