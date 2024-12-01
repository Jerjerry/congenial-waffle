import struct
import logging
from typing import List, Optional, Tuple
from .structures import MachHeader, LoadCommand, SegmentCommand64, Section64, CodeDirectory, BlobIndex, SuperBlob
from .constants import *

class MachOParser:
    def __init__(self, macho_data: bytes):
        """Initialize parser with Mach-O binary data"""
        self.macho_data = macho_data
        self.is_64bit = False
        self.is_little_endian = False
        self.header = None
        self.load_commands = []
        self.code_signature = None
        self.code_signature_offset = None
        self.code_signature_size = None
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        
        try:
            self._parse_header()
            self._parse_load_commands()
            
        except Exception as e:
            self.logger.error(f"Failed to parse Mach-O binary: {str(e)}")
            raise
            
    def _read_bytes(self, size: int) -> bytes:
        """Read bytes from the binary at current offset."""
        if self.offset + size > len(self.macho_data):
            raise ValueError(f"Attempted to read beyond end of file (offset {self.offset}, size {size})")
        data = self.macho_data[self.offset:self.offset + size]
        self.offset += size
        return data
        
    def _read_uint32(self) -> int:
        """Read a 32-bit unsigned integer."""
        try:
            return struct.unpack('<I', self._read_bytes(4))[0]
        except struct.error as e:
            raise ValueError(f"Failed to read uint32 at offset {self.offset}: {str(e)}")
            
    def _read_uint64(self) -> int:
        """Read a 64-bit unsigned integer."""
        try:
            return struct.unpack('<Q', self._read_bytes(8))[0]
        except struct.error as e:
            raise ValueError(f"Failed to read uint64 at offset {self.offset}: {str(e)}")
            
    def _parse_header(self):
        """Parse Mach-O header"""
        # Read magic number
        magic = int.from_bytes(self.macho_data[:4], byteorder='big')
        
        # Determine format
        if magic == 0xfeedface:  # 32-bit
            self.is_64bit = False
            self.is_little_endian = False
        elif magic == 0xcefaedfe:  # 32-bit, little-endian
            self.is_64bit = False
            self.is_little_endian = True
        elif magic == 0xfeedfacf:  # 64-bit
            self.is_64bit = True
            self.is_little_endian = False
        elif magic == 0xcffaedfe:  # 64-bit, little-endian
            self.is_64bit = True
            self.is_little_endian = True
        else:
            raise ValueError(f"Invalid Mach-O magic: {magic:08x}")
            
        is_swap = magic in [MH_CIGAM, MH_CIGAM_64]
            
        if self.is_64bit:
            header_size = 32  # Size of mach_header_64
        else:
            header_size = 28  # Size of mach_header
                
        if len(self.macho_data) < header_size:
            raise ValueError(f"File is too small for Mach-O header (size: {len(self.macho_data)})")
                
        # Parse header fields
        header_data = self.macho_data[:header_size]
        if self.is_64bit:
            fields = struct.unpack('<IIIIIIII' if self.is_little_endian else '>IIIIIIII', header_data)
        else:
            fields = struct.unpack('<IIIIIII' if self.is_little_endian else '>IIIIIII', header_data)
                
        self.header = MachHeader(
            magic=fields[0],
            cputype=fields[1],
            cpusubtype=fields[2],
            filetype=fields[3],
            ncmds=fields[4],
            sizeofcmds=fields[5],
            flags=fields[6]
        )
            
        self.offset = header_size
        self.logger.debug(f"Parsed Mach-O header: {self.header}")
            
    def _parse_load_commands(self):
        """Parse all load commands."""
        try:
            for i in range(self.header.ncmds):
                if self.offset + 8 > len(self.macho_data):
                    raise ValueError(f"Unexpected end of file while parsing load command {i}")
                    
                cmd, cmdsize = struct.unpack('<II' if self.is_little_endian else '>II', self.macho_data[self.offset:self.offset + 8])
                
                if cmdsize < 8:
                    raise ValueError(f"Invalid load command size: {cmdsize}")
                    
                if self.offset + cmdsize > len(self.macho_data):
                    raise ValueError(f"Load command {i} extends beyond end of file")
                    
                command_data = self.macho_data[self.offset:self.offset + cmdsize]
                
                if cmd == LC_SEGMENT_64:
                    segname = command_data[8:24].decode('utf-8').rstrip('\0')
                    self.logger.debug(f"Parsed segment {segname} with 0 sections")
                elif cmd == LC_CODE_SIGNATURE:
                    if cmdsize >= 16:
                        self.code_signature_offset, self.code_signature_size = struct.unpack('<II' if self.is_little_endian else '>II', command_data[8:16])
                        self.logger.debug(f"Found code signature at offset {self.code_signature_offset}, size {self.code_signature_size}")
                        
                self.load_commands.append(LoadCommand(cmd=cmd, cmdsize=cmdsize, data=command_data))
                self.offset += cmdsize
                
            self.logger.debug(f"Parsed {len(self.load_commands)} load commands")
            
        except Exception as e:
            self.logger.error(f"Failed to parse load commands: {str(e)}")
            raise
            
    def get_code_signature_data(self) -> Optional[bytes]:
        """Get existing code signature data if present"""
        # Find LC_CODE_SIGNATURE load command
        cmd_size = 8
        offset = 28 if self.is_64bit else 24
        
        while offset < len(self.macho_data):
            cmd = int.from_bytes(self.macho_data[offset:offset+4], 
                               byteorder='little' if self.is_little_endian else 'big')
            cmdsize = int.from_bytes(self.macho_data[offset+4:offset+8],
                                   byteorder='little' if self.is_little_endian else 'big')
            
            if cmd == 0x1d:  # LC_CODE_SIGNATURE
                data_offset = int.from_bytes(self.macho_data[offset+8:offset+12],
                                          byteorder='little' if self.is_little_endian else 'big')
                data_size = int.from_bytes(self.macho_data[offset+12:offset+16],
                                        byteorder='little' if self.is_little_endian else 'big')
                return self.macho_data[data_offset:data_offset+data_size]
                
            offset += cmdsize
            
        return None
        
    def get_code_directory(self) -> Optional[CodeDirectory]:
        """Get the CodeDirectory if present."""
        signature_data = self.get_code_signature_data()
        if not signature_data:
            return None
            
        try:
            # Parse SuperBlob
            if len(signature_data) < 12:
                return None
                
            magic, length, count = struct.unpack('>III', signature_data[:12])
            if magic != CSMAGIC_EMBEDDED_SIGNATURE:
                return None
                
            # Find CodeDirectory
            offset = 12
            for i in range(count):
                if offset + 8 > len(signature_data):
                    break
                    
                type_, blob_offset = struct.unpack('>II', signature_data[offset:offset + 8])
                if type_ == CSSLOT_CODEDIRECTORY:
                    if blob_offset < len(signature_data):
                        return CodeDirectory.from_bytes(signature_data[blob_offset:])
                offset += 8
                
        except Exception as e:
            self.logger.error(f"Failed to parse code directory: {str(e)}")
            
        return None
        
    def find_segment(self, segname: str) -> Optional[SegmentCommand64]:
        """Find a segment by name"""
        for cmd in self.load_commands:
            if cmd.cmd == LC_SEGMENT_64:
                segment = SegmentCommand64.from_bytes(cmd.data)
                if segment.segname == segname:
                    return segment
        return None
        
    def find_section(self, segname: str, sectname: str) -> Optional[Section64]:
        """Find a section by segment and section name"""
        segment = self.find_segment(segname)
        if segment:
            for section in segment.sections:
                if section.sectname == sectname:
                    return section
        return None
        
    def get_linkedit_segment(self) -> Optional[SegmentCommand64]:
        """Get the __LINKEDIT segment"""
        return self.find_segment('__LINKEDIT')
