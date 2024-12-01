import struct
import logging
from typing import List, Optional
from .structures import MachHeader, LoadCommand, SegmentCommand64, Section64

logger = logging.getLogger(__name__)

class MachOParser:
    """Parser for Mach-O binary files."""
    
    def __init__(self, binary_path: str):
        """Initialize parser with binary path."""
        self.binary_path = binary_path
        self.header: Optional[MachHeader] = None
        self.segments: List[SegmentCommand64] = []
        self.sections: List[Section64] = []
        
        try:
            with open(binary_path, 'rb') as f:
                self.macho_data = f.read()
            self._parse_header()
            self._parse_load_commands()
        except Exception as e:
            logger.error(f"Failed to parse Mach-O binary: {str(e)}")
            raise
    
    def _parse_header(self):
        """Parse Mach-O header."""
        try:
            # Check magic number
            magic = int.from_bytes(self.macho_data[:4], byteorder='little')
            is_64 = (magic == 0xfeedfacf)  # MH_MAGIC_64
            
            if not is_64:
                raise ValueError("Only 64-bit Mach-O binaries are supported")
            
            # Parse header
            self.header = MachHeader.from_bytes(self.macho_data[:32], is_64=True)
            
        except Exception as e:
            logger.error(f"Failed to parse Mach-O header: {str(e)}")
            raise
    
    def _parse_load_commands(self):
        """Parse load commands."""
        try:
            offset = 32  # Size of 64-bit header
            
            for _ in range(self.header.ncmds):
                # Read command header
                cmd, cmdsize = struct.unpack('<II', self.macho_data[offset:offset + 8])
                
                # Parse segment command
                if cmd == 0x19:  # LC_SEGMENT_64
                    segment = SegmentCommand64.from_bytes(self.macho_data[offset:offset + cmdsize])
                    self.segments.append(segment)
                    self.sections.extend(segment.sections)
                
                offset += cmdsize
                
        except Exception as e:
            logger.error(f"Failed to parse load commands: {str(e)}")
            raise
    
    def find_segment(self, segname: str) -> Optional[SegmentCommand64]:
        """Find segment by name."""
        for segment in self.segments:
            if segment.segname == segname:
                return segment
        return None
