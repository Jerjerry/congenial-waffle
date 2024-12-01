import struct
from typing import List, Tuple, Dict, Optional
import logging

logger = logging.getLogger(__name__)

def _decode_string(data: bytes) -> str:
    """Safely decode a string from bytes, handling invalid UTF-8."""
    try:
        # Try UTF-8 first
        return data.decode('utf-8').rstrip('\x00')
    except UnicodeDecodeError:
        try:
            # Try ASCII, replacing invalid chars
            return data.decode('ascii', errors='replace').rstrip('\x00')
        except:
            # Last resort: return hex representation
            return f"hex:{data.hex()}"

class MachOHeader:
    def __init__(self, data: bytes):
        # Read in native byte order first
        magic = struct.unpack_from('I', data)[0]
        
        # Determine endianness
        if magic in [0xfeedface, 0xfeedfacf]:  # Native endian
            fmt = '<IIIIIII'
        elif magic in [0xcefaedfe, 0xcffaedfe]:  # Reverse endian
            fmt = '>IIIIIII'
        else:
            raise ValueError(f"Invalid Mach-O magic: 0x{magic:08x}")
            
        self.magic, self.cputype, self.cpusubtype, self.filetype, \
        self.ncmds, self.sizeofcmds, self.flags = struct.unpack_from(fmt, data)
        
        self.is_64bit = self.magic in [0xfeedfacf, 0xcffaedfe]
        self.size = 32

class LoadCommand:
    def __init__(self, data: bytes, offset: int = 0, is_little_endian: bool = True):
        fmt = '<II' if is_little_endian else '>II'
        self.cmd, self.cmdsize = struct.unpack_from(fmt, data, offset)
        self.data = data[offset:offset + self.cmdsize]
        
    def get_data(self) -> bytes:
        return self.data

class SegmentCommand:
    def __init__(self, data: bytes, offset: int = 0, is_64bit: bool = False, is_little_endian: bool = True):
        fmt_prefix = '<' if is_little_endian else '>'
        if is_64bit:
            fmt = f'{fmt_prefix}II16sQQQQIIII'
        else:
            fmt = f'{fmt_prefix}II16sIIIIIIII'
            
        values = struct.unpack_from(fmt, data, offset)
        
        self.cmd = values[0]
        self.cmdsize = values[1]
        self.segname = _decode_string(values[2])
        self.vmaddr = values[3]
        self.vmsize = values[4]
        self.fileoff = values[5]
        self.filesize = values[6]
        self.maxprot = values[7]
        self.initprot = values[8]
        self.nsects = values[9]
        self.flags = values[10]
        
        self.sections = []
        
    def add_section(self, section: 'Section'):
        self.sections.append(section)

class Section:
    def __init__(self, data: bytes, offset: int = 0, is_64bit: bool = False, is_little_endian: bool = True):
        fmt_prefix = '<' if is_little_endian else '>'
        if is_64bit:
            fmt = f'{fmt_prefix}16s16sQQIIIIIII'
        else:
            fmt = f'{fmt_prefix}16s16sIIIIIIIII'
            
        values = struct.unpack_from(fmt, data, offset)
        
        self.sectname = _decode_string(values[0])
        self.segname = _decode_string(values[1])
        self.addr = values[2]
        self.size = values[3]
        self.offset = values[4]
        self.align = values[5]
        self.reloff = values[6]
        self.nreloc = values[7]
        self.flags = values[8]
        self.reserved1 = values[9]
        self.reserved2 = values[10]

class MachO:
    MAGIC_VALUES = [
        0xfeedface,  # 32-bit little endian
        0xfeedfacf,  # 64-bit little endian
        0xcefaedfe,  # 32-bit big endian
        0xcffaedfe,  # 64-bit big endian
        0xcafebabe,  # Universal binary
        0xbebafeca   # Universal binary (reverse byte order)
    ]
    
    def __init__(self, data: bytes):
        if len(data) < 32:
            raise ValueError("File too small to be a valid Mach-O binary")
            
        self.data = data
        
        # Check magic number and endianness
        magic = struct.unpack('<I', data[:4])[0]
        self.is_little_endian = magic in [0xfeedface, 0xfeedfacf]
        
        if magic not in self.MAGIC_VALUES:
            # Try reverse byte order
            magic = struct.unpack('>I', data[:4])[0]
            self.is_little_endian = False
            if magic not in self.MAGIC_VALUES:
                raise ValueError(f"Not a valid Mach-O binary (magic: 0x{magic:x})")
                
        # Handle universal binary
        if magic in [0xcafebabe, 0xbebafeca]:
            logger.info("Detected universal binary, extracting preferred slice")
            data = self._extract_arch_slice(data)
            self.data = data
            magic = struct.unpack('<I' if self.is_little_endian else '>I', data[:4])[0]
            
        try:
            self.header = MachOHeader(data)
            logger.debug(f"Parsed Mach-O header: magic=0x{self.header.magic:x}, ncmds={self.header.ncmds}")
            
            if self.header.ncmds > 128:  # More reasonable limit
                raise ValueError(f"Too many load commands: {self.header.ncmds}")
                
        except struct.error as e:
            raise ValueError(f"Invalid Mach-O header: {str(e)}")
            
        self.load_commands = []
        self.segments = []
        
        offset = self.header.size
        try:
            for i in range(self.header.ncmds):
                if offset + 8 > len(data):
                    raise ValueError(f"Load command {i} extends beyond file bounds")
                    
                cmd = LoadCommand(data, offset, self.is_little_endian)
                self.load_commands.append(cmd)
                
                if cmd.cmd in [0x19, 0x1a]:  # LC_SEGMENT or LC_SEGMENT_64
                    try:
                        segment = SegmentCommand(data, offset, self.header.is_64bit, self.is_little_endian)
                        self.segments.append(segment)
                        
                        # Parse sections
                        sect_offset = offset + (72 if not self.header.is_64bit else 80)
                        sect_size = 68 if not self.header.is_64bit else 80
                        
                        for j in range(segment.nsects):
                            if sect_offset + sect_size > len(data):
                                raise ValueError(f"Section {j} extends beyond file bounds")
                                
                            section = Section(data, sect_offset, self.header.is_64bit, self.is_little_endian)
                            segment.add_section(section)
                            sect_offset += sect_size
                            
                    except struct.error as e:
                        raise ValueError(f"Invalid segment/section data: {str(e)}")
                        
                offset += cmd.cmdsize
                
        except struct.error as e:
            raise ValueError(f"Error parsing Mach-O structure: {str(e)}")
            
    def _extract_arch_slice(self, data: bytes) -> bytes:
        """Extract x86_64 or arm64 slice from universal binary"""
        try:
            if len(data) < 8:
                raise ValueError("Universal binary header too small")
                
            # Check if we need to swap endianness
            magic = struct.unpack('>I', data[:4])[0]
            is_big_endian = magic == 0xcafebabe
            
            # Read number of architectures
            fmt = '>I' if is_big_endian else '<I'
            nfat_arch = struct.unpack_from(fmt, data, 4)[0]
            
            if nfat_arch > 10:  # Sanity check
                raise ValueError(f"Too many architectures in universal binary: {nfat_arch}")
                
            # Parse fat_arch structures
            offset = 8
            arch_size = 20  # sizeof(fat_arch)
            
            preferred_arch = None
            preferred_priority = -1
            
            for i in range(nfat_arch):
                if offset + arch_size > len(data):
                    raise ValueError(f"Fat architecture {i} header extends beyond file bounds")
                    
                # Read fat_arch structure
                try:
                    fmt = '>5I' if is_big_endian else '<5I'
                    cputype, cpusubtype, arch_offset, size, align = struct.unpack_from(fmt, data, offset)
                    
                    # Validate offset and size
                    if arch_offset + size > len(data):
                        logger.warning(f"Architecture {i} data extends beyond file bounds, skipping")
                        continue
                        
                    # Prioritize architectures
                    priority = -1
                    if cputype == 0x100000C:  # ARM64
                        priority = 2
                    elif cputype == 0x7:  # X86_64
                        priority = 1
                        
                    if priority > preferred_priority:
                        preferred_arch = (arch_offset, size)
                        preferred_priority = priority
                        
                except struct.error as e:
                    logger.warning(f"Failed to parse architecture {i}: {str(e)}")
                    
                offset += arch_size
                
            if preferred_arch is None:
                raise ValueError("No suitable architecture found in universal binary")
                
            # Extract the preferred architecture slice
            arch_offset, arch_size = preferred_arch
            return data[arch_offset:arch_offset + arch_size]
            
        except Exception as e:
            raise ValueError(f"Failed to extract architecture slice: {str(e)}")
            
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
                offset, size = struct.unpack_from('<II', cmd.data, 8)
                return self.data[offset:offset + size]
        return None
        
    def replace_code_signature(self, new_signature: bytes) -> bytes:
        """Replace code signature in the binary with new one."""
        for cmd in self.load_commands:
            if cmd.cmd == 0x1d:  # LC_CODE_SIGNATURE
                offset, size = struct.unpack_from('<II', cmd.data, 8)
                if len(new_signature) > size:
                    raise ValueError("New signature is larger than the original")
                    
                result = bytearray(self.data)
                result[offset:offset + len(new_signature)] = new_signature
                # Zero out remaining space
                if len(new_signature) < size:
                    result[offset + len(new_signature):offset + size] = b'\x00' * (size - len(new_signature))
                return bytes(result)
        raise ValueError("No code signature found in binary")
