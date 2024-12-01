import struct
from typing import List, Optional, Tuple
from .constants import *
from .structures import *

class DylibInjector:
    def __init__(self, macho_data: bytes):
        self.macho_data = bytearray(macho_data)
        self.is_64 = False
        self.header_size = 0
        self._parse_header()
        
    def _parse_header(self):
        """Parse the Mach-O header"""
        magic = struct.unpack('>I', self.macho_data[:4])[0]
        if magic == MH_MAGIC_64:
            self.is_64 = True
            self.header_size = 32
        elif magic == MH_MAGIC:
            self.is_64 = False
            self.header_size = 28
        else:
            raise ValueError("Invalid Mach-O file")
            
    def _find_linkedit_segment(self) -> Tuple[int, int, int]:
        """Find the __LINKEDIT segment and its offset"""
        offset = self.header_size
        ncmds = struct.unpack('>I', self.macho_data[16:20])[0]
        
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('>II', self.macho_data[offset:offset + 8])
            if cmd == LC_SEGMENT_64:
                segname = self.macho_data[offset + 8:offset + 24].decode('utf-8').rstrip('\0')
                if segname == SEG_LINKEDIT:
                    vmaddr = struct.unpack('>Q', self.macho_data[offset + 24:offset + 32])[0]
                    vmsize = struct.unpack('>Q', self.macho_data[offset + 32:offset + 40])[0]
                    fileoff = struct.unpack('>Q', self.macho_data[offset + 40:offset + 48])[0]
                    return offset, fileoff, vmaddr
            offset += cmdsize
            
        raise ValueError("__LINKEDIT segment not found")
        
    def _update_header_counts(self, size_increase: int):
        """Update the header's command count and size"""
        ncmds = struct.unpack('>I', self.macho_data[16:20])[0]
        sizeofcmds = struct.unpack('>I', self.macho_data[20:24])[0]
        
        # Update counts
        struct.pack_into('>I', self.macho_data, 16, ncmds + 1)
        struct.pack_into('>I', self.macho_data, 20, sizeofcmds + size_increase)
        
    def _shift_data(self, start: int, shift_amount: int):
        """Shift data in the file to make room for new content"""
        self.macho_data[start + shift_amount:] = self.macho_data[start:]
        
    def _update_segment_offsets(self, insert_point: int, shift_amount: int):
        """Update all segment offsets after the insertion point"""
        offset = self.header_size
        ncmds = struct.unpack('>I', self.macho_data[16:20])[0]
        
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('>II', self.macho_data[offset:offset + 8])
            if cmd == LC_SEGMENT_64:
                fileoff = struct.unpack('>Q', self.macho_data[offset + 40:offset + 48])[0]
                if fileoff > insert_point:
                    new_offset = fileoff + shift_amount
                    struct.pack_into('>Q', self.macho_data, offset + 40, new_offset)
            offset += cmdsize
            
    def inject_dylib(self, dylib_path: str, weak: bool = False) -> bytes:
        """Inject a dylib load command into the Mach-O binary"""
        # Prepare the dylib command
        path_bytes = dylib_path.encode('utf-8') + b'\0'
        padded_path_size = (len(path_bytes) + 7) & ~7  # Align to 8 bytes
        cmd_size = 24 + padded_path_size
        
        # Create the load command
        cmd_data = bytearray()
        cmd = LC_LOAD_WEAK_DYLIB if weak else LC_LOAD_DYLIB
        struct.pack_into('>I', cmd_data, 0, cmd)
        struct.pack_into('>I', cmd_data, 4, cmd_size)
        struct.pack_into('>I', cmd_data, 8, 24)  # Path offset
        struct.pack_into('>I', cmd_data, 12, 2)  # Timestamp
        struct.pack_into('>I', cmd_data, 16, 0x10000)  # Current version
        struct.pack_into('>I', cmd_data, 20, 0x10000)  # Compatibility version
        cmd_data.extend(path_bytes.ljust(padded_path_size, b'\0'))
        
        # Find insertion point (after last load command)
        offset = self.header_size
        ncmds = struct.unpack('>I', self.macho_data[16:20])[0]
        for _ in range(ncmds):
            _, cmdsize = struct.unpack('>II', self.macho_data[offset:offset + 8])
            offset += cmdsize
            
        # Make space for the new command
        self._shift_data(offset, len(cmd_data))
        
        # Insert the new command
        self.macho_data[offset:offset + len(cmd_data)] = cmd_data
        
        # Update header counts
        self._update_header_counts(len(cmd_data))
        
        # Update segment offsets
        self._update_segment_offsets(offset, len(cmd_data))
        
        return bytes(self.macho_data)
        
    def remove_dylib(self, dylib_path: str) -> bytes:
        """Remove a dylib load command from the Mach-O binary"""
        offset = self.header_size
        ncmds = struct.unpack('>I', self.macho_data[16:20])[0]
        
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack('>II', self.macho_data[offset:offset + 8])
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                path_offset = struct.unpack('>I', self.macho_data[offset + 8:offset + 12])[0]
                path_start = offset + path_offset
                path_end = self.macho_data.find(b'\0', path_start)
                path = self.macho_data[path_start:path_end].decode('utf-8')
                
                if path == dylib_path:
                    # Remove this command
                    self.macho_data[offset:offset + cmdsize] = b'\0' * cmdsize
                    self._update_header_counts(-cmdsize)
                    return bytes(self.macho_data)
                    
            offset += cmdsize
            
        raise ValueError(f"Dylib {dylib_path} not found in binary")
