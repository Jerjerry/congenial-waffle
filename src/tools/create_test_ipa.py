import os
import zipfile
import plistlib
import tempfile
import shutil
import struct

def create_macho_binary(path):
    """Create a minimal but valid Mach-O binary"""
    with open(path, 'wb') as f:
        # Mach-O Header (64-bit)
        f.write(struct.pack('<I', 0xFEEDFACF))  # Magic (64-bit)
        f.write(struct.pack('<I', 0x01000007))  # CPU Type (x86_64)
        f.write(struct.pack('<I', 0x00000003))  # CPU Subtype
        f.write(struct.pack('<I', 0x00000002))  # File Type (MH_EXECUTE)
        f.write(struct.pack('<I', 0x00000004))  # Number of load commands
        f.write(struct.pack('<I', 0x000001C0))  # Size of load commands
        f.write(struct.pack('<I', 0x00200085))  # Flags
        f.write(struct.pack('<I', 0x00000000))  # Reserved
        
        # Load Commands
        # 1. LC_SEGMENT_64 (__PAGEZERO)
        cmd_offset = 32  # Current offset after header
        segment_size = 72  # Size of segment command
        f.write(struct.pack('<I', 0x19))  # cmd (LC_SEGMENT_64)
        f.write(struct.pack('<I', segment_size))  # cmdsize
        f.write(b'__PAGEZERO'.ljust(16, b'\0'))  # segname
        f.write(struct.pack('<Q', 0x0))  # vmaddr
        f.write(struct.pack('<Q', 0x100000000))  # vmsize
        f.write(struct.pack('<Q', 0x0))  # fileoff
        f.write(struct.pack('<Q', 0x0))  # filesize
        f.write(struct.pack('<I', 0x0))  # maxprot
        f.write(struct.pack('<I', 0x0))  # initprot
        f.write(struct.pack('<I', 0x0))  # nsects
        f.write(struct.pack('<I', 0x0))  # flags
        cmd_offset += segment_size
        
        # 2. LC_SEGMENT_64 (__TEXT)
        f.write(struct.pack('<I', 0x19))  # cmd (LC_SEGMENT_64)
        f.write(struct.pack('<I', segment_size))  # cmdsize
        f.write(b'__TEXT'.ljust(16, b'\0'))  # segname
        f.write(struct.pack('<Q', 0x100000000))  # vmaddr
        f.write(struct.pack('<Q', 0x1000))  # vmsize
        f.write(struct.pack('<Q', 0x0))  # fileoff
        f.write(struct.pack('<Q', 0x1000))  # filesize
        f.write(struct.pack('<I', 0x7))  # maxprot (rwx)
        f.write(struct.pack('<I', 0x5))  # initprot (rx)
        f.write(struct.pack('<I', 0x0))  # nsects
        f.write(struct.pack('<I', 0x0))  # flags
        cmd_offset += segment_size
        
        # 3. LC_SEGMENT_64 (__LINKEDIT)
        f.write(struct.pack('<I', 0x19))  # cmd (LC_SEGMENT_64)
        f.write(struct.pack('<I', segment_size))  # cmdsize
        f.write(b'__LINKEDIT'.ljust(16, b'\0'))  # segname
        f.write(struct.pack('<Q', 0x101000000))  # vmaddr
        f.write(struct.pack('<Q', 0x1000))  # vmsize
        f.write(struct.pack('<Q', 0x1000))  # fileoff
        f.write(struct.pack('<Q', 0x1000))  # filesize
        f.write(struct.pack('<I', 0x7))  # maxprot (rwx)
        f.write(struct.pack('<I', 0x1))  # initprot (r)
        f.write(struct.pack('<I', 0x0))  # nsects
        f.write(struct.pack('<I', 0x0))  # flags
        cmd_offset += segment_size
        
        # 4. LC_CODE_SIGNATURE
        f.write(struct.pack('<I', 0x1D))  # cmd (LC_CODE_SIGNATURE)
        f.write(struct.pack('<I', 16))  # cmdsize
        f.write(struct.pack('<I', 0x2000))  # dataoff
        f.write(struct.pack('<I', 0x1000))  # datasize
        
        # Add some padding to reach file size
        f.write(b'\0' * (0x2000 - f.tell()))
        
# Create a simple test IPA structure
temp_dir = tempfile.mkdtemp()
try:
    # Create Payload directory
    payload_dir = os.path.join(temp_dir, 'Payload')
    os.makedirs(payload_dir)
    
    # Create .app directory
    app_dir = os.path.join(payload_dir, 'TestApp.app')
    os.makedirs(app_dir)
    
    # Create Info.plist
    info_plist = {
        'CFBundleIdentifier': 'com.test.app',
        'CFBundleName': 'TestApp',
        'CFBundleDisplayName': 'TestApp',
        'CFBundleExecutable': 'TestApp',
        'CFBundleVersion': '1.0',
        'CFBundleShortVersionString': '1.0',
        'CFBundlePackageType': 'APPL',
        'MinimumOSVersion': '12.0',
    }
    
    with open(os.path.join(app_dir, 'Info.plist'), 'wb') as f:
        plistlib.dump(info_plist, f)
        
    # Create executable
    create_macho_binary(os.path.join(app_dir, 'TestApp'))
    
    # Create IPA
    with zipfile.ZipFile('test.ipa', 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, temp_dir)
                zipf.write(file_path, arcname)
                
    print("Created test IPA: test.ipa")
    
finally:
    shutil.rmtree(temp_dir)
