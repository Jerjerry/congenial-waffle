import os
import shutil
import zipfile
from pathlib import Path

def create_test_ipa():
    """Create a minimal test IPA file for signing tests"""
    
    # Create temporary directory structure
    temp_dir = Path("temp_ipa")
    payload_dir = temp_dir / "Payload"
    app_dir = payload_dir / "TestApp.app"
    
    # Clean up any existing temp directory
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    
    # Create directory structure
    app_dir.mkdir(parents=True)
    
    # Create Info.plist
    info_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.testapp</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleName</key>
    <string>TestApp</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSRequiresIPhoneOS</key>
    <true/>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
    </array>
</dict>
</plist>"""
    
    with open(app_dir / "Info.plist", "w", encoding="utf-8") as f:
        f.write(info_plist)
    
    # Create dummy executable
    with open(app_dir / "TestApp", "wb") as f:
        # Simple Mach-O header for arm64
        macho_header = bytes.fromhex(
            "CF FA ED FE"  # Magic (64-bit)
            "0C 00 00 01"  # CPU Type (ARM64)
            "00 00 00 00"  # CPU Subtype
            "02 00 00 00"  # File Type (Executable)
            "02 00 00 00"  # Number of load commands (2)
            "E0 00 00 00"  # Size of load commands
            "01 00 00 00"  # Flags (MH_NOUNDEFS)
            # Load Command 1: Segment64
            "19 00 00 00"  # LC_SEGMENT_64
            "48 00 00 00"  # Command size
            "5F 54 45 58 54 00 00 00"  # segname ("__TEXT")
            "00 00 00 00 00 00 00 00"  # vmaddr
            "00 10 00 00 00 00 00 00"  # vmsize
            "00 00 00 00 00 00 00 00"  # fileoff
            "00 10 00 00 00 00 00 00"  # filesize
            "07 00 00 00"              # maxprot (rwx)
            "05 00 00 00"              # initprot (rx)
            "00 00 00 00"              # nsects
            "00 00 00 00"              # flags
            # Load Command 2: Main
            "80 00 00 00"  # LC_MAIN
            "18 00 00 00"  # Command size
            "00 00 00 00 00 00 00 00"  # entryoff
            "00 00 00 00 00 00 00 00"  # stacksize
        )
        f.write(macho_header)
        
        # Add some code section data
        f.write(bytes([
            0x55,                      # push   rbp
            0x48, 0x89, 0xE5,         # mov    rbp, rsp
            0xB8, 0x00, 0x00, 0x00, 0x00,  # mov    eax, 0
            0x5D,                      # pop    rbp
            0xC3                       # ret
        ]))
        
        # Pad to page boundary
        f.write(b"\0" * (0x1000 - f.tell()))
    
    # Make executable
    os.chmod(app_dir / "TestApp", 0o755)
    
    # Create IPA
    output_path = "test_unsigned.ipa"
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = Path(root) / file
                arc_path = file_path.relative_to(temp_dir)
                zf.write(file_path, arc_path)
    
    # Clean up
    shutil.rmtree(temp_dir)
    
    print(f"Created test IPA: {output_path}")
    return output_path

if __name__ == "__main__":
    create_test_ipa()
