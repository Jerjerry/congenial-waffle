from cryptography.hazmat.primitives.serialization import pkcs12
import os
import sys
from pathlib import Path
import send2trash
import shutil

def validate_p12(file_path, password=None):
    try:
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
            
        if not file_path.lower().endswith('.p12'):
            return False, f"Not a .p12 file: {file_path}"
            
        # Convert password to bytes if provided
        password_bytes = password.encode() if password else None
        
        # Try to load the .p12 file
        with open(file_path, 'rb') as f:
            pkcs12.load_key_and_certificates(f.read(), password_bytes)
            
        return True, "Valid .p12 file"
        
    except Exception as e:
        return False, f"Invalid .p12 file: {str(e)}"

def cleanup_invalid_p12_files(directory_path, password=None):
    """
    Move invalid .p12 files to recycle bin.
    """
    directory = Path(directory_path)
    
    # Track statistics
    total_files = 0
    valid_files = 0
    removed_files = 0
    
    print(f"Scanning directory: {directory}")
    print("Moving invalid .p12 files to recycle bin...")
    
    # Process all .p12 files in directory and subdirectories
    for p12_file in directory.rglob('*.p12'):
        total_files += 1
        is_valid, message = validate_p12(str(p12_file), password)
        
        if is_valid:
            valid_files += 1
            print(f"KEEPING: {p12_file.relative_to(directory)}")
        else:
            removed_files += 1
            print(f"REMOVING: {p12_file.relative_to(directory)}")
            try:
                send2trash.send2trash(str(p12_file))
            except Exception as e:
                print(f"Error moving file to recycle bin: {e}")
                continue
    
    # Print summary
    print("\nSummary:")
    print(f"Total .p12 files processed: {total_files}")
    print(f"Valid files kept: {valid_files}")
    print(f"Invalid files moved to recycle bin: {removed_files}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python cleanup_invalid_p12.py <directory_path> [password]")
        sys.exit(1)
        
    path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.isdir(path):
        print("Error: Please provide a valid directory path")
        sys.exit(1)
        
    cleanup_invalid_p12_files(path, password)

if __name__ == "__main__":
    main()
