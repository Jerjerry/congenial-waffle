from cryptography.hazmat.primitives.serialization import pkcs12
import os
import sys
from pathlib import Path

def validate_p12(file_path, password=None):
    """
    Validate a .p12 file by attempting to load it.
    
    Args:
        file_path (str): Path to the .p12 file
        password (bytes, optional): Password for the .p12 file, if required
        
    Returns:
        tuple: (bool, str) - (is_valid, message)
    """
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

def process_directory(directory_path, password=None):
    """
    Process all .p12 files in a directory and its subdirectories.
    
    Args:
        directory_path (str): Path to the directory containing .p12 files
        password (str, optional): Password for the .p12 files, if required
    """
    directory = Path(directory_path)
    
    # Track statistics
    total_files = 0
    valid_files = 0
    invalid_files = 0
    
    # Process all .p12 files in directory and subdirectories
    for p12_file in directory.rglob('*.p12'):
        total_files += 1
        is_valid, message = validate_p12(str(p12_file), password)
        
        # Update statistics
        if is_valid:
            valid_files += 1
            status = "VALID"
        else:
            invalid_files += 1
            status = "INVALID"
            
        # Print result with relative path
        try:
            rel_path = os.path.relpath(p12_file, directory)
        except ValueError:
            rel_path = str(p12_file)
        
        print(f"{status} {rel_path}: {message}")
    
    # Print summary
    print("\nSummary:")
    print(f"Total .p12 files found: {total_files}")
    print(f"Valid files: {valid_files}")
    print(f"Invalid files: {invalid_files}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python p12_validator.py <directory_or_file_path> [password]")
        sys.exit(1)
        
    path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else None
    
    if os.path.isdir(path):
        process_directory(path, password)
    else:
        is_valid, message = validate_p12(path, password)
        print(message)
        sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()
