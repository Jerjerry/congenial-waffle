import os
import sys
import glob
import argparse
from pathlib import Path

def find_certificates(cert_dir):
    """Find all .p12 certificates in the specified directory"""
    cert_files = list(Path(cert_dir).glob('*.p12'))
    if not cert_files:
        print("No .p12 certificates found!")
        return None
    
    print("\nAvailable certificates:")
    for i, cert in enumerate(cert_files, 1):
        print(f"{i}. {cert.name}")
    
    while True:
        try:
            choice = int(input("\nSelect certificate number (or 0 to exit): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(cert_files):
                return cert_files[choice - 1]
        except ValueError:
            pass
        print("Invalid selection. Please try again.")

def sign_ipa(ipa_path, cert_path, bundle_id=None):
    """Sign an IPA file using zsign"""
    try:
        # Prepare the command
        cmd = ['zsign']
        
        # Add certificate
        cmd.extend(['-k', str(cert_path)])
        
        # Add bundle ID if specified
        if bundle_id:
            cmd.extend(['-b', bundle_id])
        
        # Add output path (original name with _signed suffix)
        output_path = str(Path(ipa_path).with_stem(f"{Path(ipa_path).stem}_signed"))
        cmd.extend(['-o', output_path])
        
        # Add input IPA
        cmd.append(str(ipa_path))
        
        # Print the command being executed
        print(f"\nExecuting: {' '.join(cmd)}")
        
        # Execute zsign
        result = os.system(' '.join(cmd))
        
        if result == 0:
            print(f"\nSuccess! Signed IPA saved to: {output_path}")
            return True
        else:
            print("\nError: Signing failed!")
            return False
            
    except Exception as e:
        print(f"\nError: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Easy IPA Signer')
    parser.add_argument('ipa', nargs='?', help='Path to IPA file (optional)')
    parser.add_argument('-c', '--cert', help='Path to .p12 certificate (optional)')
    parser.add_argument('-b', '--bundle-id', help='New bundle ID (optional)')
    args = parser.parse_args()

    # Check for zsign
    if os.system('zsign -v') != 0:
        print("Error: zsign not found! Please make sure zsign is in your PATH")
        sys.exit(1)

    # Get IPA file
    ipa_path = args.ipa
    if not ipa_path:
        print("\nLooking for IPA files in current directory...")
        ipa_files = list(Path('.').glob('*.ipa'))
        if not ipa_files:
            print("No IPA files found!")
            return
        
        print("\nAvailable IPA files:")
        for i, ipa in enumerate(ipa_files, 1):
            print(f"{i}. {ipa.name}")
        
        while True:
            try:
                choice = int(input("\nSelect IPA number (or 0 to exit): "))
                if choice == 0:
                    return
                if 1 <= choice <= len(ipa_files):
                    ipa_path = ipa_files[choice - 1]
                    break
            except ValueError:
                pass
            print("Invalid selection. Please try again.")

    # Get certificate
    cert_path = args.cert
    if not cert_path:
        cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Cert')
        if os.path.exists(cert_dir):
            cert_path = find_certificates(cert_dir)
            if not cert_path:
                return
        else:
            print(f"Certificate directory not found: {cert_dir}")
            return

    # Get bundle ID
    bundle_id = args.bundle_id
    if not bundle_id:
        bundle_id = input("\nEnter new bundle ID (or press Enter to keep existing): ").strip()
        if not bundle_id:
            bundle_id = None

    # Sign the IPA
    print("\nSigning IPA file...")
    sign_ipa(ipa_path, cert_path, bundle_id)

if __name__ == "__main__":
    main()
