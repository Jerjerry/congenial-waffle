import os
import sys
from pysign import IPASigner

def test_signing():
    # Test parameters
    ipa_path = "test.ipa"  # Replace with your test IPA
    p12_path = "test.p12"  # Replace with your test certificate
    output_path = "signed_test.ipa"
    
    # Optional parameters
    options = {
        'password': None,  # Add if your certificate has a password
        'bundle_id': 'com.test.app',
        'bundle_name': 'Test App',
        'dylib_path': None,  # Add path to test dylib if needed
        'weak_dylib': False
    }
    
    # Create signer instance
    signer = IPASigner()
    
    try:
        # Test certificate loading
        print("Testing certificate loading...")
        private_key, certificate = signer.load_p12(p12_path, options['password'])
        print("✓ Certificate loaded successfully")
        
        # Test IPA extraction
        print("\nTesting IPA extraction...")
        app_dir = signer.extract_ipa(ipa_path)
        print(f"✓ IPA extracted to: {app_dir}")
        
        # Test Info.plist modification
        print("\nTesting Info.plist modification...")
        signer.update_info_plist(options['bundle_id'], options['bundle_name'])
        print("✓ Info.plist updated successfully")
        
        # Test binary signing
        print("\nTesting binary signing...")
        executable = os.path.join(app_dir, "YourApp")  # Replace with actual executable name
        signer.sign_binary(executable, private_key, certificate)
        print("✓ Binary signed successfully")
        
        if options['dylib_path']:
            print("\nTesting dylib injection...")
            signer.inject_dylib(executable, options['dylib_path'], options['weak_dylib'])
            print("✓ Dylib injected successfully")
            
        # Test IPA creation
        print("\nTesting IPA creation...")
        signer.create_signed_ipa(output_path)
        print(f"✓ Signed IPA created at: {output_path}")
        
        print("\nAll tests passed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
    finally:
        signer.cleanup()
        
if __name__ == "__main__":
    test_signing()
