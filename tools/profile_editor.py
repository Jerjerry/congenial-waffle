import os
import plistlib
import datetime
import uuid
from pathlib import Path

class ProvisioningProfileEditor:
    def __init__(self):
        self.output_dir = 'modified_profiles'
        os.makedirs(self.output_dir, exist_ok=True)

    def read_profile(self, profile_path):
        """Read and parse provisioning profile"""
        with open(profile_path, 'rb') as f:
            profile_data = f.read()
            
        # Find start and end of plist data
        start = profile_data.find(b'<?xml')
        end = profile_data.find(b'</plist>') + 8
        
        if start == -1 or end == -1:
            raise ValueError("Invalid provisioning profile format")
            
        # Parse plist data
        plist_data = profile_data[start:end]
        return plistlib.loads(plist_data), profile_data[:start], profile_data[end:]

    def write_profile(self, profile_dict, prefix, suffix, output_path):
        """Write modified profile back to file"""
        # Convert profile dict to plist
        plist_data = plistlib.dumps(profile_dict)
        
        # Combine all parts
        output_data = prefix + plist_data + suffix
        
        # Write to file
        with open(output_path, 'wb') as f:
            f.write(output_data)

    def add_udid(self, profile_path, udid):
        """Add UDID to provisioning profile"""
        try:
            # Read profile
            profile_dict, prefix, suffix = self.read_profile(profile_path)
            
            # Get current devices
            devices = profile_dict.get('ProvisionedDevices', [])
            
            # Add new UDID if not present
            if udid not in devices:
                devices.append(udid)
                profile_dict['ProvisionedDevices'] = devices
                
                # Update UUID and dates
                profile_dict['UUID'] = str(uuid.uuid4()).upper()
                profile_dict['CreationDate'] = datetime.datetime.now()
                profile_dict['ExpirationDate'] = datetime.datetime.now() + datetime.timedelta(days=365)
                
                # Create output filename
                output_name = f"{Path(profile_path).stem}_modified.mobileprovision"
                output_path = os.path.join(self.output_dir, output_name)
                
                # Write modified profile
                self.write_profile(profile_dict, prefix, suffix, output_path)
                
                return True, output_path, {
                    'devices': devices,
                    'uuid': profile_dict['UUID'],
                    'creation_date': profile_dict['CreationDate'],
                    'expiration_date': profile_dict['ExpirationDate']
                }
            else:
                return False, None, "UDID already exists in profile"
                
        except Exception as e:
            return False, None, str(e)

    def update_entitlements(self, profile_path, entitlements):
        """Update entitlements in provisioning profile"""
        try:
            # Read profile
            profile_dict, prefix, suffix = self.read_profile(profile_path)
            
            # Update entitlements
            profile_dict['Entitlements'].update(entitlements)
            
            # Update UUID and dates
            profile_dict['UUID'] = str(uuid.uuid4()).upper()
            profile_dict['CreationDate'] = datetime.datetime.now()
            profile_dict['ExpirationDate'] = datetime.datetime.now() + datetime.timedelta(days=365)
            
            # Create output filename
            output_name = f"{Path(profile_path).stem}_modified.mobileprovision"
            output_path = os.path.join(self.output_dir, output_name)
            
            # Write modified profile
            self.write_profile(profile_dict, prefix, suffix, output_path)
            
            return True, output_path, {
                'entitlements': profile_dict['Entitlements'],
                'uuid': profile_dict['UUID'],
                'creation_date': profile_dict['CreationDate'],
                'expiration_date': profile_dict['ExpirationDate']
            }
            
        except Exception as e:
            return False, None, str(e)

def main():
    # Example usage
    editor = ProvisioningProfileEditor()
    
    # Add UDID
    profile_path = "path/to/profile.mobileprovision"
    udid = "00008110-000650C82651801E"
    
    if os.path.exists(profile_path):
        success, output_path, details = editor.add_udid(profile_path, udid)
        if success:
            print(f"Modified profile saved to: {output_path}")
            print("\nDetails:")
            print(f"Total devices: {len(details['devices'])}")
            print(f"New UUID: {details['uuid']}")
            print(f"Valid until: {details['expiration_date']}")
        else:
            print(f"Error: {details}")
            
    # Update entitlements
    entitlements = {
        "inter-app-audio": True,
        "com.apple.developer.networking.networkextension": [
            "app-proxy-provider",
            "content-filter-provider",
            "packet-tunnel-provider",
            "dns-proxy",
            "dns-settings",
            "relay"
        ],
        "application-identifier": "J4FUC525X9.anardoni.export.*",
        "keychain-access-groups": [
            "J4FUC525X9.*",
            "com.apple.token"
        ],
        "get-task-allow": False,
        "com.apple.developer.team-identifier": "J4FUC525X9"
    }
    
    success, output_path, details = editor.update_entitlements(profile_path, entitlements)
    if success:
        print(f"\nUpdated profile saved to: {output_path}")
        print("\nNew entitlements applied")

if __name__ == "__main__":
    main()
