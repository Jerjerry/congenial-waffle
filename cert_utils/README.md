# iOS Certificate Generator

A utility for generating iOS development certificates and provisioning profiles for testing and development purposes.

## Features

- Generate self-signed certificates
- Create P12 files with optional password protection
- Generate provisioning profiles with custom entitlements
- Support for multiple device UDIDs
- User-friendly GUI interface

## Usage

1. Run the GUI:
   ```bash
   python gui.py
   ```

2. Fill in the required information:
   - Certificate Details:
     * Common Name (Your name)
     * Organization (default: iOS Developer)
     * Validity period in days
     * P12 password (optional)
   
   - Provisioning Profile Details:
     * App ID (e.g., com.example.app)
     * Team ID
     * Device UDIDs (one per line)
     * Custom entitlements (JSON format)

3. Click "Generate Certificate & Profile"

4. Find the generated files in the `generated_certs` directory:
   - `ios_developer.p12`: Your certificate
   - `[app_id].mobileprovision`: Your provisioning profile

## Requirements

```
cryptography>=41.0.0
tkinter
```

## Notes

- This is for development and testing purposes only
- Generated certificates are self-signed
- Provisioning profiles are for development use
- Real iOS app distribution requires official Apple certificates
