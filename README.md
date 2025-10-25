# IPA Signer

A cross-platform tool for signing and modifying iOS application binaries.

## Features

- Cross-platform support (Windows, macOS, Linux)
- Universal binary (fat binary) support
- Robust Mach-O binary parsing
- Certificate and provisioning profile validation
- Detailed error reporting and logging
- Special handling for complex frameworks and dylibs

## Requirements

- Python 3.11+
- cryptography library
- tkinter (for GUI features)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/jerjerry/ipa-signer.git
cd ipa-signer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
python -m src.enhanced_signer --ipa path/to/app.ipa --cert path/to/cert.p12 --profile path/to/profile.mobileprovision --output path/to/output.ipa
```

### Environment Variables

- `TEST_P12_PATH`: Path to test certificate
- `TEST_P12_PASS`: Certificate password
- `TEST_IPA_PATH`: Path to test IPA for signing

## Recent Updates

### Version 1.1.0
- Added robust universal binary support
- Improved Mach-O binary parsing with endianness detection
- Enhanced error handling for binary structures
- Added special handling for CydiaSubstrate and complex dylibs
- Improved logging and progress reporting

### Version 1.0.0
- Initial release with basic signing capabilities
- Certificate validation
- Provisioning profile support

## Technical Details

### Mach-O Binary Handling
- Automatic endianness detection
- Universal binary slice extraction
- Load command parsing and validation
- Section parsing with robust error handling
- Special case handling for complex binaries

### Security Features
- Certificate validation
- Provisioning profile compatibility checks
- Secure password handling
- Binary integrity verification

## Testing

Run the test suite:
```bash
python tests/run_real_test.py
```

Generate test IPA:
```bash
python tests/create_test_ipa.py
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Known Limitations

- Some complex frameworks require special handling
- Universal binary support is focused on ARM64 and x86_64
- Certificate must be in P12 format

## License

[MIT License](LICENSE)

## Acknowledgments

Thanks to the iOS development community for their insights into the code signing process.
