# IPA Signer Tool

A cross-platform GUI application for signing iOS IPA files. This tool provides a simple and user-friendly interface for signing iOS applications with custom certificates.

![IPA Signer Screenshot](docs/screenshot.png)

## Features

- User-friendly graphical interface
- Support for .p12 certificate files
- Password-protected certificate support
- Automatic code signing and IPA packaging
- Detailed logging for troubleshooting
- Cross-platform compatibility (Windows, macOS, Linux)

## Installation

1. Download the latest release from the [Releases](https://github.com/yourusername/ipa_signer/releases) page
2. Extract the archive to your desired location
3. Run `IPA_Signer.exe` (Windows) or `IPA_Signer` (macOS/Linux)

### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ipa_signer.git
   cd ipa_signer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Build the executable:
   ```bash
   python build_exe.py
   ```

The executable will be created in the `dist` directory.

## Usage

1. Launch the IPA Signer application
2. Click "Browse" to select your IPA file
3. Click "Browse" to select your P12 certificate
4. Enter the certificate password (if required)
5. Click "Sign IPA" to begin the signing process
6. The signed IPA will be created with "_signed" appended to the original filename

## Project Structure

```
ipa_signer/
├── gui_app.py           # Main GUI application
├── build_exe.py         # PyInstaller build script
├── requirements.txt     # Python dependencies
├── tools/
│   ├── pysign.py       # Core signing functionality
│   └── macho/          # Mach-O binary handling
│       ├── codesign.py # Code signature generation
│       ├── parser.py   # Binary parsing
│       └── structures.py # Data structures
└── docs/               # Documentation
```

## Dependencies

- Python 3.11+
- tkinter
- cryptography
- PyInstaller (for building)

## Logging

The application logs all operations to `signer.log` in the application directory. This file is useful for troubleshooting any issues that may occur during the signing process.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [cryptography](https://github.com/pyca/cryptography) for certificate handling
- [PyInstaller](https://www.pyinstaller.org/) for executable creation

## Support

If you encounter any issues or have questions, please:

1. Check the log file (`signer.log`)
2. Open an issue in the GitHub repository
3. Provide the log file and steps to reproduce the issue

## Disclaimer

This tool is provided as-is without any warranty. Always ensure you have the right to modify and sign iOS applications in your jurisdiction.