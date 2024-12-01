# IPA Signer

A simple GUI tool to sign iOS IPA files with your certificates.

## Requirements

1. Python 3.6 or higher
2. zsign (download from https://github.com/zhlynn/zsign/releases and place in the same directory)
3. The required Python packages (install using `pip install -r requirements.txt`)

## Setup

1. Download zsign for Windows from the releases page
2. Rename the downloaded exe to `zsign.exe` and place it in this directory
3. Install the Python requirements:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the program:
   ```
   python ipa_signer.py
   ```

2. In the GUI:
   - Select your IPA file
   - Select your .p12 certificate
   - Choose an output directory
   - Enter the bundle ID (e.g., com.example.app)
   - Click "Sign IPA"

3. The signed IPA will be saved in your chosen output directory with "_signed" added to the filename.

## Notes

- The certificates don't require passwords (leave empty if prompted)
- Make sure your IPA file is a valid iOS application
- The bundle ID should match the format: com.company.appname
- Keep your certificates secure and don't share them

## Troubleshooting

If you encounter any errors:
1. Make sure zsign.exe is in the same directory as the script
2. Verify that your .p12 certificate is valid
3. Check that the IPA file is not corrupted
4. Ensure you have write permissions in the output directory
