import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import uuid
import plistlib

class CertificateGenerator:
    def __init__(self):
        self.output_dir = 'generated_certs'
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_key_pair(self):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key
        
    def generate_certificate(self, private_key, common_name, org_name="Developer", valid_days=365):
        """Generate a self-signed certificate"""
        # Generate public key
        public_key = private_key.public_key()
        
        # Certificate builder
        builder = x509.CertificateBuilder()
        
        # Set serial number
        builder = builder.serial_number(x509.random_serial_number())
        
        # Set subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])
        builder = builder.subject_name(subject)
        
        # Set issuer (same as subject for self-signed)
        builder = builder.issuer_name(subject)
        
        # Set validity period
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
        )
        
        # Set public key
        builder = builder.public_key(public_key)
        
        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        
        # Sign the certificate
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256()
        )
        
        return certificate
        
    def export_p12(self, private_key, certificate, filename, password=None):
        """Export certificate and private key as P12"""
        p12_path = os.path.join(self.output_dir, f"{filename}.p12")
        
        # Convert password to bytes
        if password:
            password = password.encode()
        else:
            password = b''
            
        # Create P12
        p12 = pkcs12.serialize_key_and_certificates(
            name=b"iOS Developer",
            key=private_key,
            cert=certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        
        # Write P12 file
        with open(p12_path, 'wb') as f:
            f.write(p12)
            
        return p12_path
        
    def generate_provisioning_profile(self, app_id, team_id, certificates, devices=None, entitlements=None):
        """Generate a provisioning profile"""
        profile = {
            'AppIDName': app_id,
            'ApplicationIdentifierPrefix': [team_id],
            'CreationDate': datetime.datetime.utcnow(),
            'Platform': ['iOS'],
            'DeveloperCertificates': [
                cert.public_bytes(serialization.Encoding.DER)
                for cert in certificates
            ],
            'Entitlements': entitlements or {
                'application-identifier': f'{team_id}.{app_id}',
                'get-task-allow': True,
                'keychain-access-groups': [f'{team_id}.*'],
                'com.apple.developer.team-identifier': team_id
            },
            'ExpirationDate': datetime.datetime.utcnow() + datetime.timedelta(days=365),
            'Name': f'{app_id} Development Profile',
            'ProvisionedDevices': devices or [],
            'TeamIdentifier': [team_id],
            'TeamName': 'iOS Developer',
            'TimeToLive': 365,
            'UUID': str(uuid.uuid4()).upper(),
            'Version': 1
        }
        
        # Write provisioning profile
        profile_path = os.path.join(self.output_dir, f"{app_id}.mobileprovision")
        with open(profile_path, 'wb') as f:
            plistlib.dump(profile, f)
            
        return profile_path
        
def main():
    generator = CertificateGenerator()
    
    # Generate key pair
    private_key = generator.generate_key_pair()
    
    # Generate certificate
    certificate = generator.generate_certificate(
        private_key,
        common_name="Your Name",
        org_name="iOS Developer",
        valid_days=365
    )
    
    # Export P12
    p12_path = generator.export_p12(
        private_key,
        certificate,
        "ios_developer",
        password="your_password"
    )
    print(f"Generated P12 certificate: {p12_path}")
    
    # Generate provisioning profile
    profile_path = generator.generate_provisioning_profile(
        app_id="com.example.app",
        team_id="ABCDE12345",
        certificates=[certificate],
        devices=["device-udid-1", "device-udid-2"],
        entitlements={
            'application-identifier': 'ABCDE12345.com.example.app',
            'get-task-allow': True,
            'keychain-access-groups': ['ABCDE12345.*'],
            'com.apple.developer.team-identifier': 'ABCDE12345'
        }
    )
    print(f"Generated provisioning profile: {profile_path}")

if __name__ == "__main__":
    main()
