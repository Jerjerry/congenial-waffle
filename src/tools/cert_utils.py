from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

def generate_self_signed_cert(common_name, validity_days=365):
    """Generate a self-signed certificate and private key."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IPA Signer"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(private_key, hashes.SHA256())

    # Export as PKCS12
    p12 = serialization.pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption()
    )

    return cert, p12

def load_p12_cert(p12_path, password):
    """Load a P12 certificate from file."""
    with open(p12_path, 'rb') as f:
        p12_data = f.read()
    
    try:
        # First try with provided password
        if password:
            private_key, certificate, _ = serialization.pkcs12.load_key_and_certificates(
                p12_data,
                password.encode()
            )
        else:
            # Try with empty password
            private_key, certificate, _ = serialization.pkcs12.load_key_and_certificates(
                p12_data,
                b''
            )
        
        return private_key, certificate
    except Exception as e:
        # If both attempts fail, raise the error
        raise ValueError(f"Failed to load certificate. Please check if the password is correct. Error: {str(e)}")
