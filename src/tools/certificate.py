import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta

def generate_key_pair():
    """Generate RSA key pair."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def generate_certificate(private_key, common_name="Development"):
    """Generate a self-signed certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Development"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
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
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(private_key, hashes.SHA256())

    return cert

def generate_development_certificate(output_dir=".", password="development"):
    """Generate development certificate and key."""
    os.makedirs(output_dir, exist_ok=True)

    # Generate key pair
    private_key = generate_key_pair()

    # Generate certificate
    certificate = generate_certificate(private_key)

    # Save private key
    with open(os.path.join(output_dir, "development_key.key"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save certificate
    with open(os.path.join(output_dir, "development.crt"), "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # Create PKCS12
    if isinstance(password, str):
        password = password.encode()

    p12 = pkcs12.serialize_key_and_certificates(
        name=b"development",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open(os.path.join(output_dir, "development.p12"), "wb") as f:
        f.write(p12)

    return private_key, certificate

if __name__ == "__main__":
    generate_development_certificate()
