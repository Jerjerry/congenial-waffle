from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime

# Generate key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Generate certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Test"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
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
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True
).sign(private_key, hashes.SHA256())

# Create PKCS12
p12 = pkcs12.serialize_key_and_certificates(
    name=b"test",
    key=private_key,
    cert=cert,
    cas=None,
    encryption_algorithm=serialization.NoEncryption()
)

# Write to file
with open("cert.p12", "wb") as f:
    f.write(p12)

print("Created test certificate: cert.p12")
