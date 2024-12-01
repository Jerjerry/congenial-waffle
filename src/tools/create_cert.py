from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

# Load private key
with open("development_key.key", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Generate certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Your Development Certificate"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Development"),
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
    x509.BasicConstraints(ca=True, path_length=None), critical=True
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
    critical=False
).add_extension(
    x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
    critical=False
).sign(private_key, hashes.SHA256())

# Write certificate
with open("development.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# Create PKCS12
p12 = serialization.pkcs12.serialize_key_and_certificates(
    name=b"iOS Development",
    key=private_key,
    cert=cert,
    cas=None,
    encryption_algorithm=serialization.NoEncryption()
)

# Write P12
with open("development.p12", "wb") as f:
    f.write(p12)
