from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
from pathlib import Path

auth_dir = Path("./moppy/auth")
auth_dir.mkdir(parents=True, exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Certificate subject & issuer (self-signed)
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MOP"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

# Build certificate
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

try:
    with open("moppy/auth/private_key.pem", "xb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
except Exception:
    print("Private key already created")
try:
    with open("moppy/auth/certificate.pem", "xb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
except Exception:
    print("Certificate already created")