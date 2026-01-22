from cryptography import x509 # pyright: ignore[reportMissingImports]
from cryptography.x509.oid import NameOID # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives import hashes, serialization # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.asymmetric import ec # pyright: ignore[reportMissingImports]
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress
from colorama import Fore, Back, Style, init  # pyright: ignore[reportMissingModuleSource] # noqa: F401

init(autoreset=True)

CERT_DIR = Path("./moppy/certs")
KEY_PATH = CERT_DIR / "key.pem"
CERT_PATH = CERT_DIR / "cert.pem"
VALID_DAYS = 365


def cert_is_valid(path: Path) -> bool:
    if not path.exists():
        return False

    cert = x509.load_pem_x509_certificate(path.read_bytes())
    return cert.not_valid_after > datetime.now(timezone.utc)


def generate_cert(domains: list[str]):
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Generate ECDSA private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    san_entries: list[x509.GeneralName] = []

    for d in domains:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(d)))
        except ValueError:
            san_entries.append(x509.DNSName(d))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Moppy"),
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=VALID_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{Fore.GREEN}INFO{Fore.RESET}:      ECDSA SSL certificate generated")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:      Key:  {KEY_PATH}")
    print(f"{Fore.GREEN}INFO{Fore.RESET}:      Cert: {CERT_PATH}")


def main():
    if cert_is_valid(CERT_PATH):
        print(f"{Fore.GREEN}INFO{Fore.RESET}:      Existing certificate is still valid")
        return

    print(f"{Fore.GREEN}INFO{Fore.RESET}:      Generating new certificate")

    domain = input("Primary domain (e.g. example.com): ").strip()
    extra = input(
        "Extra SANs (comma-separated, optional): "
    ).strip()

    domains = ["127.0.0.1", "localhost", domain]

    if extra:
        domains.extend(d.strip() for d in extra.split(","))

    # Deduplicate
    domains = list(dict.fromkeys(domains))

    generate_cert(domains)


if __name__ == "__main__":
    main()
