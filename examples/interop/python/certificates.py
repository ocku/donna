"""Generate ephemeral TLS fixtures; no private credentials enter the repository."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

directory = Path(os.environ.get("CERT_DIR", "/certs"))
directory.mkdir(parents=True, exist_ok=True)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name(
    [x509.NameAttribute(NameOID.COMMON_NAME, "Donna interoperability laboratory")]
)
now = datetime.now(timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(days=1))
    .not_valid_after(now + timedelta(days=2))
    .add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.DNSName("donna"), x509.DNSName("peers")]
        ),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
for encoding, extension in (
    (serialization.Encoding.PEM, "pem"),
    (serialization.Encoding.DER, "der"),
):
    (directory / f"cert.{extension}").write_bytes(cert.public_bytes(encoding))
    (directory / f"key.{extension}").write_bytes(
        key.private_bytes(
            encoding, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
print("Created ephemeral laboratory certificates")
