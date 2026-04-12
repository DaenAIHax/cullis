"""
Minimal broker-CA bootstrap for the demo network.

Generates a self-signed broker root CA (RSA-4096, 10y) at
/broker-certs/broker-ca.pem + broker-ca-key.pem, idempotent.
The broker container mounts this volume read-only.

Deliberately standalone — avoids pulling the full app package into the
init container, so this service has a tiny image and no app-code churn
risk.
"""
import datetime
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT = pathlib.Path("/broker-certs")
OUT.mkdir(parents=True, exist_ok=True)
KEY = OUT / "broker-ca-key.pem"
CRT = OUT / "broker-ca.pem"

if KEY.exists() and CRT.exists():
    print(f"broker-init: CA already present at {OUT}, skipping")
    sys.exit(0)

print("broker-init: generating broker root CA (RSA-4096)")
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Demo Broker CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cullis Demo"),
])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365 * 10))
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    .sign(key, hashes.SHA256())
)

KEY.write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
))
CRT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

# Broker runs as non-root 'appuser' — make files world-readable.
KEY.chmod(0o644)
CRT.chmod(0o644)

print(f"broker-init: wrote {CRT} + {KEY}")
