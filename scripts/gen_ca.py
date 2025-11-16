#!/usr/bin/env python3
# scripts/gen_ca.py
import argparse
import os

from datetime import timedelta
from datetime import timezone
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


CERTS_DIR = "certs"

def write_pem(path, data, mode=0o600):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)

def main():
    parser = argparse.ArgumentParser(description="Generate a root CA (RSA + self-signed X.509).")
    parser.add_argument("--name", required=True, help="CA common name (subject CN)")
    parser.add_argument("--out-dir", default=CERTS_DIR, help="Directory to write ca.* files")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    key_path = os.path.join(args.out_dir, "ca.key.pem")
    cert_path = os.path.join(args.out_dir, "ca.cert.pem")

    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=730))  # 365*2=2 Years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    write_pem(cert_path, cert_pem, mode=0o644)
    write_pem(key_path, key_pem, mode=0o600)
   

    print(f"Central Authority key Generated: {key_path}")
    print(f"Central Authority certificate Generated: {cert_path}")

if __name__ == "__main__":
    main()

