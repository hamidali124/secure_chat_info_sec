#!/usr/bin/env python3
# scripts/gen_cert.py
import argparse
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime
from datetime import timedelta
from cryptography import x509


CERTS_DIR = "certs"

def write_pem(path, data, mode=0o600):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)

def load_ca(ca_key_path, ca_cert_path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(ca_key_path, "rb") as f:
        cakey_pem = f.read()
    with open(ca_cert_path, "rb") as f:
        cacert_pem = f.read()

    ca_key = load_pem_private_key(cakey_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(cacert_pem)
    return ca_key, ca_cert

def main():
    parser = argparse.ArgumentParser(description="Issue a certificate signed by local CA.")
    parser.add_argument("--cn", required=True, help="Common Name (CN) for the new cert")
    parser.add_argument("--out", required=True, help="Output file prefix, e.g. certs/server")
    parser.add_argument("--ca-key", default=os.path.join(CERTS_DIR, "ca.key.pem"))
    parser.add_argument("--ca-cert", default=os.path.join(CERTS_DIR, "ca.cert.pem"))
    args = parser.parse_args()
    
    out_pub_path = f"{args.out}.pub.pem"
    out_key_path = f"{args.out}.key.pem"
    out_cert_path = f"{args.out}.cert.pem"
    
    os.makedirs(os.path.dirname(out_key_path) or ".", exist_ok=True)

    ca_key, ca_cert = load_ca(args.ca_key, args.ca_cert)

    # Generate RSA private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Export private key (PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export public key (PEM)
    pubkey_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Building a certificate
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    now = datetime.utcnow()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(args.cn)]),
            critical=False
        )
    )

    # Using Certificate Authority's key to sign the certificate
    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Export certificate (PEM)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    # Writing the files granting secure permissions
    write_pem(out_key_path, key_pem, mode=0o600)
    write_pem(out_cert_path, cert_pem, mode=0o644)
    write_pem(out_pub_path, pubkey_pem, mode=0o644)
    

    print(f"Private key Generated in the path: {out_key_path}")
    print(f"Public key Generated in the path: {out_pub_path}")
    print(f"Certificate Generated in the path: {out_cert_path}")

if __name__ == "__main__":
    main()
