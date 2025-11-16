# app/crypto/pki.py
import os
from typing import Tuple
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

DEFAULT_CA_CERT = os.path.join("certs", "ca.cert.pem")


def load_pem_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_pem_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def get_common_name(cert: x509.Certificate) -> str:
    try:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def verify_cert_against_ca(peer_cert_pem: bytes, expected_cn: str, ca_cert_path: str = DEFAULT_CA_CERT) -> Tuple[bool, str]:
    """
    Verify peer cert:
    - signature: signed by CA (CA public key verifies signature)
    - validity period
    - CN match expected_cn (exact match)
    Returns (ok, reason) where reason is 'OK' or error code like 'BAD_CERT', 'EXPIRED_CERT', 'UNTRUSTED_CA', 'CN_MISMATCH'
    """
    try:
        peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    except Exception as e:
        return False, f"BAD_CERT: parse error: {e}"

    # Load CA cert
    try:
        ca_cert = load_pem_cert(ca_cert_path)
    except Exception as e:
        return False, f"UNTRUSTED_CA: cannot load CA cert: {e}"

    # === FIXED: Handle timezone-aware and naive datetimes ===
    now = datetime.now(timezone.utc)

    # Use new UTC-aware properties if available (Cryptography >= 41)
    not_before = getattr(peer_cert, "not_valid_before_utc", peer_cert.not_valid_before_utc)
    not_after = getattr(peer_cert, "not_valid_after_utc", peer_cert.not_valid_after_utc)

    # Normalize to UTC if naive
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    # Check validity period
    if not_before > now or not_after < now:
        return False, "EXPIRED_CERT"

    # Check that peer_cert is signed by CA (verify signature)
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            signature=peer_cert.signature,
            data=peer_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"UNTRUSTED_CA: signature verification failed: {e}"

    # Check CN matches expected
    cn = get_common_name(peer_cert)
    if expected_cn and cn != expected_cn:
        return False, f"CN_MISMATCH: expected={expected_cn} got={cn}"

    return True, "OK"
