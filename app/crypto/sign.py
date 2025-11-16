"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 

"""RSA PKCS#1 v1.5 SHA-256 sign/verify helpers.

Simple wrappers around cryptography's sign/verify using PKCS1v15 and SHA256.
"""
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def sign_bytes(private_key, data: bytes) -> bytes:
	"""Sign data with a private key (private_key can be a loaded key object).

	Returns raw signature bytes.
	"""
	return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
	"""Verify signature; returns True if valid, False otherwise."""
	try:
		public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
		return True
	except Exception:
		return False


def load_private_key(pem_bytes: bytes):
	return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())


def load_public_key(pem_bytes: bytes):
	return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


__all__ = ["sign_bytes", "verify_signature", "load_private_key", "load_public_key"]

