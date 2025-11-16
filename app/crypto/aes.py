"""AES-128(ECB)+PKCS#7 helpers using the cryptography library.

Functions:
 - encrypt(key: bytes, plaintext: bytes) -> bytes
 - decrypt(key: bytes, ciphertext: bytes) -> bytes

Key must be 16 bytes (AES-128). Uses ECB mode as required by the assignment.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def _check_key(key: bytes) -> None:
	if not isinstance(key, (bytes, bytearray)):
		raise TypeError("key must be bytes")
	if len(key) != 16:
		raise ValueError("key must be 16 bytes (AES-128)")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
	"""Encrypt plaintext using AES-128-ECB with PKCS#7 padding.

	Returns raw ciphertext bytes.
	"""
	_check_key(key)
	if not isinstance(plaintext, (bytes, bytearray)):
		raise TypeError("plaintext must be bytes")

	padder = padding.PKCS7(128).padder()
	padded = padder.update(plaintext) + padder.finalize()

	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	encryptor = cipher.encryptor()
	ct = encryptor.update(padded) + encryptor.finalize()
	return ct


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
	"""Decrypt ciphertext (AES-128-ECB + PKCS#7) and return plaintext bytes.

	Raises ValueError on invalid padding.
	"""
	_check_key(key)
	if not isinstance(ciphertext, (bytes, bytearray)):
		raise TypeError("ciphertext must be bytes")

	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
	decryptor = cipher.decryptor()
	padded = decryptor.update(ciphertext) + decryptor.finalize()

	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(padded) + unpadder.finalize()
	return plaintext


__all__ = ["encrypt", "decrypt"]
