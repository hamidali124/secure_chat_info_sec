
"""DH (Diffie-Hellman) helpers.

This module uses the cryptography library to generate parameters and keys,
serialize public values as big-endian integers (hex) and derive an AES-128
key as Trunc16(SHA256(Ks)).

Provided helpers:
 - generate_parameters() -> (p:int, g:int)
 - private_key_from_params(p,g) -> private key object
 - public_key_bytes(private_key) -> bytes (big-endian)
 - public_key_hex(private_key) -> hex string
 - peer_public_from_int(y_int, p, g) -> DHPublicKey
 - compute_shared_key(private_key, peer_public_key) -> raw shared bytes (Ks)
 - derive_aes_key(Ks) -> 16-byte AES key (Trunc16(SHA256(Ks)))
"""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import hashlib
from typing import Tuple


def generate_parameters(key_size: int = 512) -> Tuple[int, int]:
	"""Generate DH parameters and return (p, g) as integers.

	For testing we default to a smaller size (1024) to speed up parameter
	generation. For production use at least 2048-bit parameters or a
	standardized group.
	"""
	params = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
	nums = params.parameter_numbers()
	return nums.p, nums.g


def params_from_numbers(p: int, g: int):
	"""Return a DHParameters object constructed from p and g."""
	params_nums = dh.DHParameterNumbers(p, g)
	return params_nums.parameters(default_backend())


def private_key_from_params(p: int, g: int):
	params = params_from_numbers(p, g)
	return params.generate_private_key()


def public_key_bytes_from_private(private_key) -> bytes:
	"""Return the public value y as big-endian bytes."""
	y = private_key.public_key().public_numbers().y
	length = (y.bit_length() + 7) // 8
	return y.to_bytes(length, byteorder="big")


def public_key_hex_from_private(private_key) -> str:
	return public_key_bytes_from_private(private_key).hex()


def peer_public_from_int(y_int: int, p: int, g: int):
	params = params_from_numbers(p, g)
	pub_nums = dh.DHPublicNumbers(y_int, params.parameter_numbers())
	return pub_nums.public_key(default_backend())


def compute_shared_key(private_key, peer_public_key) -> bytes:
	"""Compute raw shared secret Ks (bytes) using private_key.exchange()."""
	return private_key.exchange(peer_public_key)


def derive_aes_key_from_shared(shared: bytes) -> bytes:
	"""Derive AES-128 key as Trunc16(SHA256(shared))."""
	h = hashlib.sha256(shared).digest()
	return h[:16]


__all__ = [
	"generate_parameters",
	"private_key_from_params",
	"public_key_bytes_from_private",
	"public_key_hex_from_private",
	"peer_public_from_int",
	"compute_shared_key",
	"derive_aes_key_from_shared",
	"params_from_numbers",
]

