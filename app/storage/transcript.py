"""Append-only transcript + TranscriptHash and SessionReceipt helpers.

This module provides helper functions used by the client and server to
maintain an append-only transcript of messages, compute a transcript SHA256
over the concatenation of transcript lines, sign the transcript hash to
produce a SessionReceipt, and verify receipts offline.

Transcript file format (one line per message):
	seqno|timestamp|base64(ciphertext)|base64(sig)|peer-cert-fingerprint\n
where the pipe character '|' is a literal separator. The transcript hash is
SHA256 over the exact bytes of the concatenation of all lines as written to
the file (including newlines). This ensures any modification to the file
changes the hash and invalidates the receipt signature.
"""

import os
import json
import base64
import hashlib
from typing import Optional, Tuple
from datetime import datetime

from crypto import pki
from crypto import sign as crypto_sign


def _ensure_dir(path: str) -> None:
	os.makedirs(path, exist_ok=True)


def b64(data: bytes) -> str:
	return base64.b64encode(data).decode()


def ub64(s: str) -> bytes:
	return base64.b64decode(s)


def append_transcript_entry(transcript_path: str, seqno: int, timestamp_ms: int,
							ciphertext: bytes, sig: bytes,
							peer_cert_fingerprint: str, side: str = "recv") -> None:
	"""Append a single transcript line to transcript_path.

	The function writes a single line using the canonical format described
	above. It opens the file in append mode and flushes immediately.
	"""
	_ensure_dir(os.path.dirname(transcript_path) or ".")
	# Format: seqno|timestamp|side|base64(ct)|base64(sig)|peer-cert-fingerprint\n
	line = (
		f"{int(seqno)}|{int(timestamp_ms)}|{side}|{b64(ciphertext)}|{b64(sig)}|{peer_cert_fingerprint}\n"
	)
	with open(transcript_path, "a", encoding="utf-8") as f:
		f.write(line)
		f.flush()


def read_transcript_bytes(transcript_path: str) -> bytes:
	"""Return the exact bytes of the transcript file (UTF-8 encoding).

	If the file does not exist an empty byte-string is returned (empty
	transcript case).
	"""
	if not os.path.exists(transcript_path):
		return b""
	with open(transcript_path, "rb") as f:
		return f.read()


def compute_transcript_hash_hex(transcript_path: str) -> str:
	"""Compute SHA256 hex digest over the concatenation of all transcript lines.

	Returns the hex string (lowercase, 64 chars). For an empty transcript the
	SHA256 of empty bytes is returned.
	"""
	data = read_transcript_bytes(transcript_path)
	return hashlib.sha256(data).hexdigest()


def compute_cert_fingerprint(cert_pem_path: str) -> str:
	"""Compute a stable fingerprint for a PEM cert.

	We use SHA256 over the PEM bytes. This is deterministic and easy to
	reproduce during offline verification; callers may use certificate DER
	if preferred, but using PEM keeps the implementation simple.
	"""
	with open(cert_pem_path, "rb") as f:
		pem = f.read()
	return hashlib.sha256(pem).hexdigest()


def parse_transcript_lines(transcript_path: str):
	"""Parse transcript lines into a list of dicts.

	Each entry is a dict with keys: seqno (int), ts (int), side (str), ct (bytes), sig (bytes), fingerprint (str)
	"""
	entries = []
	if not os.path.exists(transcript_path):
		return entries
	with open(transcript_path, "r", encoding="utf-8") as f:
		for ln in f:
			ln = ln.rstrip("\n")
			if not ln:
				continue
			# split into 6 parts max
			parts = ln.split("|", 5)
			if len(parts) != 6:
				# malformed line — skip
				continue
			seq_s, ts_s, side, ct_b64, sig_b64, fp = parts
			try:
				seq = int(seq_s)
				ts = int(ts_s)
				ct = ub64(ct_b64)
				sig = ub64(sig_b64)
			except Exception:
				continue
			entries.append({
				"seqno": seq,
				"ts": ts,
				"side": side,
				"ct": ct,
				"sig": sig,
				"fingerprint": fp,
			})
	return entries


def get_first_last_seq(transcript_path: str) -> Tuple[Optional[int], Optional[int]]:
	entries = parse_transcript_lines(transcript_path)
	if not entries:
		return None, None
	seqs = [e["seqno"] for e in entries]
	return min(seqs), max(seqs)


def create_session_receipt(transcript_path: str, private_key_path: str,
						   peer_label: str, first_seq: Optional[int],
						   last_seq: Optional[int], out_dir: str = "receipts") -> str:
	"""Create a SessionReceipt JSON file signed with the given private key.

	The receipt file is saved under `out_dir` and the path is returned.
	The signature is computed over the raw transcript SHA256 digest bytes
	(not over the hex string), but the JSON contains the hex string for easy
	display and comparison.
	"""
	_ensure_dir(out_dir)

	thash_hex = compute_transcript_hash_hex(transcript_path)
	thash_bytes = bytes.fromhex(thash_hex)

	# Load signing key
	priv = pki.load_pem_key(private_key_path)
	sig = crypto_sign.sign_bytes(priv, thash_bytes)

	receipt = {
		"type": "receipt",
		"peer": peer_label,
		"first seq": first_seq,
		"last seq": last_seq,
		"transcript sha256": thash_hex,
		"sig": b64(sig),
	}

	# If first/last not provided, compute from transcript
	if first_seq is None or last_seq is None:
		fseq, lseq = get_first_last_seq(transcript_path)
		if first_seq is None:
			first_seq = fseq
		if last_seq is None:
			last_seq = lseq

	ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
	fname = f"receipt_{peer_label}_{first_seq or '0'}_{last_seq or '0'}_{ts}.json"
	out_path = os.path.join(out_dir, fname)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(receipt, f, indent=2, sort_keys=True)
		f.write("\n")

	return out_path


def verify_session_receipt(receipt_path: str, transcript_path: str,
						   peer_cert_path: Optional[str] = None) -> Tuple[bool, str]:
	"""Verify a receipt against a local transcript file and (optionally) a peer cert.

	Returns (ok, message). Steps:
	  - parse receipt JSON
	  - compute transcript hash and compare with receipt["transcript sha256"]
	  - if peer_cert_path provided, extract public key and verify the signature
		over the binary digest bytes. If peer_cert_path is not provided the
		function will only validate the transcript hash match.
	"""
	if not os.path.exists(receipt_path):
		return False, f"receipt not found: {receipt_path}"

	with open(receipt_path, "r", encoding="utf-8") as f:
		receipt = json.load(f)

	if receipt.get("type") != "receipt":
		return False, "invalid receipt type"

	expected_thash = receipt.get("transcript sha256")
	if expected_thash is None:
		return False, "receipt missing transcript sha256"

	actual_thash = compute_transcript_hash_hex(transcript_path)
	if actual_thash != expected_thash:
		return False, "transcript hash mismatch: transcript was modified"

	# If no peer cert provided we stop here (we validated transcript integrity)
	if not peer_cert_path:
		return True, "transcript matches receipt (no signature verification performed)"

	# verify signature
	sig_b64 = receipt.get("sig", "")
	try:
		sig = ub64(sig_b64)
	except Exception:
		return False, "invalid base64 signature in receipt"

	try:
		cert = pki.load_pem_cert(peer_cert_path)
		pub = cert.public_key()
	except Exception as e:
		return False, f"failed to load peer cert: {e}"

	try:
		ok = crypto_sign.verify_signature(pub, sig, bytes.fromhex(actual_thash))
	except Exception:
		ok = False

	if not ok:
		return False, "signature verification failed"

	return True, "receipt signature valid and transcript matches"


if __name__ == "__main__":
	# Small CLI to create or verify receipts
	import argparse

	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest="cmd")

	c = sub.add_parser("create", help="create a signed receipt for a transcript")
	c.add_argument("transcript", help="path to transcript file")
	c.add_argument("privkey", help="path to PEM private key to sign receipt")
	c.add_argument("peer", help="peer label (client|server)")
	c.add_argument("--first", type=int, default=None, help="first seqno")
	c.add_argument("--last", type=int, default=None, help="last seqno")
	c.add_argument("--outdir", default="receipts", help="output dir for receipt")

	v = sub.add_parser("verify", help="verify a receipt against a transcript and peer cert")
	v.add_argument("receipt", help="path to receipt json")
	v.add_argument("transcript", help="path to transcript file")
	v.add_argument("--peercert", help="path to peer certificate PEM for signature verification")

	args = p.parse_args()
	if args.cmd == "create":
		out = create_session_receipt(args.transcript, args.privkey, args.peer, args.first, args.last, args.outdir)
		print("Wrote receipt:", out)
	elif args.cmd == "verify":
		ok, msg = verify_session_receipt(args.receipt, args.transcript, args.peercert)
		print(ok, msg)
	else:
		p.print_help()

