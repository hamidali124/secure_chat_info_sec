"""MySQL users table + salted hashing (no chat storage).

Provides a small UserDB wrapper around PyMySQL to create the users table,
add users, and verify credentials. Passwords are stored as hex(SHA256(salt||pwd)).
"""
import os
import pymysql
import hashlib
from typing import Optional, Tuple
from dotenv import load_dotenv


class UserDB:
	def __init__(self, host: str = None, port: int = None, user: str = None, password: str = None, db: str = None):
		load_dotenv()
		self.host = host or os.getenv("MYSQL_HOST", "127.0.0.1")
		self.port = int(port or os.getenv("MYSQL_PORT", "3306"))
		self.user = user or os.getenv("MYSQL_USER", "root")
		self.password = password or os.getenv("MYSQL_PASSWORD", "")
		self.db = db or os.getenv("MYSQL_DATABASE", "securechat")

	def _get_conn(self):
		return pymysql.connect(host=self.host, port=self.port, user=self.user, password=self.password, database=self.db, autocommit=True)

	def init_schema(self):
		"""Create users table if it does not exist."""
		with self._get_conn() as conn:
			with conn.cursor() as cur:
				cur.execute(
					"""
					CREATE TABLE IF NOT EXISTS users (
						email VARCHAR(255),
						username VARCHAR(255) UNIQUE,
						salt VARBINARY(16),
						pwd_hash CHAR(64),
						PRIMARY KEY (email)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
					"""
				)

	def add_user(self, email: str, username: str, salt: bytes, pwd_hash_hex: str) -> bool:
		"""Insert a new user. Returns True on success, False if duplicate.

		salt must be 16 bytes, pwd_hash_hex must be 64 hex chars.
		"""
		with self._get_conn() as conn:
			try:
				with conn.cursor() as cur:
					cur.execute(
						"INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
						(email, username, salt, pwd_hash_hex),
					)
				return True
			except pymysql.err.IntegrityError:
				return False

	def get_user(self, email: str) -> Optional[Tuple[str, str, bytes]]:
		"""Return (email, username, salt, pwd_hash) or None."""
		with self._get_conn() as conn:
			with conn.cursor() as cur:
				cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email=%s", (email,))
				row = cur.fetchone()
				if not row:
					return None
				return row  # (email, username, salt (bytes), pwd_hash)

	def verify_credentials(self, email: str, password: str) -> bool:
		"""Verify plaintext password for email. Returns True if matches."""
		row = self.get_user(email)
		if not row:
			return False
		_email, username, salt, pwd_hash = row
		computed = hashlib.sha256(salt + password.encode()).hexdigest()
		return computed == pwd_hash


__all__ = ["UserDB"]
