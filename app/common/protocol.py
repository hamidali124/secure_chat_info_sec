"""
Pydantic models for the control plane and auth messages.
for conversation between server and client


"""
from pydantic import BaseModel
from typing import Optional


class Hello(BaseModel):
	type: str = "hello"
	client_cert: Optional[str] = None
	nonce: Optional[str] = None


class ServerHello(BaseModel):
	type: str = "server hello"
	server_cert: Optional[str] = None
	nonce: Optional[str] = None
	# DH parameters (decimal strings) and server DH public (hex)
	dh_p: Optional[str] = None
	dh_g: Optional[str] = None
	server_dh_pub: Optional[str] = None


class DHClient(BaseModel):
	type: str = "dh_client"
	client_dh_pub: str


class EncMessage(BaseModel):
	type: str = "enc"
	payload: str


class Register(BaseModel):
	type: str = "register"
	email: str
	username: str
	pwd: str  # plaintext password; transported encrypted in the control plane


class Login(BaseModel):
	type: str = "login"
	email: str
	pwd: str  # plaintext password; transported encrypted
	nonce: Optional[str] = None


__all__ = ["Hello", "ServerHello", "DHClient", "EncMessage", "Register", "Login"]
