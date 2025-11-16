"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

#def now_ms(): raise NotImplementedError

#def b64e(b: bytes): raise NotImplementedError

#def b64d(s: str): raise NotImplementedError

#def sha256_hex(data: bytes): raise NotImplementedError


# app/common/utils.py
import json
import struct
import base64
from typing import Any
import os
import time

def now_ms() -> int:
    return int(time.time() * 1000)

def send_message(sock, obj: Any):
    data = json.dumps(obj).encode()
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)

def recv_message(sock):
    # read 4 bytes len
    import socket
    buf = b""
    while len(buf) < 4:
        chunk = sock.recv(4 - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    length = struct.unpack("!I", buf)[0]
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("connection closed")
        payload += chunk
    return json.loads(payload.decode())

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s)

# backward compatibility aliases (if other scripts used b64enc / b64dec)
b64enc = b64ef
b64dec = b64df
