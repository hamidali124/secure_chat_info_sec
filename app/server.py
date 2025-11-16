import socket
import os
import json
import base64
import hashlib
from common.utils import send_message, recv_message
from crypto import pki
from crypto import sign as crypto_sign
import struct
from crypto import dh as crypto_dh
from crypto import aes as crypto_aes
from storage.transcript import append_transcript_entry, create_session_receipt, compute_cert_fingerprint
from storage.db import UserDB
from dotenv import load_dotenv
load_dotenv()

CERT_PATH = os.getenv("SERVER_CERT", "certs/server.cert.pem")
KEY_PATH = os.getenv("SERVER_KEY", "certs/server.key.pem")
EXPECTED_CLIENT_CN = os.getenv("EXPECTED_CLIENT_CN", "client.local")
CA_CERT = os.getenv("CA_CERT", "certs/ca.cert.pem")

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SERVER_PORT", "9000"))


def load_cert_pem(path):
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------
# 1) CERTIFICATE CHECKING FUNCTION
# ------------------------------------------------------------
def certificate_check(conn):
    msg = recv_message(conn)
    if not isinstance(msg, dict) or msg.get("type") != "hello":
        return None

    client_cert_pem = msg["client cert"].encode()

    ok, reason = pki.verify_cert_against_ca(
        client_cert_pem, EXPECTED_CLIENT_CN, ca_cert_path=CA_CERT
    )
    if not ok:
        send_message(conn, {"type": "error", "reason": reason})
        return None

    print("Client certificate verified OK")
    # Save client's cert locally for later signature verification
    try:
        os.makedirs("certs", exist_ok=True)
        with open(os.path.join("certs", "peer_client.cert.pem"), "wb") as f:
            f.write(client_cert_pem)
    except Exception:
        pass

    server_cert_pem = load_cert_pem(CERT_PATH)
    server_nonce = str(os.urandom(16).hex())

    send_message(conn, {
        "type": "server hello",
        "server cert": server_cert_pem.decode(),
        "nonce": server_nonce
    })

    ack = recv_message(conn)
    if not isinstance(ack, dict) or ack.get("type") != "ok":
        print("Client did not acknowledge server cert")
        return None

    # also save our sent cert? (optional)
    try:
        with open(os.path.join("certs", "self_server.cert.pem"), "wb") as f:
            f.write(server_cert_pem)
    except Exception:
        pass

    return client_cert_pem


# ------------------------------------------------------------
# 2) REGISTER/LOGIN CONTROL LOOP FUNCTION
# ------------------------------------------------------------
def control_loop(conn, db):
    while True:
        # fresh DH params
        p, g = crypto_dh.generate_parameters()
        print("Generated DH params p size:", p.bit_length())
        server_priv = crypto_dh.private_key_from_params(p, g)
        server_pub_hex = crypto_dh.public_key_hex_from_private(server_priv)

        send_message(conn, {
            "type": "server hello",
            "nonce": str(os.urandom(16).hex()),
            "dh_p": str(p),
            "dh_g": str(g),
            "server_dh_pub": server_pub_hex
        })

        msg2 = recv_message(conn)
        if not isinstance(msg2, dict) or msg2.get("type") != "dh_client":
            return None

        client_pub_int = int(msg2["client_dh_pub"], 16)
        client_pub = crypto_dh.peer_public_from_int(client_pub_int, p, g)

        shared = crypto_dh.compute_shared_key(server_priv, client_pub)
        aes_key = crypto_dh.derive_aes_key_from_shared(shared)

        # get encrypted payload
        enc = recv_message(conn)
        if not isinstance(enc, dict) or enc.get("type") != "enc":
            return None

        try:
            ct = base64.b64decode(enc["payload"])
            data = json.loads(crypto_aes.decrypt(aes_key, ct).decode())
        except Exception:
            send_message(conn, {"type": "error", "reason": "BAD_PAYLOAD"})
            continue

        # REGISTER
        if data.get("type") == "register":
            email = data.get("email")
            username = data.get("username")
            pwd = data.get("pwd")

            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + pwd.encode()).hexdigest()

            ok = db.add_user(email, username, salt, pwd_hash)
            if not ok:
                send_message(conn, {"type": "error", "reason": "DUPLICATE_USER"})
                continue

            send_message(conn, {"type": "ok"})
            continue

        # LOGIN
        if data.get("type") == "login":
            if not db.verify_credentials(data.get("email"), data.get("pwd")):
                send_message(conn, {"type": "error", "reason": "INVALID_CREDENTIALS"})
                continue

            send_message(conn, {"type": "ok"})
            return {"type": "chat ready"}


# ------------------------------------------------------------
# 3) CHAT LOOP (DH KEY ESTABLISHMENT)
# ------------------------------------------------------------
def chat_loop(conn):
    # fresh DH params
    p, g = crypto_dh.generate_parameters()
    print("Generated DH params p size:", p.bit_length())

    server_priv = crypto_dh.private_key_from_params(p, g)
    server_pub_hex = crypto_dh.public_key_hex_from_private(server_priv)

    send_message(conn, {
        "type": "server hello",
        "nonce": str(os.urandom(16).hex()),
        "dh_p": str(p),
        "dh_g": str(g),
        "server_dh_pub": server_pub_hex
    })

    msg2 = recv_message(conn)

    if not isinstance(msg2, dict) or msg2.get("type") != "dh_client":
        return None

    client_pub_int = int(msg2["client_dh_pub"], 16)
    client_pub = crypto_dh.peer_public_from_int(client_pub_int, p, g)
    shared = crypto_dh.compute_shared_key(server_priv, client_pub)
    session_key = crypto_dh.derive_aes_key_from_shared(shared)

    print("Chat session key established:", len(session_key), "bytes")

    # Load peer public key from saved client cert
    peer_cert_path = os.path.join("certs", "peer_client.cert.pem")
    try:
        peer_cert = pki.load_pem_cert(peer_cert_path)
        peer_pub = peer_cert.public_key()
    except Exception:
        peer_pub = None

    # Load our private key for signing
    try:
        our_priv = pki.load_pem_key(KEY_PATH)
    except Exception:
        our_priv = None

    # message exchange loop: receive from client, verify, decrypt, reply
    expected_seq = 1
    our_seq = 0
    from common.utils import now_ms

    while True:
        msg = recv_message(conn)
        if not isinstance(msg, dict) or msg.get("type") != "msg":
            send_message(conn, {"type": "error", "reason": "BAD_MSG_FORMAT"})
            continue

        seqno = int(msg.get("seqno", 0))
        ts = int(msg.get("ts", 0))
        ct = base64.b64decode(msg.get("ct", ""))
        sig = base64.b64decode(msg.get("sig", ""))

        # freshness checks
        now = now_ms()
        if seqno != expected_seq:
            send_message(conn, {"type": "error", "reason": "BAD_SEQ"})
            print({"type": "error", "reason": "BAD_SEQ"})
            continue
        if abs(now - ts) > 120000:  # 2 minutes
            send_message(conn, {"type": "error", "reason": "STALE_TS"})
            print({"type": "error", "reason": "STALE_TS"})
            continue

        # verify signature
        verified = False
        if peer_pub is not None:
            try:
                verified = crypto_sign.verify_signature(peer_pub, sig, struct.pack("!Q", seqno) + struct.pack("!Q", ts) + ct)
            except Exception:
                verified = False

        if not verified:
            send_message(conn, {"type": "error", "reason": "BAD_SIG"})
            continue

        # decrypt
        try:
            pt = crypto_aes.decrypt(session_key, ct).decode()
        except Exception:
            send_message(conn, {"type": "error", "reason": "BAD_CIPHER"})
            continue

        # Append the received (peer) message to our transcript for non-repudiation
        try:
            peer_cert_path = os.path.join("certs", "peer_client.cert.pem")
            fingerprint = compute_cert_fingerprint(peer_cert_path)
        except Exception:
            fingerprint = ""

        try:
            _transcript_dir = os.path.join("transcripts")
            os.makedirs(_transcript_dir, exist_ok=True)
            transcript_path = os.path.join(_transcript_dir, "server.txt")
            append_transcript_entry(transcript_path, seqno, ts, ct, sig, fingerprint, side="recv")
        except Exception:
            # do not fail the chat if transcript append fails
            pass

        print(f"[client] {seqno} @ {ts}: {pt}")

        # If client says exit, break after replying
        reply_text = "ACK"
        if pt.strip().lower() == "exit":
            reply_text = "Goodbye"

        # send reply
        our_seq += 1
        rts = now_ms()
        rct = crypto_aes.encrypt(session_key, reply_text.encode())
        rdata = struct.pack("!Q", our_seq) + struct.pack("!Q", rts) + rct
        if our_priv is not None:
            rsig = crypto_sign.sign_bytes(our_priv, rdata)
        else:
            rsig = b""

        # Append our SENT reply to the transcript (so transcript contains both sides)
        try:
            peer_cert_path = os.path.join("certs", "peer_client.cert.pem")
            fingerprint = compute_cert_fingerprint(peer_cert_path)
        except Exception:
            fingerprint = ""
        try:
            _transcript_dir = os.path.join("transcripts")
            os.makedirs(_transcript_dir, exist_ok=True)
            transcript_path = os.path.join(_transcript_dir, "server.txt")
            append_transcript_entry(transcript_path, our_seq, rts, rct, rsig, fingerprint, side="sent")
        except Exception:
            pass

        send_message(conn, {"type": "msg", "seqno": our_seq, "ts": rts, "ct": base64.b64encode(rct).decode(), "sig": base64.b64encode(rsig).decode()})

        expected_seq += 1

        if pt.strip().lower() == "exit":
            break

    # Chat finished — create a signed receipt over our transcript
    try:
        transcript_path = os.path.join("transcripts", "server.txt")
        # messages from client were numbered starting at 1; expected_seq was incremented
        last_seq = expected_seq - 1
        receipt_path = create_session_receipt(transcript_path, KEY_PATH, "server", 1 if last_seq >= 1 else None, last_seq if last_seq >= 1 else None)
        print("Wrote server receipt:", receipt_path)
    except Exception:
        pass

    return session_key


# ------------------------------------------------------------
# HANDLE CONNECTION
# ------------------------------------------------------------
def handle_connection(conn, addr):
    print("Connection from", addr)

    client_cert = certificate_check(conn)
    if not client_cert:
        conn.close()
        return

    db = UserDB()
    db.init_schema()

    ret = control_loop(conn, db)
    if not ret:
        conn.close()
        return

    chat_loop(conn)
    print("Control plane complete.")


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
def main():
    print("Server running on", HOST, PORT)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)


if __name__ == "__main__":
    main()
