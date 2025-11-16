import socket
import os
import json
import base64

from crypto import pki
from crypto import dh as crypto_dh
from crypto import aes as crypto_aes
from crypto import sign as crypto_sign
from common.utils import send_message
from common.utils import recv_message
import struct
from dotenv import load_dotenv
load_dotenv()
from storage.transcript import append_transcript_entry, create_session_receipt, compute_cert_fingerprint

CERT_PATH = os.getenv("CLIENT_CERT", "certs/client.cert.pem")
KEY_PATH = os.getenv("CLIENT_KEY", "certs/client.key.pem")
EXPECTED_SERVER_CN = os.getenv("EXPECTED_SERVER_CN", "server.local")
CA_CERT = os.getenv("CA_CERT", "certs/ca.cert.pem")

SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "9000"))

def load_cert_pem(path):
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------
# 1) CERTIFICATE CHECKING FUNCTION
# ------------------------------------------------------------
def certificate_check(s):
    client_cert_pem = load_cert_pem(CERT_PATH)
    nonce = str(os.urandom(16).hex())

    hello = {"type": "hello", "client cert": client_cert_pem.decode(), "nonce": nonce}
    send_message(s, hello)

    msg = recv_message(s)
    if not isinstance(msg, dict) or msg.get("type") != "server hello":
        print("Invalid server hello:", msg)
        return None

    server_cert_pem_text = msg.get("server cert")
    server_cert_pem = server_cert_pem_text.encode()

    ok, reason = pki.verify_cert_against_ca(
        server_cert_pem, EXPECTED_SERVER_CN, ca_cert_path=CA_CERT
    )
    if not ok:
        print("Server certificate verification failed:", reason)
        send_message(s, {"type": "error", "reason": reason})
        return None

    print("Server certificate verified OK")
    # save server cert for later signature verification
    try:
        os.makedirs("certs", exist_ok=True)
        with open(os.path.join("certs", "peer_server.cert.pem"), "wb") as f:
            f.write(server_cert_pem)
    except Exception:
        pass

    send_message(s, {"type": "ok"})
    return server_cert_pem


# ------------------------------------------------------------
# 2) REGISTER / LOGIN CONTROL LOOP FUNCTION
# ------------------------------------------------------------
def control_loop(s):
    while True:
        msg = recv_message(s)
        if msg.get("type") != "server hello":
            return msg

        # Extract DH params
        p = int(msg["dh_p"])
        g = int(msg["dh_g"])
        server_pub_hex = msg["server_dh_pub"]

        client_priv = crypto_dh.private_key_from_params(p, g)
        client_pub_hex = crypto_dh.public_key_hex_from_private(client_priv)

        send_message(s, {"type": "dh_client", "client_dh_pub": client_pub_hex})

        server_pub_int = int(server_pub_hex, 16)
        server_pub = crypto_dh.peer_public_from_int(server_pub_int, p, g)

        shared = crypto_dh.compute_shared_key(client_priv, server_pub)
        aes_key = crypto_dh.derive_aes_key_from_shared(shared)

        # Ask user
        while True:
            action = input("Action (register/login): ").strip()
            if action in ("register", "login"):
                break

        email = input("email: ").strip()
        pwd = input("password: ")
        username = ""
        if action == "register":
            username = input("username: ")

        if action == "register":
            payload = {"type": "register", "email": email, "username": username, "pwd": pwd}
        else:
            payload = {"type": "login", "email": email, "pwd": pwd}

        pt = json.dumps(payload).encode()
        ct = crypto_aes.encrypt(aes_key, pt)

        send_message(s, {"type": "enc", "payload": base64.b64encode(ct).decode()})

        rsp = recv_message(s)
        print("Server response:", rsp)

        if rsp.get("type") == "ok" and action == "login":
            print("Login successful → proceed to CHAT")
            return {"type": "chat ready"}

        if rsp.get("type") == "ok" and action == "register":
            print("Registered successfully — Login now.")
            continue

        if rsp.get("type") == "error":
            print("Operation failed. Try again.")
            continue


# ------------------------------------------------------------
# 3) CHAT LOOP (DH SESSION KEY)
# ------------------------------------------------------------
def chat_loop(s):
    msg = recv_message(s)

    if not isinstance(msg, dict) or msg.get("type") != "server hello":
        return msg

    # Extract DH params
    p = int(msg["dh_p"])
    g = int(msg["dh_g"])

    server_pub_hex = msg["server_dh_pub"]
    client_priv = crypto_dh.private_key_from_params(p, g)
    client_pub_hex = crypto_dh.public_key_hex_from_private(client_priv)

    send_message(s, {"type": "dh_client", "client_dh_pub": client_pub_hex})

    server_pub_int = int(server_pub_hex, 16)
    server_pub = crypto_dh.peer_public_from_int(server_pub_int, p, g)
    shared = crypto_dh.compute_shared_key(client_priv, server_pub)
    session_key = crypto_dh.derive_aes_key_from_shared(shared)

    print("Chat session key established:", len(session_key), "bytes")

    # Load peer public key (saved earlier by certificate_check)
    peer_cert_path = os.path.join("certs", "peer_server.cert.pem")
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


    # messaging loop: client sends, server replies
    our_seq = 0
    expected_seq = 1
    from common.utils import now_ms

    # store the last normal (non-attack) sent message dict so /r can replay it
    prev_sent_packet = None

    while True:
        text = input("message: ")

        # --- Replay attack: resend previous exact packet (do not change seq counters/transcript)
        if text.strip() == "/r":
            if not prev_sent_packet:
                print("No previous message to replay")
                continue
            # don't modify our_seq or expected_seq, just retransmit the previous raw packet
            send_message(s, prev_sent_packet)
            rsp = recv_message(s)
            if not isinstance(rsp, dict):
                print("Bad reply from server:", rsp)
                continue
            if rsp.get("type") == "error":
                print("Server error:", rsp)
                continue
            # If server returns a normal msg (unlikely for replay), print it but do not append to transcript or change seq
            if rsp.get("type") == "msg":
                print("Server reply to replay (not logged):", rsp)
            continue

        # --- Flip-bit attack: construct a fresh message but flip one bit in the ciphertext after signing
        if text.strip() == "/f":
            seq_candidate = our_seq + 1
            ts = now_ms()
            ct = crypto_aes.encrypt(session_key, text.encode())
            # sign the original (uncorrupted) data to simulate an in-transit corruption
            data = struct.pack("!Q", seq_candidate) + struct.pack("!Q", ts) + ct
            if our_priv is not None:
                sig = crypto_sign.sign_bytes(our_priv, data)
            else:
                sig = b""

            # flip a single bit in a copy of the ciphertext
            ct_flipped = bytearray(ct)
            if len(ct_flipped) > 0:
                ct_flipped[0] ^= 0x01

            pkt = {"type": "msg", "seqno": seq_candidate, "ts": ts, "ct": base64.b64encode(bytes(ct_flipped)).decode(), "sig": base64.b64encode(sig).decode()}
            send_message(s, pkt)

            rsp = recv_message(s)
            if not isinstance(rsp, dict):
                print("Bad reply from server:", rsp)
                continue
            if rsp.get("type") == "error":
                print("Server error:", rsp)
                continue
            if rsp.get("type") == "msg":
                print("Server reply to flipped message (not logged):", rsp)
            continue

        # --- Normal message flow: increment sequence, send, and log transcript
        our_seq += 1
        ts = now_ms()
        ct = crypto_aes.encrypt(session_key, text.encode())
        data = struct.pack("!Q", our_seq) + struct.pack("!Q", ts) + ct
        if our_priv is not None:
            sig = crypto_sign.sign_bytes(our_priv, data)
        else:
            sig = b""

        # Append our SENT message to the transcript (so transcript contains both sides)
        try:
            peer_cert_path = os.path.join("certs", "peer_server.cert.pem")
            fingerprint = compute_cert_fingerprint(peer_cert_path)
        except Exception:
            fingerprint = ""
        try:
            _transcript_dir = os.path.join("transcripts")
            os.makedirs(_transcript_dir, exist_ok=True)
            transcript_path = os.path.join(_transcript_dir, "client.txt")
            append_transcript_entry(transcript_path, our_seq, ts, ct, sig, fingerprint, side="sent")
        except Exception:
            pass

        pkt = {"type": "msg", "seqno": our_seq, "ts": ts, "ct": base64.b64encode(ct).decode(), "sig": base64.b64encode(sig).decode()}

        # store the last normal-sent packet for potential replay
        prev_sent_packet = pkt.copy()

        send_message(s, pkt)

        # receive server reply
        rsp = recv_message(s)
        if not isinstance(rsp, dict) or rsp.get("type") != "msg":
            print("Bad reply from server:", rsp)
            continue

        rseq = int(rsp.get("seqno", 0))
        rts = int(rsp.get("ts", 0))
        rct = base64.b64decode(rsp.get("ct", ""))
        rsig = base64.b64decode(rsp.get("sig", ""))

        # verify
        now = now_ms()
        if rseq != expected_seq:
            print("Unexpected server seq", rseq, "expected", expected_seq)
            continue
        if abs(now - rts) > 120000:
            print("Stale server message")
            continue

        verified = False
        if peer_pub is not None:
            try:
                verified = crypto_sign.verify_signature(peer_pub, rsig, struct.pack("!Q", rseq) + struct.pack("!Q", rts) + rct)
            except Exception:
                verified = False

        if not verified:
            print("Bad signature from server")
            continue

        try:
            rpt = crypto_aes.decrypt(session_key, rct).decode()
        except Exception:
            print("Failed to decrypt server reply")
            continue

        # Append received server message to our transcript
        try:
            peer_cert_path = os.path.join("certs", "peer_server.cert.pem")
            fingerprint = compute_cert_fingerprint(peer_cert_path)

        except Exception:
            fingerprint = ""

        try:
            _transcript_dir = os.path.join("transcripts")
            os.makedirs(_transcript_dir, exist_ok=True)
            transcript_path = os.path.join(_transcript_dir, "client.txt")
            append_transcript_entry(transcript_path, rseq, rts, rct, rsig, fingerprint, side="recv")
        except Exception:
            pass
        
        print(f"[server] {rseq} @ {rts}: {rpt}")

        expected_seq += 1

        if text.strip().lower() == "exit":
            break

    # Chat finished — create a signed receipt over our transcript
    try:
        transcript_path = os.path.join("transcripts", "client.txt")
        last_seq = expected_seq - 1
        receipt_path = create_session_receipt(transcript_path, KEY_PATH, "client", 1 if last_seq >= 1 else None, last_seq if last_seq >= 1 else None)
        print("Wrote client receipt:", receipt_path)
    except Exception:
        pass

    return session_key


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))

        if not certificate_check(s):
            return

        msg = control_loop(s)

        if msg and msg.get("type") == "chat ready":
            session_key = chat_loop(s)

if __name__ == "__main__":
    main()
