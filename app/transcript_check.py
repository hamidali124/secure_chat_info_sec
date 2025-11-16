from storage import transcript as t

receipt = "receipts/receipt_server_1_2_20251125T132052Z.json"
transcript = "transcripts/server.txt"
peer_cert = "certs/server.cert.pem"   # the certificate whose private key signed the receipt

ok, msg = t.verify_session_receipt(receipt, transcript, peer_cert)
print(ok, msg)