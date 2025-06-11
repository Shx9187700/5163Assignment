# Root CA Script (root.py)
# This script manages the Root Certificate Authority: certificate issuance to Sub CAs, revocation, and CRL generation.

import os
import json
import datetime
import secrets
import cryptography.x509 as x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import NameOID, BasicConstraints
from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder

RECORD_FILE = "cert_registry.json"  # Registry for all certificates and their statuses
aes_key = b"thisisa32bytekeythisisa32bytekey"  # Shared AES key with Sub CAs

# === Utility: Load the registry file ===
def load_registry():
    if os.path.exists(RECORD_FILE):
        with open(RECORD_FILE, "r") as f:
            try:
                content = f.read().strip()
                return json.loads(content) if content else {"certificates": [], "revoked_serials": []}
            except json.JSONDecodeError:
                print("⚠️ cert_registry.json format error. Resetting to empty.")
                return {"certificates": [], "revoked_serials": []}
    return {"certificates": [], "revoked_serials": []}

# === Utility: Save the registry file ===
def save_registry(registry):
    with open(RECORD_FILE, "w") as f:
        json.dump(registry, f, indent=2)

# === Root CA Setup ===
# Generate Root key and certificate if not exists
if not os.path.exists("root_private_key.pem") or not os.path.exists("root_cert.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"AU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
        .add_extension(BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    # Save private key and cert
    with open("root_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("root_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # Record in registry
    registry = load_registry()
    registry["certificates"].append({
        "serial": str(cert.serial_number),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "file": "root_cert.pem",
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "revoked": False
    })
    save_registry(registry)

# === View all issued certificates ===
def list_certificates():
    registry = load_registry()
    for idx, cert in enumerate(registry["certificates"]):
        status = "❌Revoked" if cert.get("revoked") else "✅Valid"
        print(f"[{idx}] {status} {cert['subject']} ← {cert['issuer']} | File: {cert['file']} | Expiry: {cert['not_after']}")
    input("\nPress any key to return to the main menu...\n")

# === Approve encrypted Sub CA requests and issue certs ===
def process_sub_ca_requests():
    enc_requests = [f for f in os.listdir() if f.endswith("_request.enc")]
    if not enc_requests:
        input("📭 No encrypted requests found.\nPress Enter to return...")
        return

    for filename in enc_requests:
        sub_name = filename.replace("_request.enc", "")
        with open(filename, "rb") as f:
            data = f.read()
        iv = data[:16]
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data[16:]) + decryptor.finalize()

        csr = x509.load_pem_x509_csr(decrypted)
        print(f"\n📥 Decrypted CSR from: {sub_name}")
        print("Subject:", csr.subject.rfc4514_string())
        approve = input("Approve certificate issuance? (y/n): ").strip().lower()
        if approve != "y":
            continue

        with open("root_private_key.pem", "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("root_cert.pem", "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
            .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        cert_file = f"{sub_name}_cert.pem"
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        os.remove(filename)

        registry = load_registry()
        registry["certificates"].append({
            "serial": str(cert.serial_number),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "file": cert_file,
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "revoked": False
        })
        save_registry(registry)
        print(f"✅ Certificate {cert_file} issued and recorded")

    input("\nAll requests processed. Press Enter to return...\n")

# === Revoke a certificate and its issued descendants ===
def revoke_certificate():
    registry = load_registry()
    for idx, cert in enumerate(registry["certificates"]):
        status = "❌Revoked" if cert.get("revoked") else "✅Valid"
        print(f"[{idx}] {status} {cert['subject']} ← {cert['issuer']} | File: {cert['file']} | Expiry: {cert['not_after']}")
    idx = int(input("\nEnter index of certificate to revoke: "))
    cert = registry["certificates"][idx]
    cert["revoked"] = True
    issuer_subject = cert["subject"]
    for c in registry["certificates"]:
        if c["issuer"] == issuer_subject:
            c["revoked"] = True
    save_registry(registry)
    print("✅ Revocation complete, including downstream certificates.")
    input("\nPress any key to return to the main menu...\n")
    generate_crl()

# === Generate and save the Certificate Revocation List (CRL) ===
def generate_crl():
    registry = load_registry()
    with open("root_private_key.pem", "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("root_cert.pem", "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    builder = CertificateRevocationListBuilder()
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.last_update(datetime.datetime.now(datetime.UTC))
    builder = builder.next_update(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7))
    for cert in registry["certificates"]:
        if cert.get("revoked"):
            revoked = RevokedCertificateBuilder()
            revoked = revoked.serial_number(int(cert["serial"]))
            revoked = revoked.revocation_date(datetime.datetime.now(datetime.UTC))
            builder = builder.add_revoked_certificate(revoked.build())
    crl = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
    with open("root_crl.pem", "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

# === Main loop for the Root CA Control Panel ===
while True:
    generate_crl()
    print("\n===== Root CA Control Panel =====")
    print("1. View all issued certificates")
    print("2. Decrypt and approve Sub CA requests")
    print("3. Revoke certificate")
    print("0. Exit")
    choice = input("Enter option number: ").strip()
    if choice == "1":
        list_certificates()
    elif choice == "2":
        process_sub_ca_requests()
    elif choice == "3":
        revoke_certificate()
    elif choice == "0":
        break
    else:
        print("❌ Invalid option")