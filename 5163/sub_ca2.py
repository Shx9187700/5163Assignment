# ✅ sub_ca.py (Subordinate CA Script: Apply for Certificate from Root CA, Issue to Clients, Handle Revocations)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import NameOID, Name, NameAttribute, BasicConstraints
import cryptography.x509 as x509
import datetime
import json
import os
import secrets

RECORD_FILE = "cert_registry.json"  # File to store certificate and revocation records
aes_key = b"thisisa32bytekeythisisa32bytekey"  # Shared AES key with Root CA (32 bytes)

sub_name = os.path.basename(__file__).replace(".py", "")
CRL_FILE = f"{sub_name}_crl.pem"  # Output file for generated CRL

# === Apply to Root CA for a certificate (using encrypted CSR) ===
def apply_to_root():
    print(f"📤 {sub_name} is applying to Root CA for a certificate (encrypted)...")
    try:
        key_file = f"{sub_name}_private_key.pem"

        # Reuse or generate Sub CA's private key
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                sub_private_key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            sub_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(key_file, "wb") as f:
                f.write(sub_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        # Create CSR
        subject_info = Name([
            NameAttribute(NameOID.COUNTRY_NAME, u"AU"),
            NameAttribute(NameOID.ORGANIZATION_NAME, f"My {sub_name}"),
            NameAttribute(NameOID.COMMON_NAME, f"{sub_name.replace('_', ' ').title()}"),
        ])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject_info).sign(sub_private_key, hashes.SHA256())

        # Encrypt CSR using AES (CFB mode)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_csr = iv + encryptor.update(csr.public_bytes(serialization.Encoding.PEM)) + encryptor.finalize()

        with open(f"{sub_name}_request.enc", "wb") as f:
            f.write(encrypted_csr)

        print(f"✅ Encrypted request saved to {sub_name}_request.enc, waiting for Root CA approval")
    except Exception as e:
        print(f"❌ Error during application to Root CA: {str(e)}")

# === Generate CRL (Certificate Revocation List) based on revoked serials ===
def update_crl():
    try:
        with open(f"{sub_name}_private_key.pem", "rb") as f:
            sub_private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(f"{sub_name}_cert.pem", "rb") as f:
            sub_cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.datetime.now(datetime.UTC)
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(sub_cert.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + datetime.timedelta(days=7))

        # Add all revoked certs into CRL
        if os.path.exists(RECORD_FILE):
            with open(RECORD_FILE, "r") as f:
                registry = json.load(f)
            for cert in registry.get("certificates", []):
                if cert.get("revoked"):
                    revoked_cert = x509.RevokedCertificateBuilder()
                    revoked_cert = revoked_cert.serial_number(int(cert["serial"]))
                    revoked_cert = revoked_cert.revocation_date(now)
                    revoked_cert = revoked_cert.build()
                    builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=sub_private_key, algorithm=hashes.SHA256())
        with open(CRL_FILE, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        print(f"📃 CRL updated: {CRL_FILE}")
    except Exception as e:
        print(f"❌ Error updating CRL: {str(e)}")

# === Sub CA Menu Loop ===
while True:
    update_crl()  # Auto update CRL on each loop
    print(f"\n===== {sub_name} Menu =====")
    print("1. Apply to Root CA (encrypted)")
    print("2. Approve client requests and issue certificates")
    print("3. Revoke issued certificates")
    print("0. Exit")
    op = input("Select an option: ").strip()

    if op == "1":
        apply_to_root()

    elif op == "2":
        print(f"\n📥 {sub_name} is scanning for client request files...")
        pending_requests = [f for f in os.listdir() if f.endswith("_request.enc") and not f.startswith(sub_name)]
        if not pending_requests:
            input("📭 No encrypted client requests found. Press Enter to continue...")
            continue

        for req_file in pending_requests:
            client_name = req_file.replace("_request.enc", "")
            print(f"🔓 Decrypting CSR request from {req_file}...")
            try:
                # Decrypt CSR
                with open(req_file, "rb") as f:
                    data = f.read()
                iv = data[:16]
                encrypted = data[16:]
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                decryptor = cipher.decryptor()
                decrypted_csr = decryptor.update(encrypted) + decryptor.finalize()

                csr = x509.load_pem_x509_csr(decrypted_csr)

                print("Subject:", csr.subject.rfc4514_string())
                approve = input("Approve and issue certificate? (y/n): ").strip().lower()
                if approve != "y":
                    continue

                # Load Sub CA key and certificate
                with open(f"{sub_name}_private_key.pem", "rb") as f:
                    sub_private_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(f"{sub_name}_cert.pem", "rb") as f:
                    sub_cert = x509.load_pem_x509_certificate(f.read())

                # Build and sign client certificate
                client_cert = (
                    x509.CertificateBuilder()
                    .subject_name(csr.subject)
                    .issuer_name(sub_cert.subject)
                    .public_key(csr.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.now(datetime.UTC))
                    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
                    .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(sub_private_key, hashes.SHA256())
                )

                # Save certificate file
                cert_file = f"{client_name}_cert.pem"
                with open(cert_file, "wb") as f:
                    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

                print(f"✅ Certificate issued to {client_name}, saved as {cert_file}")

                # Update registry
                if os.path.exists(RECORD_FILE):
                    with open(RECORD_FILE, "r") as f:
                        content = f.read().strip()
                        registry = json.loads(content) if content else {"certificates": [], "revoked_serials": []}
                else:
                    registry = {"certificates": [], "revoked_serials": []}

                sub_issuer_str = sub_cert.subject.rfc4514_string()

                registry["certificates"].append({
                    "serial": str(client_cert.serial_number),
                    "subject": client_cert.subject.rfc4514_string(),
                    "issuer": sub_issuer_str,
                    "issuer_serial": str(sub_cert.serial_number),
                    "file": cert_file,
                    "not_before": client_cert.not_valid_before.isoformat(),
                    "not_after": client_cert.not_valid_after.isoformat(),
                    "revoked": False
                })

                with open(RECORD_FILE, "w") as f:
                    json.dump(registry, f, indent=2)

                os.remove(req_file)
            except Exception as e:
                print(f"❌ Error processing request {req_file}: {str(e)}")

    elif op == "3":
        client_name = input("Enter client name to revoke (e.g. client1): ").strip()
        cert_file = f"{client_name}_cert.pem"
        if not os.path.exists(cert_file):
            print(f"❌ Certificate file {cert_file} not found.")
            continue

        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        if os.path.exists(RECORD_FILE):
            with open(RECORD_FILE, "r") as f:
                registry = json.load(f)
        else:
            registry = {"certificates": [], "revoked_serials": []}

        for c in registry["certificates"]:
            if c["serial"] == str(cert.serial_number):
                c["revoked"] = True
        if str(cert.serial_number) not in registry["revoked_serials"]:
            registry["revoked_serials"].append(str(cert.serial_number))

        with open(RECORD_FILE, "w") as f:
            json.dump(registry, f, indent=2)

        print(f"📛 Certificate revoked: {client_name}_cert.pem")

    elif op == "0":
        print("👋 Exiting Sub CA.")
        break
    else:
        print("❌ Invalid option. Please try again.")
