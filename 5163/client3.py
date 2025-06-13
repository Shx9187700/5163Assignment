# ✅ client.py (Client Script: Apply for Certificate, Perform Mutual TLS, Check CRLs)

import ssl
import socket
import os
import json
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import NameOID, Name, NameAttribute
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

client_name = os.path.basename(__file__).replace(".py", "")  # Get client name from filename
RECORD_FILE = "cert_registry.json"  # File storing certificate and revocation data
aes_key = b"thisisa32bytekeythisisa32bytekey"  # Shared AES key for encryption (32 bytes)

# === Set up SSL context for client or server mode ===
def setup_ssl_context(is_server=False):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False

    try:
        context.load_cert_chain(certfile=f"{client_name}_cert.pem", keyfile=f"{client_name}_private_key.pem")
    except FileNotFoundError:
        print("❌ Certificate not found. Please apply using Option 1 first.")
        return None

    ca_loaded = False

    # Load trusted root and sub CA certificates
    for ca_file in ["root_cert.pem", "sub_ca1_cert.pem", "sub_ca2_cert.pem"]:
        if os.path.exists(ca_file):
            try:
                context.load_verify_locations(cafile=ca_file)
                ca_loaded = True
            except Exception as e:
                print(f"❌ Failed to load CA file {ca_file}: {str(e)}")
        else:
            print(f"⚠️ CA file not found, skipping: {ca_file}")

    # Load CRLs for revocation checking
    for crl_file in ["root_crl.pem", "sub_ca1_crl.pem", "sub_ca2_crl.pem"]:
        if os.path.exists(crl_file):
            try:
                context.load_verify_locations(cafile=crl_file)
            except Exception as e:
                print(f"❌ Failed to load CRL file {crl_file}: {str(e)}")
        else:
            print(f"⚠️ CRL file not found, skipping: {crl_file}")

    # Enable CRL checking for peer certificate only
    context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

    if not ca_loaded:
        print("❌ No trusted CA available for verification.")
        return None

    return context

# === Check if a certificate is revoked using the appropriate CRL ===
def check_crl(cert: x509.Certificate) -> bool:
    issuer = cert.issuer.rfc4514_string()
    crl_file = None
    if "sub_ca1" in issuer:
        crl_file = "sub_ca1_crl.pem"
    elif "sub_ca2" in issuer:
        crl_file = "sub_ca2_crl.pem"
    elif "My Root CA" in issuer:
        crl_file = "root_crl.pem"

    if crl_file and os.path.exists(crl_file):
        with open(crl_file, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        return cert.serial_number in {r.serial_number for r in crl}
    return False

def verify_certificate_chain(cert: x509.Certificate) -> bool:
    """
    Verify the certificate chain and check CRL revocation status at each level.
    """
    try:
        # Step 1: Check if current certificate is revoked
        if check_crl(cert):
            print("❌ Certificate is revoked according to CRL.")
            return False

        # Step 2: Extract issuer Common Name (CN) and normalize
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        issuer_cn_normalized = issuer_cn.lower().replace(" ", "")  # normalize for consistent matching

        # Step 3: Map normalized issuer CN to corresponding cert file
        if "subca1" in issuer_cn_normalized:
            issuer_cert_file = "sub_ca1_cert.pem"
        elif "subca2" in issuer_cn_normalized:
            issuer_cert_file = "sub_ca2_cert.pem"
        elif "myrootca" in issuer_cn_normalized:
            issuer_cert_file = "root_cert.pem"
        else:
            print("❌ Unknown issuer, cannot verify chain.")
            return False

        if not os.path.exists(issuer_cert_file):
            print(f"❌ Issuer cert file {issuer_cert_file} not found.")
            return False

        # Step 4: Load issuer certificate
        with open(issuer_cert_file, "rb") as f:
            issuer_cert = x509.load_pem_x509_certificate(f.read())

        # Step 5: Verify the signature of the current certificate
        issuer_cert.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )

        # Step 6: Recursively verify the issuer's certificate unless it's the Root CA
        if issuer_cn_normalized != "myrootca":
            return verify_certificate_chain(issuer_cert)

        return True

    except Exception as e:
        print(f"❌ Certificate chain verification failed: {e}")
        return False

# === Request a certificate from Sub CA (encrypted CSR) ===
def request_certificate():
    target = input(f"📥 {client_name}: Enter Sub CA to apply (e.g., sub1 or sub2): ").strip().lower()
    ca_map = {"sub1": "sub_ca1", "sub2": "sub_ca2"}
    mapped_target = ca_map.get(target, target)
    sub_ca_cert_file = f"{mapped_target}_cert.pem"

    try:
        with open(sub_ca_cert_file, "rb") as f:
            sub_cert = x509.load_pem_x509_certificate(f.read())

        # Check if Sub CA is revoked
        if os.path.exists(RECORD_FILE):
            with open(RECORD_FILE, "r") as f:
                content = f.read().strip()
                registry = json.loads(content) if content else {"certificates": [], "revoked_serials": []}
        else:
            registry = {"certificates": [], "revoked_serials": []}

        if str(sub_cert.serial_number) in registry.get("revoked_serials", []):
            print("❌ This Sub CA's certificate has been revoked. Cannot request a certificate.")
            return

        print(f"📤 Sending encrypted certificate request to {mapped_target}...")

        # Generate client key and CSR
        client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(Name([
            NameAttribute(NameOID.COMMON_NAME, client_name),
        ])).sign(client_private_key, hashes.SHA256())

        # Encrypt CSR with AES
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        encrypted_csr = iv + encryptor.update(csr_bytes) + encryptor.finalize()

        # Save encrypted CSR and private key
        with open(f"{client_name}_request.enc", "wb") as f:
            f.write(encrypted_csr)

        with open(f"{client_name}_private_key.pem", "wb") as f:
            f.write(client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print(f"✅ Encrypted request written to {client_name}_request.enc. Please submit to CA.")

    except FileNotFoundError:
        print(f"❌ CA file {sub_ca_cert_file} not found.")
    except Exception as e:
        print(f"❌ Error occurred: {str(e)}")

# === Run in listen mode (TLS server, accept connections) ===
def listen_mode():
    port = int(input("📡 Enter port to listen on (e.g., 8443): "))
    context = setup_ssl_context(is_server=True)
    if context is None:
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('', port))
        sock.listen(5)
        print(f"📡 Listening on port {port}, waiting for connection...")

        try:
            with context.wrap_socket(sock, server_side=True) as ssock:
                try:
                    conn, addr = ssock.accept()
                    with conn:
                        print(f"✅ Connected: {addr}")
                        peer_cert = conn.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(peer_cert)

                        if check_crl(cert):
                            print("❌ Peer certificate is revoked. Disconnecting.")
                            return

                        # ✅ NEW: Verify full trust chain
                        if not verify_certificate_chain(cert):
                            print("❌ Certificate chain verification failed. Disconnecting.")
                            return

                        message = conn.recv(1024).decode()
                        print(f"📨 Received message: {message}")
                except ssl.SSLError as e:
                    print(f"⚠️ TLS handshake failed: {e}")
                finally:
                    print("🔙 Returning to menu.")
        except Exception as e:
            print(f"❌ Server listen error: {e}")

# === Run in connect mode (TLS client, initiate connection) ===
def connect_mode():
    ip = input("🔌 Enter target IP: ").strip()
    port = int(input("📡 Enter target port (e.g., 8443): ").strip())
    context = setup_ssl_context(is_server=False)
    if context is None:
        return

    try:
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print("✅ TLS connection established.")
                peer_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(peer_cert)

                if check_crl(cert):
                    print("❌ Peer certificate is revoked. Disconnecting.")
                    return

                msg = input("💬 Enter message to send: ").strip()
                ssock.send(msg.encode())
                print("✅ Message sent.")

    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")

# === Main interactive menu ===
if __name__ == "__main__":
    while True:
        print(f"\n===== {client_name} Menu =====")
        print("1. Apply for certificate from Sub CA")
        print("2. Wait for incoming connection (listen mode)")
        print("3. Connect to another client and send message")
        print("0. Exit")
        op = input("Select an option: ").strip()

        if op == "0":
            print("👋 Exiting client.")
            break
        elif op == "1":
            request_certificate()
        elif op == "2":
            listen_mode()
        elif op == "3":
            connect_mode()
        else:
            print("❌ Invalid option. Please try again.")
