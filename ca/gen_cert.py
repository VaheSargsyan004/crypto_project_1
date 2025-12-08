import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

# Add project root to path
BASE = os.path.dirname(__file__)
PROJECT_ROOT = os.path.join(BASE, "..")
sys.path.insert(0, PROJECT_ROOT)

from utils.crypto_utils import save_cert_info


CERT_DIR = BASE
SERVER_DIR = os.path.join(BASE, "..", "server")
os.makedirs(SERVER_DIR, exist_ok=True)

def create_ca():
    # Create certificates directory
    certs_dir = os.path.join(CERT_DIR, "certificates")
    os.makedirs(certs_dir, exist_ok=True)
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key_path = os.path.join(certs_dir, "ca_key.pem")
    with open(ca_key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AM"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vahe CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "VaheRootCA")
    ])

    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))

    ca_cert_path = os.path.join(certs_dir, "ca_cert.pem")
    
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    json_path = save_cert_info(ca_cert_path, ca_key_path, CERT_DIR, "ca")
    print(f"[✓] CA created successfully!")
    print(f"[✓] Certificate and key saved to: {certs_dir}")
    print(f"[✓] Certificate info saved to: {json_path}")

def create_server_cert():
    from utils.crypto_utils import sign_data

    # Load CA key and cert from certificates directory
    ca_certs_dir = os.path.join(CERT_DIR, "certificates")
    with open(os.path.join(ca_certs_dir, "ca_key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), None)
    with open(os.path.join(ca_certs_dir, "ca_cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Create server certificates directory
    server_certs_dir = os.path.join(SERVER_DIR, "certificates")
    os.makedirs(server_certs_dir, exist_ok=True)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_key_path = os.path.join(server_certs_dir, "server_key.pem")
    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption()))

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AM"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Yerevan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Yerevan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vahe Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "my-server"),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    server_cert_path = os.path.join(server_certs_dir, "server_cert.pem")
    
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    json_path = save_cert_info(server_cert_path, server_key_path, SERVER_DIR, "server")
    print(f"[✓] Server certificate generated!")
    print(f"[✓] Certificate and key saved to: {server_certs_dir}")
    print(f"[✓] Certificate info saved to: {json_path}")

if __name__ == "__main__":
    print("1. Create CA\n2. Create Server Certificate")
    choice = input("Choose: ")
    if choice == "1":
        create_ca()
    elif choice == "2":
        create_server_cert()
    else:
        print("Invalid choice")
