import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

BASE = os.path.dirname(__file__)
CERT_DIR = BASE
SERVER_DIR = os.path.join(BASE, "..", "server")
os.makedirs(SERVER_DIR, exist_ok=True)

def create_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(CERT_DIR, "ca_key.pem"), "wb") as f:
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

    with open(os.path.join(CERT_DIR, "ca_cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[✓] CA created successfully!")

def create_server_cert():
    from utils.crypto_utils import sign_data

    with open(os.path.join(CERT_DIR, "ca_key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), None)
    with open(os.path.join(CERT_DIR, "ca_cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(os.path.join(SERVER_DIR, "server_key.pem"), "wb") as f:
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

    with open("../server/server_cert.pem", "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print("[✓] Server certificate generated!")

if __name__ == "__main__":
    print("1. Create CA\n2. Create Server Certificate")
    choice = input("Choose: ")
    if choice == "1":
        create_ca()
    elif choice == "2":
        create_server_cert()
    else:
        print("Invalid choice")
