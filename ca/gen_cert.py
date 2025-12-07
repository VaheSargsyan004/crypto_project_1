import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.dirname(__file__)
CERT_DIR = os.path.join(BASE_DIR, "certificates")

os.makedirs(CERT_DIR, exist_ok=True)


# -------------------------------------------------------
# 1. CREATE ROOT CA
# -------------------------------------------------------
def create_ca():
    print("[*] Generating CA private key...")

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(os.path.join(CERT_DIR, "ca_key.pem"), "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print("[*] Creating CA certificate...")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AM"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Yerevan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Yerevan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vahe CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vahe-root-ca"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    with open(os.path.join(CERT_DIR, "ca_cert.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("[✓] CA created!\n")


# -------------------------------------------------------
# 2. SIGN SERVER CERTIFICATE
# -------------------------------------------------------
def sign_server_certificate():
    print("[*] Loading CA key and certificate...")

    with open(os.path.join(CERT_DIR, "ca_key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(os.path.join(CERT_DIR, "ca_cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    print("[*] Generating server private key...")

    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("../server/server_key.pem", "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print("[*] Creating server certificate...")

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

    print("[✓] Server certificate created!\n")


# -------------------------------------------------------
# MENU
# -------------------------------------------------------
if __name__ == "__main__":
    print("1. Generate ROOT CA certificate")
    print("2. Generate SERVER certificate")
    choice = input("Select option: ")

    if choice == "1":
        create_ca()
    elif choice == "2":
        sign_server_certificate()
    else:
        print("Invalid input.")
