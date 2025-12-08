## Cryptography Programming Project

A secure client-server communication system using X.509 certificates, RSA encryption, and AES session keys.

### Features

- CA (Certificate Authority) certificate generation
- Server certificate generation and signing
- Secure client-server communication with encrypted messaging
- JSON metadata storage for all certificates and keys in `/certificates` directories

### Project Structure

```
crypto_project_1/
├── ca/
│   ├── gen_cert.py          # CA and server certificate generation
│   └── certificates/        # JSON files with CA cert/key info
├── server/
│   ├── server.py            # Server application
│   └── certificates/        # JSON files with server cert/key info
├── client/
│   ├── client.py            # Client application
│   └── certificates/        # JSON files with received cert info
└── utils/
    ├── crypto_utils.py      # Cryptographic utilities
    └── aes_utils.py         # AES encryption utilities
```

### Prerequisites

Activate venv

```bash
python3 -m venv venv
source venv/bin/activate
```

Install required Python packages:

```bash
pip install -r requirements.txt
```

### How to Run

#### Step 1: Generate CA Certificate

```bash
cd ca
python gen_cert.py
# Choose option 1 to create CA
```

This will create:
- `ca_key.pem` - CA private key
- `ca_cert.pem` - CA certificate
- `certificates/ca_info.json` - JSON metadata with certificate and key information

#### Step 2: Generate Server Certificate

```bash
cd ca
python gen_cert.py
# Choose option 2 to create server certificate
```

This will create:
- `server/server_key.pem` - Server private key
- `server/server_cert.pem` - Server certificate
- `server/certificates/server_info.json` - JSON metadata with certificate and key information

#### Step 3: Start the Server

```bash
cd server
python server.py
```

The server will:
- Load its certificate and key
- Save certificate info to `server/certificates/server_info.json`
- Listen on `127.0.0.1:5000`

#### Step 4: Run the Client

In a new terminal:

```bash
cd client
python client.py
```

The client will:
- Connect to the server
- Receive and verify the server certificate
- Save received certificate info to `client/certificates/received_server_cert_info.json`
- Establish encrypted communication using AES session keys

### JSON Certificate Info Format

The JSON files in `/certificates` directories contain:

- **Certificate information**: subject, issuer, serial number, validity dates, fingerprint
- **Public key**: PEM-encoded public key
- **Key information**: key size, public key details
- **Metadata**: creation timestamp, name

Example structure:
```json
{
  "name": "ca",
  "created_at": "2024-01-01T12:00:00",
  "certificate": {
    "subject": {...},
    "issuer": {...},
    "serial_number": "...",
    "not_valid_before": "...",
    "not_valid_after": "...",
    "fingerprint": "...",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
  },
  "key": {
    "key_size": 2048,
    "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
  }
}
```

### Security Features

- X.509 certificate-based authentication
- RSA-2048 for key exchange
- AES-256-CBC for session encryption
- Certificate chain verification