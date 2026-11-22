# Multi-QR File Reconstruction Prototype

A research prototype for splitting file transfers across QR codes. It contains two deliberately separate paths:

- **Baseline puzzle demo:** zlib compression, QR chunks, decoy identifiers, and Flask reconstruction behavior. This path is not confidential and is retained for evaluation.
- **Secure prototype core:** recipient-owned X25519 keys, HKDF-derived keys, AES-256-GCM encryption, an authenticated manifest, SQLite-backed encrypted fragments, opaque single-use retrieval tokens, expiry, and replay rejection.

Do not describe the baseline puzzle flow as encryption or access control. It is an obfuscation and reconstruction experiment.

## Secure Prototype Scope

`secure_protocol.py` implements the cryptographic and persistent-storage core described by the paper's proposed architecture:

1. The receiver creates and retains an X25519 private key.
2. The sender receives only the receiver's public key.
3. The sender encrypts the complete payload with AES-GCM and creates an authenticated transfer manifest.
4. Ciphertext is fragmented and stored in SQLite.
5. Each fragment has an unpredictable, single-use retrieval token.
6. The receiver verifies the manifest, retrieves every fragment, decrypts the payload, and verifies the plaintext digest.

This is a local academic prototype. It does not yet include certificates or signatures for authenticating public keys, a production database, distributed rate limiting, multi-device retrieval, or a complete secure web UI.

## Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Verify The Secure Core

```bash
pytest tests
```

The tests cover encrypted round-trip reconstruction, one-time token replay rejection, and manifest-tampering rejection.

## Baseline Flask Demo

The original sender/receiver interface remains available for controlled comparison with the secure prototype:

```bash
python app.py
```

It is a local demonstration only. Its in-memory transfer state is lost on restart and its QR payloads are not encrypted.

## Paper Alignment

The paper should present the baseline as implemented evidence and the secure prototype as an implemented local core. Claims about production deployment, authenticated peer identity, long-lived storage, load handling, mobile clients, or high-scale retrieval remain future work until those components and evaluations exist.

## Security Notes

- AES-GCM nonces are generated randomly per transfer.
- Retrieval tokens are CSPRNG-generated and are stored only as hashes.
- A fragment token becomes unusable after one successful retrieval.
- SQLite state makes restart behavior testable, unlike the baseline Flask dictionaries.
- The receiver private key must never be uploaded to the sender or storage service.
