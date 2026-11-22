"""Persistent authenticated-encryption prototype for multi-QR transfers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = "2.0"
DEFAULT_FRAGMENT_SIZE = 700


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def generate_recipient_keypair() -> tuple[bytes, bytes]:
    """Return raw X25519 private and public keys; store the private key only with the receiver."""
    private = x25519.X25519PrivateKey.generate()
    return (
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
    )


def _derive_keys(private_key: bytes, peer_public_key: bytes, transfer_id: str) -> tuple[bytes, bytes]:
    shared = x25519.X25519PrivateKey.from_private_bytes(private_key).exchange(
        x25519.X25519PublicKey.from_public_bytes(peer_public_key)
    )
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=uuid.UUID(transfer_id).bytes,
        info=b"multi-qr-prototype-v2",
    ).derive(shared)
    return material[:32], material[32:]


@dataclass(frozen=True)
class SecureTransfer:
    transfer_id: str
    manifest: dict[str, object]
    tokens: list[str]


class SecureTransferStore:
    """SQLite-backed encrypted-fragment store for local prototype evaluation."""

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS fragments (
                    transfer_id TEXT NOT NULL,
                    fragment_index INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    ciphertext BLOB NOT NULL,
                    downloads INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (transfer_id, fragment_index),
                    FOREIGN KEY (transfer_id) REFERENCES transfers(transfer_id)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def create_transfer(
        self,
        plaintext: bytes,
        filename: str,
        recipient_public_key: bytes,
        ttl_seconds: int = 900,
        fragment_size: int = DEFAULT_FRAGMENT_SIZE,
    ) -> SecureTransfer:
        if not plaintext:
            raise ValueError("Empty files are not supported.")
        if ttl_seconds <= 0 or fragment_size <= 0:
            raise ValueError("ttl_seconds and fragment_size must be positive.")
        if len(recipient_public_key) != 32:
            raise ValueError("recipient_public_key must be a raw 32-byte X25519 public key.")

        transfer_id = str(uuid.uuid4())
        sender_private = x25519.X25519PrivateKey.generate()
        sender_private_raw = sender_private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        sender_public = sender_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        encryption_key, manifest_key = _derive_keys(sender_private_raw, recipient_public_key, transfer_id)
        nonce = secrets.token_bytes(12)
        aad = json.dumps(
            {"version": PROTOCOL_VERSION, "transfer_id": transfer_id, "filename": filename},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
        fragments = [ciphertext[i : i + fragment_size] for i in range(0, len(ciphertext), fragment_size)]
        expires_at = int(time.time()) + ttl_seconds
        manifest: dict[str, object] = {
            "version": PROTOCOL_VERSION,
            "transfer_id": transfer_id,
            "filename": Path(filename).name,
            "sender_ephemeral_public_key": _b64(sender_public),
            "recipient_key_fingerprint": hashlib.sha256(recipient_public_key).hexdigest()[:16],
            "nonce": _b64(nonce),
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "fragment_count": len(fragments),
            "expires_at": expires_at,
        }
        canonical = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
        manifest["mac"] = _b64(hmac.new(manifest_key, canonical, hashlib.sha256).digest())

        tokens: list[str] = []
        with self._connect() as db:
            db.execute(
                "INSERT INTO transfers VALUES (?, ?, ?, 0)",
                (transfer_id, json.dumps(manifest, separators=(",", ":"), sort_keys=True), expires_at),
            )
            for index, fragment in enumerate(fragments):
                token = secrets.token_urlsafe(32)
                tokens.append(token)
                db.execute(
                    "INSERT INTO fragments VALUES (?, ?, ?, ?, 0)",
                    (transfer_id, index, hashlib.sha256(token.encode()).hexdigest(), fragment),
                )
        return SecureTransfer(transfer_id, manifest, tokens)

    def retrieve_fragment(self, token: str) -> bytes:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._connect() as db:
            row = db.execute(
                """SELECT f.ciphertext, f.downloads, t.expires_at, t.revoked
                   FROM fragments f JOIN transfers t ON t.transfer_id=f.transfer_id
                   WHERE f.token_hash=?""",
                (token_hash,),
            ).fetchone()
            if row is None or row[2] < int(time.time()) or row[3] or row[1] >= 1:
                raise PermissionError("Fragment is unavailable.")
            db.execute("UPDATE fragments SET downloads=downloads+1 WHERE token_hash=?", (token_hash,))
            return bytes(row[0])

    @staticmethod
    def decrypt_transfer(
        manifest: dict[str, object],
        tokens: Iterable[str],
        store: "SecureTransferStore",
        recipient_private_key: bytes,
    ) -> bytes:
        transfer_id = str(manifest["transfer_id"])
        sender_public = _unb64(str(manifest["sender_ephemeral_public_key"]))
        encryption_key, manifest_key = _derive_keys(recipient_private_key, sender_public, transfer_id)
        unsigned = {key: value for key, value in manifest.items() if key != "mac"}
        canonical = json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode("utf-8")
        expected_mac = hmac.new(manifest_key, canonical, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, _unb64(str(manifest["mac"]))):
            raise ValueError("Manifest authentication failed.")
        encrypted = b"".join(store.retrieve_fragment(token) for token in tokens)
        aad = json.dumps(
            {"version": manifest["version"], "transfer_id": transfer_id, "filename": manifest["filename"]},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        plaintext = AESGCM(encryption_key).decrypt(_unb64(str(manifest["nonce"])), encrypted, aad)
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), str(manifest["plaintext_sha256"])):
            raise ValueError("Plaintext integrity verification failed.")
        return plaintext
