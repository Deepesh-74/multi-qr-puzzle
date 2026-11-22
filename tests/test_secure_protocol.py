from pathlib import Path

import pytest

from secure_protocol import SecureTransferStore, generate_recipient_keypair


def test_persistent_encrypted_transfer_round_trip(tmp_path: Path) -> None:
    private_key, public_key = generate_recipient_keypair()
    store = SecureTransferStore(tmp_path / "transfers.db")
    source = b"prototype payload" * 100

    transfer = store.create_transfer(
        source, "report.bin", public_key, ttl_seconds=60, fragment_size=64
    )

    restored = store.decrypt_transfer(transfer.manifest, transfer.tokens, store, private_key)

    assert restored == source
    assert transfer.manifest["fragment_count"] > 1


def test_fragment_token_is_single_use(tmp_path: Path) -> None:
    _, public_key = generate_recipient_keypair()
    store = SecureTransferStore(tmp_path / "transfers.db")
    transfer = store.create_transfer(b"one use", "note.txt", public_key, ttl_seconds=60)

    assert store.retrieve_fragment(transfer.tokens[0])
    with pytest.raises(PermissionError):
        store.retrieve_fragment(transfer.tokens[0])


def test_manifest_rejects_modified_metadata(tmp_path: Path) -> None:
    private_key, public_key = generate_recipient_keypair()
    store = SecureTransferStore(tmp_path / "transfers.db")
    transfer = store.create_transfer(b"authenticated", "note.txt", public_key, ttl_seconds=60)
    manifest = dict(transfer.manifest)
    manifest["filename"] = "tampered.txt"

    with pytest.raises(ValueError, match="Manifest authentication failed"):
        store.decrypt_transfer(manifest, transfer.tokens, store, private_key)
