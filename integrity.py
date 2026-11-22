"""Cryptographic integrity utilities using SHA-256."""

import hashlib
import hmac
from pathlib import Path
from typing import Union

BUFFER_SIZE = 65536  # 64 KB read buffer for file hashing


def calculate_bytes_sha256(data: bytes) -> str:
    """Calculate the hexadecimal SHA-256 digest of raw byte data.

    Args:
        data: The raw bytes to hash.

    Returns:
        A 64-character lowercase hexadecimal SHA-256 string.

    Raises:
        TypeError: If the provided input is not of type bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data).__name__}.")
    return hashlib.sha256(data).hexdigest()


def calculate_file_sha256(file_path: Union[str, Path]) -> str:
    """Calculate the hexadecimal SHA-256 digest of a file on disk.

    Args:
        file_path: Path to the target file.

    Returns:
        A 64-character lowercase hexadecimal SHA-256 string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the path points to a directory or non-regular file.
        OSError: If the file cannot be read due to permissions or I/O issues.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    sha256_hash = hashlib.sha256()
    try:
        with path.open("rb") as file_handle:
            while chunk := file_handle.read(BUFFER_SIZE):
                sha256_hash.update(chunk)
    except OSError as exc:
        raise OSError(f"Error reading file '{path}': {exc}") from exc

    return sha256_hash.hexdigest()


def _normalize_hash(expected_hash: str) -> str:
    """Validate and normalize an expected SHA-256 hex digest string."""
    if not isinstance(expected_hash, str):
        raise TypeError(f"Expected string for hash, got {type(expected_hash).__name__}.")
    cleaned = expected_hash.strip().lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError(
            "Invalid SHA-256 hash format: expected a 64-character hexadecimal string."
        )
    return cleaned


def verify_bytes_sha256(data: bytes, expected_hash: str) -> bool:
    """Verify that raw byte data matches an expected SHA-256 digest.

    Args:
        data: The raw bytes to verify.
        expected_hash: The expected 64-character hexadecimal SHA-256 string.

    Returns:
        True if the calculated digest matches the expected digest, False otherwise.
    """
    normalized_expected = _normalize_hash(expected_hash)
    actual_hash = calculate_bytes_sha256(data)
    return hmac.compare_digest(actual_hash, normalized_expected)


def verify_file_sha256(file_path: Union[str, Path], expected_hash: str) -> bool:
    """Verify that a file on disk matches an expected SHA-256 digest.

    Args:
        file_path: Path to the file to verify.
        expected_hash: The expected 64-character hexadecimal SHA-256 string.

    Returns:
        True if the file's digest matches the expected digest, False otherwise.
    """
    normalized_expected = _normalize_hash(expected_hash)
    actual_hash = calculate_file_sha256(file_path)
    return hmac.compare_digest(actual_hash, normalized_expected)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Calculate or verify the SHA-256 hash of a file."
    )
    parser.add_argument("file", type=Path, help="Path to the target file.")
    parser.add_argument(
        "-c",
        "--check",
        type=str,
        default=None,
        help="Expected SHA-256 hex string to verify against the file.",
    )
    args = parser.parse_args()

    try:
        if args.check:
            is_valid = verify_file_sha256(args.file, args.check)
            if is_valid:
                print(f"[OK] Integrity verified for '{args.file.name}'.")
                sys.exit(0)
            else:
                print(
                    f"[FAILED] Hash mismatch for '{args.file.name}'.",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            digest = calculate_file_sha256(args.file)
            print(f"{digest}  {args.file.name}")
    except Exception as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)