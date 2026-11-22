"""Core Multi-QR file encoder with zlib compression, JSON metadata, and Chain-Link Puzzle integration."""

import argparse
import base64
import json
import math
import sys
import uuid
import zlib
from pathlib import Path
from typing import Any, Dict, List, Union

import qrcode
from qrcode.constants import ERROR_CORRECT_M
from qrcode.exceptions import DataOverflowError

from integrity import calculate_bytes_sha256
from puzzle import generate_puzzle_metadata

PROTOCOL_VERSION = "1.0"
COMPRESSION_METHOD = "zlib"
DEFAULT_CHUNK_SIZE = 700
MAX_QR_CODES = 10


def read_binary_file(file_path: Union[str, Path]) -> bytes:
    """Read a file from disk as raw binary data.

    Args:
        file_path: Path to the input file.

    Returns:
        The complete file contents as bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the path is not a regular file or the file is empty.
        OSError: If an I/O error occurs while reading the file.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Input path is not a regular file: {path}")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise OSError(f"Failed to read file '{path}': {exc}") from exc

    if len(data) == 0:
        raise ValueError(f"Input file is empty: {path}")

    return data


def compress_data(data: bytes, level: int = zlib.Z_BEST_COMPRESSION) -> bytes:
    """Compress raw bytes using zlib.

    Args:
        data: Uncompressed binary data.
        level: Compression level (0-9 or -1 for default).

    Returns:
        Compressed binary data.

    Raises:
        TypeError: If data is not bytes.
        ValueError: If compression fails or an invalid compression level is given.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes to compress, got {type(data).__name__}.")
    try:
        return zlib.compress(data, level=level)
    except zlib.error as exc:
        raise ValueError(f"zlib compression error: {exc}") from exc


def chunk_data(
    data: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_chunks: int = MAX_QR_CODES,
) -> List[bytes]:
    """Split binary data into fixed-size chunks and enforce a chunk count ceiling.

    Args:
        data: The binary data to split.
        chunk_size: Maximum size of each chunk in bytes.
        max_chunks: Maximum allowed number of chunks.

    Returns:
        A list of byte chunks.

    Raises:
        ValueError: If chunk_size or max_chunks is non-positive, data is empty,
            or the required number of chunks exceeds max_chunks.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be greater than 0 (got {chunk_size}).")
    if max_chunks <= 0:
        raise ValueError(f"max_chunks must be greater than 0 (got {max_chunks}).")
    if not data:
        raise ValueError("Cannot chunk empty byte data.")

    total_chunks = math.ceil(len(data) / chunk_size)
    if total_chunks > max_chunks:
        max_capacity = chunk_size * max_chunks
        raise ValueError(
            f"Compressed data size ({len(data)} bytes) requires {total_chunks} chunks "
            f"at {chunk_size} bytes/chunk, exceeding the limit of {max_chunks} QR codes "
            f"(maximum compressed capacity: {max_capacity} bytes)."
        )

    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def generate_payload(
    transfer_id: str,
    original_filename: str,
    total_chunks: int,
    original_sha256: str,
    chunk_bytes: bytes,
    misleading_label: str,
    entry_key: str,
    exit_key: str,
    protocol_version: str = PROTOCOL_VERSION,
    compression_method: str = COMPRESSION_METHOD,
) -> str:
    """Create a compact JSON string payload for a single QR code chunk with puzzle metadata.

    Args:
        transfer_id: Unique UUID string shared across all chunks in the transfer.
        original_filename: Name of the source file (without parent directories).
        total_chunks: Total number of chunks in the transfer.
        original_sha256: Hexadecimal SHA-256 hash of the uncompressed source file.
        chunk_bytes: Raw slice of compressed bytes for this chunk.
        misleading_label: Decoy sequence label (e.g. 'SEQ-03/05') independent of true order.
        entry_key: Chain-link entry token ('START' or unique hex token).
        exit_key: Chain-link exit token ('END' or unique hex token).
        protocol_version: Schema version identifier.
        compression_method: Identifier for the compression algorithm used.

    Returns:
        A serialized JSON string ready for QR encoding without order leakage.

    Raises:
        ValueError: If metadata values are invalid or empty.
    """
    if total_chunks <= 0:
        raise ValueError("total_chunks must be at least 1.")
    if not chunk_bytes:
        raise ValueError("chunk_bytes must not be empty.")
    if not misleading_label or not entry_key or not exit_key:
        raise ValueError("Puzzle metadata fields must not be empty.")

    # Encode raw compressed chunk bytes to an ASCII Base64 string for JSON transport
    b64_chunk_str = base64.b64encode(chunk_bytes).decode("ascii")

    # Verify round-trip Base64 integrity prior to packaging
    if base64.b64decode(b64_chunk_str.encode("ascii")) != chunk_bytes:
        raise RuntimeError("Internal Base64 encoding verification failed.")

    payload_dict: Dict[str, Any] = {
        "protocol_version": protocol_version,
        "transfer_id": transfer_id,
        "original_filename": original_filename,
        "total_chunks": total_chunks,
        "original_sha256": original_sha256,
        "compression_method": compression_method,
        "chunk_data": b64_chunk_str,
        "misleading_label": misleading_label,
        "entry_key": entry_key,
        "exit_key": exit_key,
    }

    # Compact separators minimize QR code symbol density
    return json.dumps(payload_dict, separators=(",", ":"), ensure_ascii=True)


def generate_qr_image(payload: str, output_path: Union[str, Path]) -> Path:
    """Encode a JSON payload string into a QR code with error correction M and save as PNG.

    Args:
        payload: The serialized JSON payload string.
        output_path: Destination path for the generated PNG image.

    Returns:
        The resolved Path to the saved PNG file.

    Raises:
        ValueError: If the payload is empty or exceeds the maximum QR capacity at level M.
        OSError: If the image cannot be written to disk.
    """
    if not payload:
        raise ValueError("QR payload cannot be empty.")

    destination = Path(output_path).resolve()
    if destination.suffix.lower() != ".png":
        destination = destination.with_suffix(".png")

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)

    try:
        qr.make(fit=True)
    except (DataOverflowError, ValueError) as exc:
        raise ValueError(
            f"Payload size ({len(payload)} bytes) exceeds maximum QR code capacity "
            f"at error correction level M. Reduce chunk_size and try again."
        ) from exc

    image = qr.make_image(fill_color="black", back_color="white")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        image.save(destination, format="PNG")
    except OSError as exc:
        raise OSError(f"Failed to save QR image to '{destination}': {exc}") from exc

    return destination


def encode_file_to_qr_codes(
    input_file: Union[str, Path],
    output_dir: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_chunks: int = MAX_QR_CODES,
) -> Dict[str, Any]:
    """Orchestrate reading, hashing, compressing, chunking, puzzle metadata attachment, and QR generation.

    Args:
        input_file: Path to the source file to encode.
        output_dir: Directory where generated PNG QR codes will be written.
        chunk_size: Maximum compressed bytes per chunk (default: 700).
        max_chunks: Maximum allowed QR codes per transfer (default: 10).

    Returns:
        A dictionary containing transfer metadata and the list of generated file paths.
    """
    source_path = Path(input_file).resolve()
    target_dir = Path(output_dir).resolve()

    if target_dir.exists() and not target_dir.is_dir():
        raise ValueError(
            f"Output path exists and is not a directory: {target_dir}"
        )

    raw_bytes = read_binary_file(source_path)
    original_sha256 = calculate_bytes_sha256(raw_bytes)
    compressed_bytes = compress_data(raw_bytes)

    chunks = chunk_data(
        compressed_bytes,
        chunk_size=chunk_size,
        max_chunks=max_chunks,
    )

    transfer_id = str(uuid.uuid4())
    total_chunks = len(chunks)
    original_filename = source_path.name

    # Generate cryptographic puzzle metadata containing chain links and misleading sequence labels
    puzzle_metadata_list = generate_puzzle_metadata(total_chunks)

    target_dir.mkdir(parents=True, exist_ok=True)
    generated_files: List[Path] = []

    for chunk_bytes, puzzle_meta in zip(chunks, puzzle_metadata_list):
        payload = generate_payload(
            transfer_id=transfer_id,
            original_filename=original_filename,
            total_chunks=total_chunks,
            original_sha256=original_sha256,
            chunk_bytes=chunk_bytes,
            misleading_label=puzzle_meta["misleading_label"],
            entry_key=puzzle_meta["entry_key"],
            exit_key=puzzle_meta["exit_key"],
        )
        # Use neutral filenames based on transfer ID and misleading label slug (no true position leakage)
        label_slug = puzzle_meta["misleading_label"].replace("/", "-")
        qr_filename = f"qr_{transfer_id[:8]}_{label_slug}.png"
        saved_path = generate_qr_image(payload, target_dir / qr_filename)
        generated_files.append(saved_path)

    return {
        "protocol_version": PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "original_filename": original_filename,
        "original_size_bytes": len(raw_bytes),
        "compressed_size_bytes": len(compressed_bytes),
        "original_sha256": original_sha256,
        "compression_method": COMPRESSION_METHOD,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "generated_files": generated_files,
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Encode a file into up to 10 compressed, puzzle-linked, and misleadingly labeled PNG QR codes."
        )
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to the input file to encode.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("output_qr"),
        help="Directory to save generated PNG QR codes (default: ./output_qr).",
    )
    parser.add_argument(
        "-c",
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Maximum compressed bytes per QR chunk (default: {DEFAULT_CHUNK_SIZE}).",
    )
    parser.add_argument(
        "-m",
        "--max-chunks",
        type=int,
        default=MAX_QR_CODES,
        help=f"Maximum number of QR codes allowed (default: {MAX_QR_CODES}).",
    )
    return parser


def main() -> int:
    """CLI entry point for the QR file encoder."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.max_chunks > MAX_QR_CODES:
        print(
            f"Error: --max-chunks cannot exceed the protocol limit of {MAX_QR_CODES}.",
            file=sys.stderr,
        )
        return 1

    try:
        summary = encode_file_to_qr_codes(
            input_file=args.input_file,
            output_dir=args.output_dir,
            chunk_size=args.chunk_size,
            max_chunks=args.max_chunks,
        )
    except Exception as exc:
        print(f"Encoding failed: {exc}", file=sys.stderr)
        return 1

    print("Encoding completed successfully:")
    print(f"  Transfer ID       : {summary['transfer_id']}")
    print(f"  Original File     : {summary['original_filename']}")
    print(f"  Original Size     : {summary['original_size_bytes']} bytes")
    print(f"  Compressed Size   : {summary['compressed_size_bytes']} bytes")
    print(f"  SHA-256 Digest    : {summary['original_sha256']}")
    print(f"  Chunks Generated  : {summary['total_chunks']} (chunk size: {summary['chunk_size']} bytes)")
    print("  Saved QR Images   :")
    for file_path in summary["generated_files"]:
        print(f"    - {file_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())