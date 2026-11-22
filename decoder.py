"""Core Multi-QR file decoder with ZXing-CPP detection, strict schema validation, puzzle chain solving, SHA-256 verification, safe incremental decompression, and file count limits."""

import argparse
import base64
import binascii
import json
import sys
import uuid
import zlib
from pathlib import Path
from typing import Any, Dict, List, Union

import cv2
import numpy as np
import zxingcpp

from integrity import calculate_bytes_sha256, verify_bytes_sha256
from puzzle import solve_puzzle_chain

SUPPORTED_PROTOCOL_VERSION = "1.0"
SUPPORTED_COMPRESSION_METHOD = "zlib"
MAX_QR_CODES = 10
MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB safety ceiling for zlib expansion

REQUIRED_METADATA_TYPES: Dict[str, type] = {
    "protocol_version": str,
    "transfer_id": str,
    "original_filename": str,
    "total_chunks": int,
    "original_sha256": str,
    "compression_method": str,
    "chunk_data": str,
    "misleading_label": str,
    "entry_key": str,
    "exit_key": str,
}


def find_qr_images(input_dir: Union[str, Path]) -> List[Path]:
    """Locate all PNG image files in the specified directory and enforce maximum QR code count ceiling.

    Args:
        input_dir: Directory containing QR PNG images.

    Returns:
        A sorted list of resolved Paths to PNG files.

    Raises:
        FileNotFoundError: If the directory does not exist or contains no PNG files.
        ValueError: If the path is not a directory or exceeds MAX_QR_CODES.
    """
    dir_path = Path(input_dir).resolve()

    if not dir_path.exists():
        raise FileNotFoundError(f"Input directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise ValueError(f"Input path is not a directory: {dir_path}")

    png_files = sorted(
        p for p in dir_path.iterdir() if p.is_file() and p.suffix.lower() == ".png"
    )

    if not png_files:
        raise FileNotFoundError(f"No PNG files found in directory: {dir_path}")

    if len(png_files) > MAX_QR_CODES:
        raise ValueError(
            f"Too many QR images found ({len(png_files)}): exceeds protocol maximum of {MAX_QR_CODES} QR codes."
        )

    return png_files


def decode_qr_image(image_path: Union[str, Path]) -> str:
    """Decode a single QR code PNG image using ZXing-CPP with OpenCV's QRCodeDetector as fallback.

    Args:
        image_path: Path to the PNG image file.

    Returns:
        The raw decoded UTF-8 string payload from the QR code.

    Raises:
        FileNotFoundError: If the image file does not exist.
        ValueError: If the image cannot be read or no valid QR code is detected.
    """
    path = Path(image_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"QR image file not found: {path}")

    try:
        # Read via numpy buffer in BGR color (matching cv2.imread default)
        raw_file_bytes = np.fromfile(str(path), dtype=np.uint8)
        image = cv2.imdecode(raw_file_bytes, cv2.IMREAD_COLOR)
    except Exception as exc:
        raise ValueError(f"Failed to read image file '{path.name}': {exc}") from exc

    if image is None:
        raise ValueError(
            f"File '{path.name}' could not be decoded as a valid image."
        )

    # Primary decoder: ZXing-CPP
    try:
        barcodes = zxingcpp.read_barcodes(image)
        for barcode in barcodes:
            text = getattr(barcode, "text", None)
            if isinstance(text, str) and text:
                return text
    except Exception:
        # Fall through to OpenCV fallback if ZXing raises an error
        pass

    # Fallback decoder: OpenCV QRCodeDetector (grayscale + thresholding)
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    detector = cv2.QRCodeDetector()
    try:
        decoded_text, points, _ = detector.detectAndDecode(gray_image)
        if points is None or not decoded_text:
            _, binary_image = cv2.threshold(
                gray_image, 127, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU
            )
            decoded_text, points, _ = detector.detectAndDecode(binary_image)
    except cv2.error as exc:
        raise ValueError(
            f"Failed to decode QR image '{path.name}' with ZXing, and OpenCV fallback raised an error: {exc}"
        ) from exc

    if points is None:
        raise ValueError(f"No QR code detected in '{path.name}'.")
    if not decoded_text:
        raise ValueError(
            f"QR code detected in '{path.name}', but payload could not be decoded."
        )

    return decoded_text


def parse_and_validate_payload(
    raw_payload: str, source_name: str = "<unknown>"
) -> Dict[str, Any]:
    """Parse JSON QR payload, validate metadata schema, and strictly decode Base64 data.

    Args:
        raw_payload: Raw JSON string decoded from a QR code.
        source_name: Filename identifier for clear error reporting.

    Returns:
        A validated dictionary containing metadata and 'decoded_chunk_bytes'.

    Raises:
        ValueError: If JSON parsing, schema validation, or strict Base64 decoding fails.
    """
    if not isinstance(raw_payload, str) or not raw_payload.strip():
        raise ValueError(f"[{source_name}] Empty or non-string QR payload.")

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"[{source_name}] Malformed JSON payload: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(
            f"[{source_name}] Expected JSON object at root, got {type(payload).__name__}."
        )

    missing_keys = [k for k in REQUIRED_METADATA_TYPES if k not in payload]
    if missing_keys:
        raise ValueError(
            f"[{source_name}] Missing required metadata fields: {', '.join(missing_keys)}"
        )

    unexpected_keys = [k for k in payload if k not in REQUIRED_METADATA_TYPES]
    if unexpected_keys:
        raise ValueError(
            f"[{source_name}] Unexpected metadata fields: {', '.join(unexpected_keys)}"
        )

    for field, expected_type in REQUIRED_METADATA_TYPES.items():
        value = payload[field]
        if expected_type is int and isinstance(value, bool):
            raise ValueError(
                f"[{source_name}] Field '{field}' must be an integer, got boolean."
            )
        if not isinstance(value, expected_type):
            raise ValueError(
                f"[{source_name}] Field '{field}' must be of type {expected_type.__name__}, "
                f"got {type(value).__name__}."
            )

    if payload["protocol_version"] != SUPPORTED_PROTOCOL_VERSION:
        raise ValueError(
            f"[{source_name}] Unsupported protocol_version '{payload['protocol_version']}' "
            f"(expected '{SUPPORTED_PROTOCOL_VERSION}')."
        )

    if payload["compression_method"] != SUPPORTED_COMPRESSION_METHOD:
        raise ValueError(
            f"[{source_name}] Unsupported compression_method '{payload['compression_method']}' "
            f"(expected '{SUPPORTED_COMPRESSION_METHOD}')."
        )

    try:
        uuid.UUID(payload["transfer_id"])
    except ValueError as exc:
        raise ValueError(
            f"[{source_name}] Invalid transfer_id UUID format: '{payload['transfer_id']}'."
        ) from exc

    raw_filename = payload["original_filename"].strip()
    safe_filename = Path(raw_filename).name
    if (
        not raw_filename
        or safe_filename != raw_filename
        or safe_filename in {".", ".."}
    ):
        raise ValueError(
            f"[{source_name}] Invalid or unsafe original_filename: '{payload['original_filename']}'."
        )

    total_chunks = payload["total_chunks"]
    if not (1 <= total_chunks <= MAX_QR_CODES):
        raise ValueError(
            f"[{source_name}] Invalid total_chunks ({total_chunks}): must be between 1 and {MAX_QR_CODES}."
        )

    sha256_str = payload["original_sha256"].strip().lower()
    if len(sha256_str) != 64 or any(
        c not in "0123456789abcdef" for c in sha256_str
    ):
        raise ValueError(
            f"[{source_name}] Invalid original_sha256 format: expected 64-character hex string."
        )
    payload["original_sha256"] = sha256_str

    b64_data = payload["chunk_data"]
    if not b64_data or not b64_data.isascii():
        raise ValueError(
            f"[{source_name}] Field 'chunk_data' must be a non-empty ASCII Base64 string."
        )

    try:
        decoded_bytes = base64.b64decode(b64_data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"[{source_name}] Strict Base64 validation failed for 'chunk_data': {exc}"
        ) from exc

    if not decoded_bytes:
        raise ValueError(f"[{source_name}] Decoded 'chunk_data' is empty.")

    if base64.b64encode(decoded_bytes).decode("ascii") != b64_data:
        raise ValueError(
            f"[{source_name}] Non-canonical Base64 encoding detected in 'chunk_data'."
        )

    payload["decoded_chunk_bytes"] = decoded_bytes
    payload["source_image"] = source_name
    return payload


def validate_transfer_consistency(payloads: List[Dict[str, Any]]) -> None:
    """Verify that all decoded payloads belong to the same transfer without metadata mismatches.

    Args:
        payloads: List of validated payload dictionaries.

    Raises:
        ValueError: If payloads are empty or have inconsistent transfer-wide metadata fields.
    """
    if not payloads:
        raise ValueError("No valid QR payloads provided for consistency check.")

    reference = payloads[0]
    ref_source = reference.get("source_image", "chunk_0")
    consistent_fields = (
        "protocol_version",
        "transfer_id",
        "original_filename",
        "total_chunks",
        "original_sha256",
        "compression_method",
    )

    for item in payloads:
        src = item.get("source_image", "<unknown>")
        for field in consistent_fields:
            if item[field] != reference[field]:
                raise ValueError(
                    f"Metadata mismatch on field '{field}': '{src}' has '{item[field]}', "
                    f"expected '{reference[field]}' (from '{ref_source}')."
                )


def decompress_payload_data(
    compressed_data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE
) -> bytes:
    """Decompress reconstructed zlib byte stream with strict incremental limit enforcement.

    Args:
        compressed_data: Concatenated compressed bytes from all solved chunks.
        max_size: Maximum allowed decompressed output size in bytes (default: 100 MB).

    Returns:
        Uncompressed original file bytes.

    Raises:
        ValueError: If compressed_data is empty, exceeds max_size during decompression,
            or if zlib decompression detects incompleteness, corruption, or trailing data.
    """
    if not compressed_data:
        raise ValueError("Cannot decompress empty byte stream.")

    try:
        decompressor = zlib.decompressobj()
        chunks: List[bytes] = []
        total_output_size = 0
        remaining_limit = max_size + 1  # Allow detecting exact boundary vs overflow

        # Decompress input stream in chunks using max_length to stop memory expansion immediately
        block_size = 65536
        for i in range(0, len(compressed_data), block_size):
            block = compressed_data[i : i + block_size]
            part = decompressor.decompress(block, max_length=remaining_limit)
            if part:
                total_output_size += len(part)
                if total_output_size > max_size:
                    raise ValueError(
                        f"Decompressed output size exceeds safety limit of {max_size} bytes (100 MB)."
                    )
                remaining_limit = max_size + 1 - total_output_size
                chunks.append(part)

        # Handle stream termination safely without unrestricted buffers
        while not decompressor.eof and (
            decompressor.unconsumed_tail or not decompressor.unused_data
        ):
            part = decompressor.decompress(b"", max_length=remaining_limit)
            if part:
                total_output_size += len(part)
                if total_output_size > max_size:
                    raise ValueError(
                        f"Decompressed output size exceeds safety limit of {max_size} bytes (100 MB)."
                    )
                remaining_limit = max_size + 1 - total_output_size
                chunks.append(part)
            if not part:
                break

        decompressed = b"".join(chunks)
    except zlib.error as exc:
        raise ValueError(
            f"zlib decompression failed (corrupted or out-of-order chunk data): {exc}"
        ) from exc

    if not decompressor.eof:
        raise ValueError(
            "Incomplete zlib stream: end-of-stream marker not reached."
        )

    if decompressor.unused_data:
        raise ValueError(
            f"Corrupted zlib stream: {len(decompressor.unused_data)} trailing unconsumed bytes detected."
        )

    return decompressed


def decode_qr_directory(
    input_dir: Union[str, Path],
    output_dir: Union[str, Path],
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Decode all QR PNGs in a directory, solve puzzle chain ordering, verify integrity, and save file.

    Args:
        input_dir: Directory containing the QR code PNG images.
        output_dir: Directory where the reconstructed file will be written.
        overwrite: Whether to overwrite an existing file at the destination path.

    Returns:
        A dictionary containing reconstruction details and the saved file path.

    Raises:
        FileNotFoundError: If the input directory or PNG files are missing.
        FileExistsError: If the destination file already exists and overwrite is False.
        ValueError: If decoding, schema validation, puzzle solving, decompression, or SHA-256 verification fails.
        OSError: If the output directory or reconstructed file cannot be written.
    """
    target_out_dir = Path(output_dir).resolve()
    if target_out_dir.exists() and not target_out_dir.is_dir():
        raise ValueError(
            f"Output path exists and is not a directory: {target_out_dir}"
        )

    png_files = find_qr_images(input_dir)
    validated_payloads: List[Dict[str, Any]] = []

    for image_path in png_files:
        raw_text = decode_qr_image(image_path)
        payload = parse_and_validate_payload(
            raw_text, source_name=image_path.name
        )
        validated_payloads.append(payload)

    # 1. Verify transfer consistency across all decoded chunks
    validate_transfer_consistency(validated_payloads)

    reference = validated_payloads[0]
    expected_total_chunks = reference["total_chunks"]

    # 2. Solve the puzzle chain using entry/exit keys to reconstruct the correct chunk order
    solved_chunks = solve_puzzle_chain(validated_payloads)

    if len(solved_chunks) != expected_total_chunks:
        raise ValueError(
            f"Puzzle reconstruction error: solved {len(solved_chunks)} chunks, "
            f"expected {expected_total_chunks}."
        )

    # 3. Concatenate compressed bytes strictly in the solved chain order
    compressed_stream = b"".join(chunk["decoded_chunk_bytes"] for chunk in solved_chunks)

    # 4. Decompress the zlib byte stream with strict incremental safety limits
    reconstructed_bytes = decompress_payload_data(compressed_stream)

    expected_sha256 = reference["original_sha256"]
    actual_sha256 = calculate_bytes_sha256(reconstructed_bytes)

    # 5. Strictly verify SHA-256 before writing any file to disk
    if not verify_bytes_sha256(reconstructed_bytes, expected_sha256):
        raise ValueError(
            f"SHA-256 integrity verification failed! "
            f"Expected '{expected_sha256}', but reconstructed data hashed to '{actual_sha256}'. "
            f"Output file was NOT saved."
        )

    safe_filename = Path(reference["original_filename"]).name
    output_file_path = target_out_dir / safe_filename

    if output_file_path.exists() and not overwrite:
        raise FileExistsError(
            f"Destination file already exists: '{output_file_path}'. "
            f"Use --overwrite to permit overwriting."
        )

    try:
        target_out_dir.mkdir(parents=True, exist_ok=True)
        output_file_path.write_bytes(reconstructed_bytes)
    except OSError as exc:
        raise OSError(
            f"Failed to write reconstructed file to '{output_file_path}': {exc}"
        ) from exc

    return {
        "protocol_version": reference["protocol_version"],
        "transfer_id": reference["transfer_id"],
        "original_filename": safe_filename,
        "total_chunks": expected_total_chunks,
        "compressed_size_bytes": len(compressed_stream),
        "reconstructed_size_bytes": len(reconstructed_bytes),
        "original_sha256": expected_sha256,
        "reconstructed_sha256": actual_sha256,
        "output_file_path": output_file_path,
        "processed_images": [p.name for p in png_files],
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Decode Multi-QR PNG images from a directory, solve the chain-link puzzle, "
            "verify SHA-256 integrity, and reconstruct the original file."
        )
    )
    parser.add_argument(
        "input_dir",
        type=Path,
        help="Directory containing the QR code PNG images.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("reconstructed_out"),
        help="Directory to save the reconstructed file (default: ./reconstructed_out).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Permit overwriting an existing output file if it already exists.",
    )
    return parser


def main() -> int:
    """CLI entry point for the QR file decoder."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    try:
        summary = decode_qr_directory(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            overwrite=args.overwrite,
        )
    except Exception as exc:
        print(f"[ERROR] Decoding failed: {exc}", file=sys.stderr)
        return 1

    print("Decoding and puzzle reconstruction completed successfully:")
    print(f"  Transfer ID        : {summary['transfer_id']}")
    print(f"  Original Filename  : {summary['original_filename']}")
    print(f"  QR Chunks Solved   : {summary['total_chunks']}")
    print(f"  Compressed Size    : {summary['compressed_size_bytes']} bytes")
    print(f"  Reconstructed Size : {summary['reconstructed_size_bytes']} bytes")
    print(f"  Expected SHA-256   : {summary['original_sha256']}")
    print(f"  Verified SHA-256   : {summary['reconstructed_sha256']} [MATCH]")
    print(f"  Saved Output File  : {summary['output_file_path']}")

    return 0


# Unit test suite for decompress_payload_data and validation requirements
if __name__ == "__main__" and "--test" in sys.argv:
    import unittest

    class TestDecompressPayloadData(unittest.TestCase):
        def test_normal_compressed_file(self):
            original = b"Hello world! " * 100
            compressed = zlib.compress(original)
            result = decompress_payload_data(compressed, max_size=10000)
            self.assertEqual(result, original)

        def test_output_exact_boundary(self):
            original = b"A" * 50
            compressed = zlib.compress(original)
            result = decompress_payload_data(compressed, max_size=50)
            self.assertEqual(result, original)

        def test_output_exceeding_max_size(self):
            original = b"A" * 51
            compressed = zlib.compress(original)
            with self.assertRaises(ValueError) as ctx:
                decompress_payload_data(compressed, max_size=50)
            self.assertIn("exceeds safety limit", str(ctx.exception))

        def test_incomplete_zlib_stream(self):
            original = b"A" * 100
            compressed = zlib.compress(original)
            # Truncate zlib stream
            truncated = compressed[:-2]
            with self.assertRaises(ValueError) as ctx:
                decompress_payload_data(truncated, max_size=1000)
            self.assertIn("Incomplete zlib stream", str(ctx.exception))

        def test_corrupted_compressed_data(self):
            corrupted = b"notazlibstreamatall"
            with self.assertRaises(ValueError) as ctx:
                decompress_payload_data(corrupted, max_size=1000)
            self.assertIn("zlib decompression failed", str(ctx.exception))

        def test_trailing_bytes(self):
            original = b"Hello zlib"
            compressed = zlib.compress(original)
            with_trailing = compressed + b"TRAILINGBYTES"
            with self.assertRaises(ValueError) as ctx:
                decompress_payload_data(with_trailing, max_size=1000)
            self.assertIn("trailing unconsumed bytes", str(ctx.exception))

    print("Running decoder decompression unit tests...")
    unittest.main(argv=[sys.argv[0]])


if __name__ == "__main__" and "--test" not in sys.argv:
    sys.exit(main())