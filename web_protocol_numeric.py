"""
Web Protocol Module for Multi-QR File Reconstruction.
Implements sequence-based transfer, obfuscated decoy generation, strict validation,
Windows-safe filename sanitization, and plausible dummy-output routing.
"""

import base64
import binascii
import io
import json
import math
import secrets
import uuid
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import cv2
import numpy as np
import qrcode
try:
    import zxingcpp
except ImportError:
    zxingcpp = None
from PIL import Image
from qrcode.constants import ERROR_CORRECT_M
from qrcode.exceptions import DataOverflowError

from integrity import calculate_bytes_sha256, verify_bytes_sha256

WEB_PROTOCOL_VERSION = "2.0"
COMPRESSION_METHOD = "zlib"
DEFAULT_CHUNK_SIZE = 700
MAX_REAL_CHUNKS = 8
DECOY_CHUNKS = 1
MIN_TOTAL_QRS = 2
MAX_TOTAL_QRS = MAX_REAL_CHUNKS + DECOY_CHUNKS
MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB safety ceiling

SUPPORTED_DUMMY_EXTENSIONS: Set[str] = {
    ".json",
    ".txt",
    ".md",
    ".log",
    ".csv",
    ".html",
    ".htm",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".pdf",
}

WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

WINDOWS_INVALID_CHARS: Set[str] = set('<>:"/\\|?*')

REQUIRED_WEB_METADATA_TYPES: Dict[str, type] = {
    "web_protocol_version": str,
    "transfer_id": str,
    "original_filename": str,
    "total_qrs": int,
    "original_sha256": str,
    "compression_method": str,
    "qr_identifier": str,
    "chunk_data": str,
}


def _generate_unique_qr_identifier(existing_ids: Set[str], total_qrs: int) -> str:
    """Choose a unique numeric QR identifier from 1 through total_qrs."""
    if not (MIN_TOTAL_QRS <= total_qrs <= MAX_TOTAL_QRS):
        raise ValueError(f"total_qrs must be between {MIN_TOTAL_QRS} and {MAX_TOTAL_QRS}.")

    available_ids = [str(number) for number in range(1, total_qrs + 1) if str(number) not in existing_ids]
    if not available_ids:
        raise ValueError("No numeric QR identifiers remain available.")

    chosen_id = secrets.choice(available_ids)
    existing_ids.add(chosen_id)
    return chosen_id


def _validate_safe_filename(filename: str, source_context: str = "input") -> str:
    """
    Validate that a filename is a non-empty, safe base name without path traversal,
    reserved Windows device names, invalid Windows characters, or trailing dots/spaces.
    """
    if not isinstance(filename, str) or not filename:
        raise ValueError(f"[{source_context}] Filename must be a non-empty string.")

    # Reject leading/trailing whitespace or trailing dots before stripping
    if filename != filename.strip() or filename.endswith(".") or filename.endswith(" "):
        raise ValueError(
            f"[{source_context}] Invalid or unsafe filename (leading/trailing space or dot): '{filename}'."
        )

    if any(ord(ch) < 32 or ch in WINDOWS_INVALID_CHARS for ch in filename):
        raise ValueError(
            f"[{source_context}] Invalid or unsafe filename (forbidden characters): '{filename}'."
        )

    safe_name = Path(filename).name
    if (
        not safe_name
        or safe_name != filename
        or safe_name in {".", ".."}
    ):
        raise ValueError(f"[{source_context}] Invalid or unsafe filename: '{filename}'.")

    # Windows checks the base stem before the first dot against reserved device names
    primary_stem = safe_name.split(".")[0].upper()
    stem_upper = Path(safe_name).stem.upper()
    if primary_stem in WINDOWS_RESERVED_NAMES or stem_upper in WINDOWS_RESERVED_NAMES:
        raise ValueError(
            f"[{source_context}] Unsafe filename (reserved Windows device name): '{filename}'."
        )

    return safe_name


def _validate_qr_identifier_format(qr_id: str, source_context: str = "input") -> str:
    """Validate that a QR identifier is a single digit from 1 through 9."""
    if not isinstance(qr_id, str):
        raise ValueError(f"[{source_context}] QR identifier must be a string.")
    cleaned = qr_id.strip()
    if len(cleaned) != 1 or cleaned not in "123456789":
        raise ValueError(
            f"[{source_context}] Invalid qr_identifier format '{qr_id}': "
            "expected a single digit from 1 through 9."
        )
    return cleaned


def _build_valid_dummy_pdf() -> bytes:
    """
    Construct a syntactically valid minimal PDF with dynamically calculated stream /Length,
    exact 20-byte classic xref entries, and dynamically calculated startxref offset.
    """
    header = b"%PDF-1.4\n"
    stream_content = b"BT /F1 12 Tf 72 720 Td (Project Summary Notes) Tj ET"
    stream_length = len(stream_content)

    obj4 = (
        f"4 0 obj\n<< /Length {stream_length} >>\nstream\n".encode("ascii")
        + stream_content
        + b"\nendstream\nendobj\n"
    )

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        ),
        obj4,
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    body_parts: List[bytes] = [header]
    offsets: List[int] = []
    current_offset = len(header)

    for obj_bytes in objects:
        offsets.append(current_offset)
        body_parts.append(obj_bytes)
        current_offset += len(obj_bytes)

    xref_offset = current_offset
    total_entries = len(objects) + 1

    # Classic PDF cross-reference table entries must be strictly 20 bytes each:
    # 10-digit byte offset, 1 space, 5-digit generation, 1 space, 'n'/'f', and 2-byte EOL ('\r\n').
    xref_header = f"xref\n0 {total_entries}\n".encode("ascii")
    xref_rows: List[bytes] = [b"0000000000 65535 f\r\n"]
    for off in offsets:
        row = f"{off:010d} 00000 n\r\n".encode("ascii")
        if len(row) != 20:
            raise RuntimeError(f"Internal PDF xref formatting error: row length is {len(row)}.")
        xref_rows.append(row)

    trailer = (
        f"trailer\n<< /Size {total_entries} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")

    return b"".join(body_parts) + xref_header + b"".join(xref_rows) + trailer


def resolve_dummy_download_filename(original_filename: str) -> str:
    """
    Return the safe download filename for a dummy response.
    Supported extensions retain their original filename; unsupported extensions receive
    a clearly identified generic '.txt' filename so invalid bytes are never served under
    a binary/proprietary extension.
    """
    safe_name = _validate_safe_filename(original_filename, source_context="dummy_filename")
    path_obj = Path(safe_name)
    ext = path_obj.suffix.lower()

    if ext in SUPPORTED_DUMMY_EXTENSIONS:
        return safe_name

    stem = path_obj.stem if path_obj.stem else "archivo"
    return f"{stem}_generic_dummy.txt"


def generate_dummy_output_with_filename(original_filename: str) -> Tuple[str, bytes]:
    """
    Generate a plausible, harmless dummy output payload and its safe download filename.
    Unsupported extensions receive a clearly identified generic text download rather than
    serving invalid binary bytes under the original extension.
    """
    safe_name = _validate_safe_filename(original_filename, source_context="generate_dummy_output")
    ext = Path(safe_name).suffix.lower()
    download_filename = resolve_dummy_download_filename(safe_name)

    if ext == ".json":
        payload = (
            b'{\n'
            b'  "document_id": "DOC-2026-0419",\n'
            b'  "title": "Quarterly Operations Summary",\n'
            b'  "status": "archived",\n'
            b'  "items": [\n'
            b'    {"id": 101, "category": "general", "notes": "Routine review completed."},\n'
            b'    {"id": 102, "category": "logistics", "notes": "Inventory schedule updated."}\n'
            b'  ]\n'
            b'}\n'
        )
    elif ext in {".txt", ".md", ".log"}:
        payload = (
            b"Project Reference Notes\n"
            b"=======================\n"
            b"Date: 2026-10-15\n"
            b"Status: Standard Routine Log\n\n"
            b"1. Completed scheduled maintenance checks across standard nodes.\n"
            b"2. Archived routine weekly status metrics for team review.\n"
            b"3. No action items pending for the next cycle.\n"
        )
    elif ext == ".csv":
        payload = (
            b"item_id,department,category,status,updated_date\n"
            b"1001,Operations,Inventory,Completed,2026-10-01\n"
            b"1002,Logistics,Scheduling,Pending,2026-10-08\n"
            b"1003,Administration,Documentation,Archived,2026-10-14\n"
        )
    elif ext in {".html", ".htm"}:
        payload = (
            b"<!DOCTYPE html>\n"
            b"<html lang=\"en\">\n"
            b"<head><meta charset=\"utf-8\"><title>Department Summary</title></head>\n"
            b"<body>\n"
            b"  <h1>Routine Status Overview</h1>\n"
            b"  <p>All scheduled milestones for the current reporting period have been logged.</p>\n"
            b"</body>\n"
            b"</html>\n"
        )
    elif ext == ".png":
        buf = io.BytesIO()
        Image.new("RGB", (16, 16), color=(220, 228, 235)).save(buf, format="PNG")
        payload = buf.getvalue()
    elif ext in {".jpg", ".jpeg"}:
        buf = io.BytesIO()
        Image.new("RGB", (16, 16), color=(220, 228, 235)).save(buf, format="JPEG")
        payload = buf.getvalue()
    elif ext == ".gif":
        buf = io.BytesIO()
        Image.new("RGB", (16, 16), color=(220, 228, 235)).save(buf, format="GIF")
        payload = buf.getvalue()
    elif ext == ".bmp":
        buf = io.BytesIO()
        Image.new("RGB", (16, 16), color=(220, 228, 235)).save(buf, format="BMP")
        payload = buf.getvalue()
    elif ext == ".pdf":
        payload = _build_valid_dummy_pdf()
    else:
        payload = (
            f"GENERIC DUMMY PLACEHOLDER FILE ({download_filename})\n"
            f"====================================================\n"
            f"Original requested filename: {safe_name}\n"
            f"Notice: This is a generic placeholder text download generated for an "
            f"unsupported file format ({ext or 'no extension'}).\n"
            f"Sample Reference ID: REF-2026-8841\n"
        ).encode("utf-8")

    return download_filename, payload


def generate_dummy_output(original_filename: str) -> bytes:
    """
    Generate a plausible, harmless dummy output payload for the given filename.
    Preserves the original function signature returning bytes.
    """
    _, payload = generate_dummy_output_with_filename(original_filename)
    return payload


def encode_web_transfer(
    file_bytes: bytes,
    filename: str,
    output_dir: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, Any]:
    """
    Compress, chunk, and encode a file into Web Protocol QR payloads, generating 1 decoy QR.

    Writes QR images into a transfer-specific subdirectory inside output_dir and returns
    a dictionary containing transfer metadata, QR file paths, the ordered real sequence,
    and the decoy identifier.
    """
    if not isinstance(file_bytes, bytes):
        raise TypeError(f"file_bytes must be bytes, got {type(file_bytes).__name__}.")
    if len(file_bytes) == 0:
        raise ValueError("Cannot encode an empty file.")

    safe_filename = _validate_safe_filename(filename, source_context="encode_web_transfer")

    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size!r}.")

    base_out_dir = Path(output_dir).resolve()
    if base_out_dir.exists() and not base_out_dir.is_dir():
        raise ValueError(f"Output path exists and is not a directory: {base_out_dir}")

    original_sha256 = calculate_bytes_sha256(file_bytes)

    try:
        compressed_bytes = zlib.compress(file_bytes, level=zlib.Z_BEST_COMPRESSION)
    except zlib.error as exc:
        raise ValueError(f"zlib compression error: {exc}") from exc

    total_real_chunks = math.ceil(len(compressed_bytes) / chunk_size)
    if total_real_chunks > MAX_REAL_CHUNKS:
        raise ValueError(
            f"Compressed data ({len(compressed_bytes)} bytes) requires {total_real_chunks} chunks "
            f"at {chunk_size} bytes/chunk, exceeding the limit of {MAX_REAL_CHUNKS} real chunks."
        )

    real_chunks = [
        compressed_bytes[i : i + chunk_size]
        for i in range(0, len(compressed_bytes), chunk_size)
    ]

    # Generate 1 obfuscated decoy chunk with matching size characteristics
    decoy_size = len(real_chunks[0]) if real_chunks else min(chunk_size, len(compressed_bytes))
    decoy_bytes = secrets.token_bytes(max(1, decoy_size))

    transfer_id = str(uuid.uuid4())
    total_qrs = len(real_chunks) + DECOY_CHUNKS

    # Use a transfer-specific subdirectory to isolate temporary outputs
    transfer_dir = base_out_dir / transfer_id
    transfer_dir.mkdir(parents=True, exist_ok=False)

    allocated_ids: Set[str] = set()
    correct_sequence: List[str] = []
    payload_items: List[Dict[str, Any]] = []

    for chunk in real_chunks:
        qr_id = _generate_unique_qr_identifier(allocated_ids, total_qrs)
        correct_sequence.append(qr_id)
        payload_items.append({"qr_id": qr_id, "bytes": chunk})

    decoy_id = _generate_unique_qr_identifier(allocated_ids, total_qrs)
    payload_items.append({"qr_id": decoy_id, "bytes": decoy_bytes})

    # Shuffle using cryptographically strong randomness so file order never leaks the decoy
    secrets.SystemRandom().shuffle(payload_items)

    generated_files: List[str] = []
    for item in payload_items:
        b64_data = base64.b64encode(item["bytes"]).decode("ascii")
        if base64.b64decode(b64_data.encode("ascii")) != item["bytes"]:
            raise RuntimeError("Internal Base64 encoding verification failed.")

        payload_dict: Dict[str, Any] = {
            "web_protocol_version": WEB_PROTOCOL_VERSION,
            "transfer_id": transfer_id,
            "original_filename": safe_filename,
            "total_qrs": total_qrs,
            "original_sha256": original_sha256,
            "compression_method": COMPRESSION_METHOD,
            "qr_identifier": item["qr_id"],
            "chunk_data": b64_data,
        }

        payload_json = json.dumps(payload_dict, separators=(",", ":"), ensure_ascii=True)

        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(payload_json)

        try:
            qr.make(fit=True)
        except (DataOverflowError, ValueError) as exc:
            raise ValueError(
                f"Payload size ({len(payload_json)} bytes) exceeds maximum QR code capacity "
                f"at error correction level M. Reduce chunk_size and try again."
            ) from exc

        img = qr.make_image(fill_color="black", back_color="white")
        qr_filename = f"qr_web_{transfer_id[:8]}_QR-{int(item['qr_id']):02d}.png"
        out_path = transfer_dir / qr_filename
        img.save(out_path, format="PNG")
        generated_files.append(str(out_path))

    return {
        "web_protocol_version": WEB_PROTOCOL_VERSION,
        "transfer_id": transfer_id,
        "original_filename": safe_filename,
        "original_size_bytes": len(file_bytes),
        "compressed_size_bytes": len(compressed_bytes),
        "total_qrs": total_qrs,
        "real_chunk_count": len(real_chunks),
        "original_sha256": original_sha256,
        "compression_method": COMPRESSION_METHOD,
        "transfer_dir": str(transfer_dir),
        "generated_files": generated_files,
        "correct_sequence": correct_sequence,
        "decoy_identifier": decoy_id,
    }


def decode_web_qr_image(image_path: Union[str, Path]) -> str:
    """Decode a single Web Protocol QR PNG image using ZXing-CPP with OpenCV fallback."""
    path = Path(image_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"QR image file not found: {path}")

    try:
        raw_file_bytes = np.fromfile(str(path), dtype=np.uint8)
        image = cv2.imdecode(raw_file_bytes, cv2.IMREAD_COLOR)
    except Exception as exc:
        raise ValueError(f"Failed to read image file '{path.name}': {exc}") from exc

    if image is None:
        raise ValueError(f"File '{path.name}' could not be decoded as a valid image.")

    if zxingcpp is not None:
        try:
            barcodes = zxingcpp.read_barcodes(image)
            for barcode in barcodes:
                text = getattr(barcode, "text", None)
                if isinstance(text, str) and text:
                    return text
        except Exception:
            pass

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
        raise ValueError(f"OpenCV error while decoding '{path.name}': {exc}") from exc

    if points is None:
        raise ValueError(f"No QR code detected in '{path.name}'.")
    if not decoded_text:
        raise ValueError(f"QR code detected in '{path.name}', but payload could not be decoded.")

    return decoded_text


def decode_web_payload(raw_payload: str, source_name: str = "<unknown>") -> Dict[str, Any]:
    """
    Strictly parse and validate a Web Protocol JSON QR payload and decode its Base64 chunk_data.
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

    missing_keys = [k for k in REQUIRED_WEB_METADATA_TYPES if k not in payload]
    if missing_keys:
        raise ValueError(
            f"[{source_name}] Missing required metadata fields: {', '.join(missing_keys)}"
        )

    unexpected_keys = [k for k in payload if k not in REQUIRED_WEB_METADATA_TYPES]
    if unexpected_keys:
        raise ValueError(
            f"[{source_name}] Unexpected metadata fields: {', '.join(unexpected_keys)}"
        )

    for field, exp_type in REQUIRED_WEB_METADATA_TYPES.items():
        val = payload[field]
        if exp_type is int and isinstance(val, bool):
            raise ValueError(
                f"[{source_name}] Field '{field}' must be an integer, got boolean."
            )
        if not isinstance(val, exp_type):
            raise ValueError(
                f"[{source_name}] Field '{field}' must be of type {exp_type.__name__}, "
                f"got {type(val).__name__}."
            )

    if payload["web_protocol_version"] != WEB_PROTOCOL_VERSION:
        raise ValueError(
            f"[{source_name}] Unsupported web_protocol_version '{payload['web_protocol_version']}' "
            f"(expected '{WEB_PROTOCOL_VERSION}')."
        )

    if payload["compression_method"] != COMPRESSION_METHOD:
        raise ValueError(
            f"[{source_name}] Unsupported compression_method '{payload['compression_method']}' "
            f"(expected '{COMPRESSION_METHOD}')."
        )

    try:
        parsed_uuid = uuid.UUID(payload["transfer_id"])
    except ValueError as exc:
        raise ValueError(
            f"[{source_name}] Invalid transfer_id UUID format: '{payload['transfer_id']}'."
        ) from exc
    payload["transfer_id"] = str(parsed_uuid)

    payload["original_filename"] = _validate_safe_filename(
        payload["original_filename"], source_context=source_name
    )

    total_qrs = payload["total_qrs"]
    if not (MIN_TOTAL_QRS <= total_qrs <= MAX_TOTAL_QRS):
        raise ValueError(
            f"[{source_name}] Invalid total_qrs ({total_qrs}): "
            f"must be between {MIN_TOTAL_QRS} and {MAX_TOTAL_QRS}."
        )

    sha256_str = payload["original_sha256"].strip()
    if len(sha256_str) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha256_str):
        raise ValueError(
            f"[{source_name}] Invalid original_sha256 format: expected 64 hexadecimal characters."
        )
    payload["original_sha256"] = sha256_str.lower()

    payload["qr_identifier"] = _validate_qr_identifier_format(
        payload["qr_identifier"], source_context=source_name
    )

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


def validate_web_transfer_consistency(payloads: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Validate that all decoded payloads share identical transfer-wide metadata and have unique
    QR identifiers. Rejects duplicate QR identifiers and mixed transfers.

    Returns:
        A dictionary mapping each unique qr_identifier to its validated payload dict.
    """
    if not isinstance(payloads, list) or not payloads:
        raise ValueError("No QR payloads provided for validation.")

    reference = payloads[0]
    ref_source = reference.get("source_image", "payload_0")
    consistent_fields = (
        "web_protocol_version",
        "transfer_id",
        "original_filename",
        "total_qrs",
        "original_sha256",
        "compression_method",
    )

    payload_map: Dict[str, Dict[str, Any]] = {}

    for idx, item in enumerate(payloads):
        if not isinstance(item, dict):
            raise ValueError(f"Payload at index {idx} must be a dictionary.")
        src = item.get("source_image", f"payload_{idx}")

        for field in consistent_fields:
            if field not in item:
                raise ValueError(f"[{src}] Missing required field '{field}'.")
            if item[field] != reference[field]:
                raise ValueError(
                    f"Metadata mismatch on field '{field}': '{src}' has '{item[field]}', "
                    f"expected '{reference[field]}' (from '{ref_source}')."
                )

        qr_id = _validate_qr_identifier_format(
            item.get("qr_identifier", ""), source_context=src
        )
        if qr_id in payload_map:
            prev_src = payload_map[qr_id].get("source_image", "<unknown>")
            raise ValueError(
                f"Duplicate qr_identifier '{qr_id}' detected in '{src}' and '{prev_src}'."
            )

        payload_map[qr_id] = item

    return payload_map


def _validate_trusted_server_metadata(
    expected_sequence: Optional[List[str]],
    decoy_identifier: Optional[str],
    required_real_chunks: int,
    payload_map: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Validate trusted server-side expected_sequence and decoy_identifier metadata when provided.
    Ensures format validity, length consistency, no duplicate IDs, no overlap between
    real and decoy identifiers, and presence within the uploaded payload_map.
    """
    clean_expected: Optional[List[str]] = None
    clean_decoy: Optional[str] = None

    if expected_sequence is not None:
        if not isinstance(expected_sequence, list) or not expected_sequence:
            raise ValueError("Invalid expected_sequence metadata: must be a non-empty list.")
        if len(expected_sequence) != required_real_chunks:
            raise ValueError(
                f"Invalid expected_sequence metadata length: got {len(expected_sequence)}, "
                f"expected {required_real_chunks}."
            )
        seen_exp: Set[str] = set()
        clean_expected = []
        for idx, qid in enumerate(expected_sequence):
            cid = _validate_qr_identifier_format(
                qid, source_context=f"expected_sequence[{idx}]"
            )
            if cid in seen_exp:
                raise ValueError(
                    f"Invalid expected_sequence metadata: duplicate identifier '{cid}'."
                )
            if cid not in payload_map:
                raise ValueError(
                    f"Missing required real QR image for expected_sequence identifier '{cid}'."
                )
            seen_exp.add(cid)
            clean_expected.append(cid)

    if decoy_identifier is not None:
        clean_decoy = _validate_qr_identifier_format(
            decoy_identifier, source_context="decoy_identifier"
        )
        if clean_decoy not in payload_map:
            raise ValueError(
                f"Missing QR image for server decoy_identifier '{clean_decoy}'."
            )
        if clean_expected is not None and clean_decoy in set(clean_expected):
            raise ValueError(
                f"Invalid server metadata: decoy_identifier '{clean_decoy}' also appears in expected_sequence."
            )

    if clean_expected is not None and clean_decoy is None:
        leftover_ids = set(payload_map.keys()) - set(clean_expected)
        if len(leftover_ids) == 1:
            clean_decoy = next(iter(leftover_ids))

    return clean_expected, clean_decoy


def _safe_decompress(compressed_data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """Incrementally decompress zlib data with strict max_length enforcement."""
    if not compressed_data:
        raise ValueError("Cannot decompress empty byte stream.")

    try:
        decompressor = zlib.decompressobj()
        chunks: List[bytes] = []
        total_size = 0
        remaining_limit = max_size + 1
        block_size = 65536

        for i in range(0, len(compressed_data), block_size):
            block = compressed_data[i : i + block_size]
            part = decompressor.decompress(block, max_length=remaining_limit)
            if part:
                total_size += len(part)
                if total_size > max_size:
                    raise ValueError(
                        f"Decompressed output size exceeds safety limit of {max_size} bytes."
                    )
                remaining_limit = max_size + 1 - total_size
                chunks.append(part)

        while not decompressor.eof and (
            decompressor.unconsumed_tail or not decompressor.unused_data
        ):
            part = decompressor.decompress(b"", max_length=remaining_limit)
            if part:
                total_size += len(part)
                if total_size > max_size:
                    raise ValueError(
                        f"Decompressed output size exceeds safety limit of {max_size} bytes."
                    )
                remaining_limit = max_size + 1 - total_size
                chunks.append(part)
            else:
                break

        decompressed = b"".join(chunks)
    except zlib.error as exc:
        raise ValueError(f"zlib decompression failed: {exc}") from exc

    if not decompressor.eof:
        raise ValueError("Incomplete zlib stream: end-of-stream marker not reached.")
    if decompressor.unused_data:
        raise ValueError(
            f"Corrupted zlib stream: {len(decompressor.unused_data)} trailing bytes detected."
        )

    return decompressed


def reconstruct_web_transfer(
    payloads: List[Dict[str, Any]],
    submitted_sequence: List[str],
    expected_sequence: Optional[List[str]] = None,
    decoy_identifier: Optional[str] = None,
    output_dir: Optional[Union[str, Path]] = None,
    overwrite: bool = False,
) -> Tuple[bool, bytes]:
    """
    Validate uploaded QR payloads and reconstruct the original file using submitted_sequence.

    In Flask integration, `expected_sequence` and `decoy_identifier` MUST be supplied from
    trusted server-side transfer metadata (keyed by `transfer_id`), never from client input.

    Order of checks:
      1. Validate uploaded payloads consistency and reject duplicate QR payloads.
      2. Validate submitted_sequence format and reject duplicate sequence identifiers.
      3. Ensure all QR images (total_qrs) and all identifiers referenced in submitted_sequence
         were uploaded.
      4. Validate trusted server metadata (expected_sequence / decoy_identifier).
      5. Detect decoy identifier inclusion BEFORE checking required real-sequence length,
         so both replacing a real identifier with the decoy and appending the decoy to the
         real sequence route cleanly to the dummy output handler.
      6. Enforce required real-sequence length (total_qrs - 1) for non-decoy submissions.
      7. Reconstruct, decompress, and verify SHA-256; route any mismatch to dummy output.
    """
    if not isinstance(submitted_sequence, list) or not submitted_sequence:
        raise ValueError("submitted_sequence must be a non-empty list of QR identifiers.")

    # 1. Validate transfer consistency and reject duplicate uploaded QR payloads
    payload_map = validate_web_transfer_consistency(payloads)

    reference = payloads[0]
    total_qrs = reference["total_qrs"]
    required_real_chunks = total_qrs - DECOY_CHUNKS
    filename = reference["original_filename"]
    original_sha256 = reference["original_sha256"]

    # 2. Validate submitted_sequence format and uniqueness (reject malformed or duplicate IDs)
    normalized_sequence: List[str] = []
    seen_seq_ids: Set[str] = set()
    for idx, qid in enumerate(submitted_sequence):
        clean_id = _validate_qr_identifier_format(
            qid, source_context=f"submitted_sequence[{idx}]"
        )
        if clean_id in seen_seq_ids:
            raise ValueError(
                f"Duplicate QR identifier '{clean_id}' in submitted_sequence."
            )
        seen_seq_ids.add(clean_id)
        normalized_sequence.append(clean_id)

    # 3. Ensure all QR images referenced in submitted_sequence were uploaded
    for qid in normalized_sequence:
        if qid not in payload_map:
            raise ValueError(
                f"Missing QR image: identifier '{qid}' in submitted_sequence was not found "
                f"among uploaded QR codes."
            )

    # 4. Ensure the complete set of QR images (all real chunks + decoy) was uploaded
    if len(payload_map) < total_qrs:
        raise ValueError(
            f"Missing QR image(s): uploaded {len(payload_map)} of {total_qrs} required QR codes."
        )
    if len(payload_map) > total_qrs:
        raise ValueError(
            f"Excess QR images uploaded: received {len(payload_map)}, expected {total_qrs}."
        )

    # 5. Validate trusted server-side expected_sequence and decoy_identifier metadata
    clean_expected, clean_decoy = _validate_trusted_server_metadata(
        expected_sequence=expected_sequence,
        decoy_identifier=decoy_identifier,
        required_real_chunks=required_real_chunks,
        payload_map=payload_map,
    )

    # 6. Explicitly detect decoy identifier inclusion BEFORE checking required real-sequence length
    if clean_decoy is not None and clean_decoy in seen_seq_ids:
        return False, generate_dummy_output(filename)

    # 7. Validate required real-sequence length for non-decoy submissions
    if len(normalized_sequence) != required_real_chunks:
        raise ValueError(
            f"Invalid sequence length: submitted {len(normalized_sequence)} identifiers, "
            f"expected exactly {required_real_chunks} real chunk identifiers "
            f"(for total_qrs={total_qrs})."
        )

    # 8. Check against expected_sequence if supplied
    if clean_expected is not None:
        if seen_seq_ids != set(clean_expected) or normalized_sequence != clean_expected:
            return False, generate_dummy_output(filename)

    # 9. Concatenate chunks according to submitted_sequence and attempt decompression + verification
    compressed_stream = b"".join(
        payload_map[qid]["decoded_chunk_bytes"] for qid in normalized_sequence
    )

    try:
        decompressed_bytes = _safe_decompress(compressed_stream)
    except ValueError:
        return False, generate_dummy_output(filename)

    if not verify_bytes_sha256(decompressed_bytes, original_sha256):
        return False, generate_dummy_output(filename)

    # 10. Optional disk write ONLY when integrity verification succeeds; never overwrite unless permitted
    if output_dir is not None:
        target_dir = Path(output_dir).resolve() / reference["transfer_id"]
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / filename
        if out_path.exists() and not overwrite:
            raise FileExistsError(
                f"Destination file already exists: '{out_path}'. Refusing to overwrite."
            )
        out_path.write_bytes(decompressed_bytes)

    return True, decompressed_bytes


# ==========================================
# Unit Tests for Web Protocol
# ==========================================
if __name__ == "__main__":
    import copy
    import re
    import shutil
    import tempfile
    import unittest

    class TestWebProtocol(unittest.TestCase):
        def setUp(self) -> None:
            self.test_dir = tempfile.mkdtemp()
            self.sample_data = (
                b"Confidential Web Protocol Payload Line.\n" * 60
                + secrets.token_bytes(256)
            )
            self.filename = "report.txt"

        def tearDown(self) -> None:
            shutil.rmtree(self.test_dir, ignore_errors=True)

        def _encode_and_load_payloads(
            self,
            data: Optional[bytes] = None,
            filename: Optional[str] = None,
            chunk_size: int = 200,
        ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
            encoded = encode_web_transfer(
                data if data is not None else self.sample_data,
                filename if filename is not None else self.filename,
                self.test_dir,
                chunk_size=chunk_size,
            )
            loaded_payloads: List[Dict[str, Any]] = []
            for path_str in encoded["generated_files"]:
                raw_json = decode_web_qr_image(path_str)
                loaded_payloads.append(
                    decode_web_payload(raw_json, source_name=Path(path_str).name)
                )
            return encoded, loaded_payloads

        def test_01_successful_reconstruction(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            self.assertEqual(
                Path(encoded["transfer_dir"]).name, encoded["transfer_id"]
            )
            success, output = reconstruct_web_transfer(
                payloads,
                encoded["correct_sequence"],
                expected_sequence=encoded["correct_sequence"],
                decoy_identifier=encoded["decoy_identifier"],
            )
            self.assertTrue(success)
            self.assertEqual(output, self.sample_data)

        def test_02_wrong_order_routes_to_dummy(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            wrong_order = list(reversed(encoded["correct_sequence"]))
            if wrong_order == encoded["correct_sequence"]:
                wrong_order[0], wrong_order[1] = wrong_order[1], wrong_order[0]
            success, output = reconstruct_web_transfer(
                payloads,
                wrong_order,
                expected_sequence=encoded["correct_sequence"],
                decoy_identifier=encoded["decoy_identifier"],
            )
            self.assertFalse(success)
            self.assertEqual(output, generate_dummy_output(self.filename))

        def test_03_decoy_replacing_real_or_appended_routes_to_dummy(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()

            # Case A: Replacing a real identifier with the decoy identifier (same length N)
            seq_replaced = encoded["correct_sequence"][:-1] + [
                encoded["decoy_identifier"]
            ]
            success_rep, output_rep = reconstruct_web_transfer(
                payloads,
                seq_replaced,
                decoy_identifier=encoded["decoy_identifier"],
            )
            self.assertFalse(success_rep)
            self.assertEqual(output_rep, generate_dummy_output(self.filename))

            # Case B: Appending the decoy identifier to the full real sequence (length N + 1)
            seq_appended = encoded["correct_sequence"] + [
                encoded["decoy_identifier"]
            ]
            success_app, output_app = reconstruct_web_transfer(
                payloads,
                seq_appended,
                decoy_identifier=encoded["decoy_identifier"],
            )
            self.assertFalse(success_app)
            self.assertEqual(output_app, generate_dummy_output(self.filename))

            # Case C: Appending the decoy identifier when inferred via expected_sequence
            success_inf, output_inf = reconstruct_web_transfer(
                payloads,
                seq_appended,
                expected_sequence=encoded["correct_sequence"],
            )
            self.assertFalse(success_inf)
            self.assertEqual(output_inf, generate_dummy_output(self.filename))

        def test_04_missing_qr_raises_explicit_error(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            incomplete_payloads = payloads[:-1]
            with self.assertRaises(ValueError) as ctx:
                reconstruct_web_transfer(
                    incomplete_payloads, encoded["correct_sequence"]
                )
            self.assertIn("Missing QR image", str(ctx.exception))

        def test_05_duplicate_qr_raises_explicit_error(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            duplicated_payloads = payloads[:-1] + [copy.deepcopy(payloads[0])]
            with self.assertRaises(ValueError) as ctx:
                reconstruct_web_transfer(
                    duplicated_payloads, encoded["correct_sequence"]
                )
            self.assertIn("Duplicate qr_identifier", str(ctx.exception))

        def test_06_duplicate_identifiers_in_submitted_sequence_rejected(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            dup_seq = [encoded["correct_sequence"][0]] + encoded["correct_sequence"][:-1]
            with self.assertRaises(ValueError) as ctx:
                reconstruct_web_transfer(payloads, dup_seq)
            self.assertIn("Duplicate QR identifier", str(ctx.exception))

        def test_07_invalid_expected_sequence_metadata_rejected(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()

            # Case A: Wrong length in expected_sequence
            with self.assertRaises(ValueError) as ctx1:
                reconstruct_web_transfer(
                    payloads,
                    encoded["correct_sequence"],
                    expected_sequence=encoded["correct_sequence"][:-1],
                )
            self.assertIn("Invalid expected_sequence metadata length", str(ctx1.exception))

            # Case B: Duplicate ID inside expected_sequence
            dup_expected = [encoded["correct_sequence"][0]] + encoded["correct_sequence"][:-1]
            with self.assertRaises(ValueError) as ctx2:
                reconstruct_web_transfer(
                    payloads,
                    encoded["correct_sequence"],
                    expected_sequence=dup_expected,
                )
            self.assertIn("duplicate identifier", str(ctx2.exception))

            # Case C: Unknown ID inside expected_sequence
            uploaded_ids = {payload["qr_identifier"] for payload in payloads}
            unknown_id = next(
                str(number)
                for number in range(1, MAX_TOTAL_QRS + 1)
                if str(number) not in uploaded_ids
            )
            unknown_expected = [unknown_id] + encoded["correct_sequence"][1:]
            with self.assertRaises(ValueError) as ctx3:
                reconstruct_web_transfer(
                    payloads,
                    encoded["correct_sequence"],
                    expected_sequence=unknown_expected,
                )
            self.assertIn("Missing required real QR image", str(ctx3.exception))

            # Case D: Decoy ID overlapping with expected_sequence
            with self.assertRaises(ValueError) as ctx4:
                reconstruct_web_transfer(
                    payloads,
                    encoded["correct_sequence"],
                    expected_sequence=encoded["correct_sequence"],
                    decoy_identifier=encoded["correct_sequence"][0],
                )
            self.assertIn("also appears in expected_sequence", str(ctx4.exception))

        def test_08_invalid_base64_rejected(self) -> None:
            encoded, _ = self._encode_and_load_payloads()
            raw_json = decode_web_qr_image(encoded["generated_files"][0])
            raw_dict = json.loads(raw_json)
            raw_dict["chunk_data"] = "!!!NOT_VALID_BASE64!!!"
            with self.assertRaises(ValueError) as ctx:
                decode_web_payload(json.dumps(raw_dict), source_name="bad_b64.png")
            self.assertIn("Base64", str(ctx.exception))

        def test_09_mixed_transfer_ids_rejected(self) -> None:
            encoded_a, payloads_a = self._encode_and_load_payloads()
            _, payloads_b = self._encode_and_load_payloads(
                data=b"Second distinct transfer payload" * 15, filename="other.txt"
            )
            mixed_payloads = payloads_a[:-1] + [payloads_b[0]]
            with self.assertRaises(ValueError) as ctx:
                reconstruct_web_transfer(mixed_payloads, encoded_a["correct_sequence"])
            self.assertIn("Metadata mismatch on field 'transfer_id'", str(ctx.exception))

        def test_10_windows_and_unsafe_filenames_rejected(self) -> None:
            unsafe_filenames = [
                "../secret.txt",
                "..\\secret.txt",
                "/etc/passwd",
                "..",
                "",
                "CON",
                "con.txt",
                "PRN.pdf",
                "AUX",
                "NUL.json",
                "COM1",
                "com1.txt",
                "LPT1.doc",
                "LPT9.txt",
                "bad:name.txt",
                "bad*name.txt",
                "bad?name.txt",
                'bad"name.txt',
                "bad<name>.txt",
                "bad|name.txt",
                "trailingdot.",
                "trailing_space.txt ",
                " leading_space.txt",
            ]
            for unsafe_name in unsafe_filenames:
                with self.assertRaises(
                    ValueError, msg=f"Failed to reject unsafe filename: {unsafe_name!r}"
                ):
                    encode_web_transfer(self.sample_data, unsafe_name, self.test_dir)

            encoded, _ = self._encode_and_load_payloads()
            raw_json = decode_web_qr_image(encoded["generated_files"][0])
            for payload_bad_name in ["../evil.txt", "CON.txt", "invalid|char.txt", "dot."]:
                raw_dict = json.loads(raw_json)
                raw_dict["original_filename"] = payload_bad_name
                with self.assertRaises(ValueError):
                    decode_web_payload(json.dumps(raw_dict), source_name="unsafe_fn.png")

        def test_11_incorrect_sha256_routes_to_dummy(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            tampered_sha = "0" * 64
            for p in payloads:
                p["original_sha256"] = tampered_sha
            success, output = reconstruct_web_transfer(
                payloads, encoded["correct_sequence"]
            )
            self.assertFalse(success)
            self.assertEqual(output, generate_dummy_output(self.filename))

        def test_12_invalid_sequence_length_rejected_when_no_decoy(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            too_short = encoded["correct_sequence"][:-1]
            with self.assertRaises(ValueError) as ctx:
                reconstruct_web_transfer(
                    payloads,
                    too_short,
                    decoy_identifier=encoded["decoy_identifier"],
                )
            self.assertIn("Invalid sequence length", str(ctx.exception))

        def test_13_invalid_chunk_size_rejected(self) -> None:
            for bad_size in [0, -100, True, "700"]:
                with self.assertRaises((ValueError, TypeError)):
                    encode_web_transfer(
                        self.sample_data,
                        self.filename,
                        self.test_dir,
                        chunk_size=bad_size,  # type: ignore[arg-type]
                    )

        def test_14_no_corrupted_or_dummy_overwrites_existing_file(self) -> None:
            encoded, payloads = self._encode_and_load_payloads()
            out_root = Path(self.test_dir) / "reconstructed"
            success, _ = reconstruct_web_transfer(
                payloads,
                encoded["correct_sequence"],
                output_dir=out_root,
                overwrite=False,
            )
            self.assertTrue(success)
            saved_file = out_root / encoded["transfer_id"] / self.filename
            self.assertEqual(saved_file.read_bytes(), self.sample_data)

            seq_with_decoy = encoded["correct_sequence"][:-1] + [
                encoded["decoy_identifier"]
            ]
            success_bad, dummy_bytes = reconstruct_web_transfer(
                payloads,
                seq_with_decoy,
                decoy_identifier=encoded["decoy_identifier"],
                output_dir=out_root,
                overwrite=True,
            )
            self.assertFalse(success_bad)
            self.assertNotEqual(dummy_bytes, self.sample_data)
            self.assertEqual(saved_file.read_bytes(), self.sample_data)

            with self.assertRaises(FileExistsError):
                reconstruct_web_transfer(
                    payloads,
                    encoded["correct_sequence"],
                    output_dir=out_root,
                    overwrite=False,
                )

        def test_15_pdf_dummy_structure_xref_20_bytes_and_parser(self) -> None:
            pdf_bytes = generate_dummy_output("document.pdf")
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4\n"))
            self.assertTrue(pdf_bytes.endswith(b"%%EOF\n"))

            # Verify dynamic /Length matches exact stream content length
            stream_match = re.search(
                rb"<< /Length (\d+) >>\nstream\n(.*?)\nendstream",
                pdf_bytes,
                flags=re.DOTALL,
            )
            self.assertIsNotNone(stream_match)
            declared_len = int(stream_match.group(1))  # type: ignore[union-attr]
            actual_stream = stream_match.group(2)  # type: ignore[union-attr]
            self.assertEqual(declared_len, len(actual_stream))

            # Verify startxref points to exact byte offset of 'xref\n'
            actual_xref_index = pdf_bytes.index(b"xref\n")
            match = re.search(rb"startxref\n(\d+)\n%%EOF", pdf_bytes)
            self.assertIsNotNone(match)
            recorded_xref_offset = int(match.group(1))  # type: ignore[union-attr]
            self.assertEqual(recorded_xref_offset, actual_xref_index)

            # Verify each classic xref row is strictly 20 bytes
            trailer_index = pdf_bytes.index(b"trailer\n")
            xref_block = pdf_bytes[actual_xref_index:trailer_index]
            xref_header_end = xref_block.index(b"\n", len(b"xref\n")) + 1
            entries_bytes = xref_block[xref_header_end:]
            self.assertEqual(len(entries_bytes), 6 * 20)
            for i in range(6):
                entry = entries_bytes[i * 20 : (i + 1) * 20]
                self.assertEqual(len(entry), 20)
                self.assertTrue(entry.endswith(b"\r\n"))

            # If a real PDF parser (pypdf, PyPDF2, or fitz/PyMuPDF) is installed, parse the PDF
            for parser_mod in ("pypdf", "PyPDF2"):
                try:
                    mod = __import__(parser_mod)
                    reader = mod.PdfReader(io.BytesIO(pdf_bytes), strict=True)
                    self.assertEqual(len(reader.pages), 1)
                    extracted = reader.pages[0].extract_text()
                    self.assertIn("Project Summary Notes", extracted)
                    break
                except ImportError:
                    continue

        def test_16_dummy_output_for_supported_and_unsupported_extensions(self) -> None:
            for sample_name in ["notes.txt", "data.json", "table.csv", "index.html"]:
                content = generate_dummy_output(sample_name).lower()
                self.assertNotIn(b"corrupted", content)
                self.assertNotIn(b"invalid", content)
                self.assertNotIn(b"error", content)
                self.assertEqual(resolve_dummy_download_filename(sample_name), sample_name)

            for unsupported_name in ["archive.zip", "binary.exe", "model.bin", "archive.tar"]:
                dl_name, raw_bytes = generate_dummy_output_with_filename(unsupported_name)
                self.assertTrue(dl_name.endswith("_generic_dummy.txt"))
                self.assertNotEqual(dl_name, unsupported_name)
                self.assertIn(b"GENERIC DUMMY PLACEHOLDER FILE", raw_bytes)
                self.assertIn(unsupported_name.encode("utf-8"), raw_bytes)

            for ext, fmt in [
                ("sample.jpg", "JPEG"),
                ("sample.png", "PNG"),
                ("sample.gif", "GIF"),
                ("sample.bmp", "BMP"),
            ]:
                raw = generate_dummy_output(ext)
                with Image.open(io.BytesIO(raw)) as im:
                    self.assertEqual(im.format, fmt)

    unittest.main()