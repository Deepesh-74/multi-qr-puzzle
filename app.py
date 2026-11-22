
import io
import mimetypes
import re
import secrets
import tempfile
import zipfile
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    send_from_directory,
    abort,
    url_for
)

from web_protocol import (
    encode_web_transfer,
    decode_web_qr_image,
    decode_web_payload,
    validate_web_transfer_consistency,
    reconstruct_web_transfer,
    generate_dummy_output_with_filename
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

QR_OUTPUT_DIR = Path("web_generated_qr")

ACTIVE_TRANSFERS = {}
DOWNLOADS = {}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/sender", methods=["GET", "POST"])
def sender():
    error = None
    result = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a file."
        else:
            file_bytes = uploaded_file.read()

            try:
                transfer = encode_web_transfer(
                    file_bytes=file_bytes,
                    filename=uploaded_file.filename,
                    output_dir=QR_OUTPUT_DIR,
                    chunk_size=700
                )

                ACTIVE_TRANSFERS[transfer["transfer_id"]] = transfer

                qr_images = []

                for file_path in transfer["generated_files"]:
                    filename = Path(file_path).name

                    qr_images.append({
                        "filename": filename,
                        "url": url_for(
                            "qr_image",
                            transfer_id=transfer["transfer_id"],
                            filename=filename
                        )
                    })

                result = {
                    "transfer_id": transfer["transfer_id"],
                    "original_filename": transfer["original_filename"],
                    "total_qrs": transfer["total_qrs"],
                    "real_chunk_count": transfer["real_chunk_count"],
                    "original_sha256": transfer["original_sha256"],
                    "correct_sequence": " - ".join(
                        transfer["correct_sequence"]
                    ),
                    "qr_images": qr_images
                }

            except (ValueError, OSError, RuntimeError) as exc:
                error = str(exc)

    return render_template(
        "sender.html",
        error=error,
        result=result
    )


@app.route("/receiver", methods=["GET", "POST"])
def receiver():
    error = None
    result = None

    if request.method == "POST":
        sequence_text = request.form.get("sequence", "").strip()

        sequence_parts = [
            part for part in re.split(r"[\s,;-]+", sequence_text)
            if part
        ]

        if not sequence_parts or any(
            len(part) != 1 or part not in "123456789"
            for part in sequence_parts
        ):
            error = "Enter a valid numeric sequence, such as 7 - 2 - 5 - 1."

        else:
            uploaded_files = [
                item for item in request.files.getlist("qr_files")
                if item and item.filename
            ]

            if len(uploaded_files) < 2 or len(uploaded_files) > 9:
                error = "Upload all QR images. The transfer must contain 2 to 9 QR codes."

            else:
                try:
                    payloads = []

                    with tempfile.TemporaryDirectory(
                        prefix="qr_receiver_"
                    ) as temp_dir:

                        for index, uploaded in enumerate(uploaded_files):
                            extension = Path(uploaded.filename).suffix.lower()

                            if extension not in {".png", ".jpg", ".jpeg"}:
                                raise ValueError(
                                    f"Unsupported image format: {uploaded.filename}"
                                )

                            image_path = (
                                Path(temp_dir) / f"qr_upload_{index + 1}{extension}"
                            )

                            uploaded.save(image_path)

                            raw_payload = decode_web_qr_image(image_path)

                            payload = decode_web_payload(
                                raw_payload,
                                source_name=image_path.name
                            )

                            payloads.append(payload)

                        payload_map = validate_web_transfer_consistency(payloads)

                        transfer_id = payloads[0]["transfer_id"]
                        transfer = ACTIVE_TRANSFERS.get(transfer_id)

                        if transfer is None:
                            raise ValueError(
                                "Transfer not found. The sender must generate the QR "
                                "collection on this running website first."
                            )

                        success, output_bytes = reconstruct_web_transfer(
                            payloads=payloads,
                            submitted_sequence=sequence_parts,
                            expected_sequence=transfer["correct_sequence"],
                            decoy_identifier=transfer["decoy_identifier"]
                        )

                        original_filename = transfer["original_filename"]

                        if success:
                            download_filename = original_filename
                            status = "Reconstruction completed"
                        else:
                            download_filename, output_bytes = (
                                generate_dummy_output_with_filename(
                                    original_filename
                                )
                            )
                            status = "Reconstruction completed"

                        download_token = secrets.token_urlsafe(24)

                        DOWNLOADS[download_token] = {
                            "bytes": output_bytes,
                            "filename": download_filename,
                            "mime_type": (
                                mimetypes.guess_type(download_filename)[0]
                                or "application/octet-stream"
                            )
                        }

                        result = {
                            "status": status,
                            "download_url": url_for(
                                "download_file",
                                token=download_token
                            )
                        }

                except (ValueError, FileNotFoundError, OSError) as exc:
                    error = str(exc)

    return render_template(
        "receiver.html",
        error=error,
        result=result
    )


@app.route("/qr/<transfer_id>/<filename>")
def qr_image(transfer_id, filename):
    transfer = ACTIVE_TRANSFERS.get(transfer_id)

    if transfer is None:
        abort(404)

    allowed_files = {
        Path(path).name
        for path in transfer["generated_files"]
    }

    if filename not in allowed_files:
        abort(404)

    return send_from_directory(
        transfer["transfer_dir"],
        filename,
        mimetype="image/png"
    )


@app.route("/download-qrs/<transfer_id>")
def download_qr_collection(transfer_id):
    """Download every generated QR image for a transfer as one ZIP archive."""
    transfer = ACTIVE_TRANSFERS.get(transfer_id)

    if transfer is None:
        abort(404)

    transfer_dir = Path(transfer["transfer_dir"]).resolve()
    generated_files = transfer.get("generated_files", [])

    if not generated_files:
        abort(404)

    archive_buffer = io.BytesIO()

    try:
        with zipfile.ZipFile(
            archive_buffer,
            mode="w",
            compression=zipfile.ZIP_DEFLATED
        ) as archive:
            for generated_path in generated_files:
                qr_path = Path(generated_path).resolve()

                # Only include files generated inside this transfer's directory.
                if qr_path.parent != transfer_dir or not qr_path.is_file():
                    abort(404)

                archive.write(qr_path, arcname=qr_path.name)
    except (OSError, zipfile.BadZipFile):
        abort(404)

    archive_buffer.seek(0)
    return send_file(
        archive_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"qr_collection_{transfer_id[:8]}.zip"
    )


@app.route("/download/<token>")
def download_file(token):
    item = DOWNLOADS.pop(token, None)

    if item is None:
        abort(404)

    return send_file(
        io.BytesIO(item["bytes"]),
        mimetype=item["mime_type"],
        as_attachment=True,
        download_name=item["filename"]
    )


@app.errorhandler(413)
def file_too_large(error):
    return "Upload exceeds the 10 MB limit.", 413


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
