\# Puzzle-Based Multi-QR File Reconstruction with Misleading Sequence Labels



\## 1. Project Overview



This project implements a puzzle-based file transfer and reconstruction system using multiple QR codes.



A file is compressed, divided into smaller chunks, and encoded into individual QR codes. Each QR code contains metadata and a chunk of the compressed file.



Instead of revealing the actual sequence through filenames or numerical labels, the system uses misleading sequence labels and chain-link puzzle keys. The receiver solves these links to reconstruct the original chunk order.



After reconstruction, the compressed data is decompressed and its SHA-256 hash is verified against the original file hash.



\## 2. Key Features



\- File compression using zlib.

\- Splitting compressed files into multiple chunks.

\- QR code generation using Python.

\- Misleading sequence labels to conceal the actual chunk order.

\- Entry and exit keys to establish a puzzle chain.

\- Reconstruction independent of QR filenames and input order.

\- QR decoding using ZXing-CPP with OpenCV fallback.

\- Strict metadata and Base64 validation.

\- SHA-256 integrity verification.

\- Decompression size limit to reduce decompression-bomb risks.

\- Detection of missing, duplicate, inconsistent, and unreadable QR codes.



\## 3. System Architecture



\### Sender



1\. Select the input file.

2\. Calculate its SHA-256 hash.

3\. Compress the file using zlib.

4\. Split the compressed data into chunks.

5\. Generate puzzle metadata for each chunk.

6\. Assign misleading sequence labels and entry/exit keys.

7\. Encode each chunk and its metadata into a QR code.

8\. Save the generated QR images.



\### Receiver



1\. Load the QR code images from a directory.

2\. Decode QR payloads using ZXing-CPP, with OpenCV fallback.

3\. Validate the payload structure and metadata.

4\. Check consistency across all QR codes.

5\. Solve the entry/exit key chain.

6\. Reorder chunks into their original sequence.

7\. Concatenate the compressed chunks.

8\. Decompress the reconstructed data.

9\. Verify the SHA-256 hash.

10\. Save the reconstructed file only after successful integrity verification.



\## 4. Project Structure



```text

multi\_qr\_project/

│

├── encoder.py

├── decoder.py

├── puzzle.py

├── integrity.py

├── requirements.txt

├── README.md

│

├── test\_files/

├── generated\_qr/

├── reconstructed/

├── reconstructed\_shuffled/

├── reconstructed\_text/

├── reconstructed\_limit/

├── reconstructed\_pdf/

│

├── documentation/

├── presentation/

└── test\_results/

```



\## 5. Technologies Used



| Technology | Purpose |

|---|---|

| Python | Core implementation |

| zlib | File compression and decompression |

| qrcode | QR code generation |

| OpenCV | QR image processing and fallback decoding |

| ZXing-CPP | Primary QR decoding |

| NumPy | Image array processing |

| Base64 | Binary chunk representation in JSON |

| SHA-256 | File integrity verification |



\## 6. Installation



\### Prerequisites



\- Python 3.13 or compatible Python version.

\- Windows, Linux, or macOS.

\- A terminal or command prompt.



\### Create a virtual environment



```bash

python -m venv venv

```



\### Activate the virtual environment



Windows CMD:



```cmd

venv\\Scripts\\activate

```



\### Install dependencies



```bash

python -m pip install -r requirements.txt

```



\## 7. Running the Project



\### Generate QR codes



Example:



```bash

python encoder.py test\_files/sample.txt --output-dir generated\_qr --chunk-size 600

```



The encoder generates multiple QR images containing the file chunks and puzzle metadata.



\### Reconstruct the original file



```bash

python decoder.py generated\_qr --output-dir reconstructed

```



The decoder solves the puzzle chain, reconstructs the compressed data, decompresses it, and verifies the resulting file.



\### Run decoder unit tests



```bash

python decoder.py --test

```



\### Test puzzle generation and solving



```bash

python puzzle.py --chunks 10

```



\## 8. Testing and Evaluation



The prototype was evaluated using the following scenarios:



| Test | Expected behavior |

|---|---|

| Normal file reconstruction | Successful reconstruction |

| Shuffled QR filenames | Correct reconstruction |

| Missing QR code | Reject incomplete puzzle chain |

| Duplicate QR code | Reject ambiguous chain |

| Unreadable QR image | Reject decoding |

| Partially damaged QR | May recover through QR error correction |

| Invalid Base64 data | Reject malformed payload |

| Mismatched transfer IDs | Reject inconsistent transfer |

| Unsafe filename | Reject path traversal |

| Incorrect SHA-256 | Reject integrity verification |

| Maximum 10 QR chunks | Successful reconstruction when within capacity |

| Empty input file | Reject empty input |



\## 9. Security and Integrity Considerations



The system uses SHA-256 to verify that the reconstructed file matches the original file.



The puzzle chain conceals the actual chunk ordering through misleading labels and linked keys.



However, the current implementation is not an encryption system. Puzzle-based ordering is an obfuscation mechanism, not a substitute for cryptographic security.



SHA-256 verifies data consistency but does not authenticate the sender or protect metadata against a malicious attacker.



Future versions can integrate authenticated encryption such as AES-GCM and digital signatures for stronger security.



\## 10. Limitations



\- The current implementation supports a maximum of 10 QR codes per transfer.

\- Large or poorly compressible files may exceed the QR capacity limit.

\- Empty input files are currently rejected.

\- QR scanning quality depends on image resolution and physical scanning conditions.

\- The current puzzle mechanism does not provide cryptographic confidentiality.

\- SHA-256 alone does not provide sender authentication.

\- The receiver requires all necessary chunks to reconstruct the original file.



\## 11. Future Enhancements



\- AES-GCM encryption for confidentiality and authentication.

\- Digital signatures for sender verification.

\- Dynamic QR chunk sizing.

\- Support for larger files through multiple transfer batches.

\- Improved error recovery for missing or damaged QR codes.

\- Graphical user interface for encoding and reconstruction.

\- Mobile-based QR scanning and reconstruction.

\- Performance evaluation across different QR sizes and error-correction levels.



\## 12. Conclusion



This project demonstrates a multi-QR file reconstruction approach that combines compression, chunking, misleading sequence labels, and chain-link puzzle solving.



The receiver can reconstruct files even when QR images are presented in an arbitrary order, provided all required chunks are available and valid.



SHA-256 verification ensures that the reconstructed output matches the original file before it is saved.

