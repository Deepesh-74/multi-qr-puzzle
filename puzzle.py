"""Chain-Link Matching Puzzle with Misleading Sequence Labels for Multi-QR Reconstruction."""

import argparse
import secrets
import sys
from typing import Any, Dict, List, Set

START_KEY = "START"
END_KEY = "END"
MIN_CHUNKS = 1
MAX_CHUNKS = 10
DEFAULT_KEY_BYTES = 4  # Produces 8-character uppercase hexadecimal link tokens


def _generate_unique_link_key(existing_keys: Set[str], num_bytes: int = DEFAULT_KEY_BYTES) -> str:
    """Generate a cryptographically random hex token distinct from reserved and existing keys.

    Args:
        existing_keys: Set of keys already allocated in the current transfer.
        num_bytes: Number of random bytes to generate (hex length is 2 * num_bytes).

    Returns:
        A unique uppercase hexadecimal key string.
    """
    if num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer.")

    while True:
        candidate = secrets.token_hex(num_bytes).upper()
        if candidate not in existing_keys and candidate not in {START_KEY, END_KEY}:
            existing_keys.add(candidate)
            return candidate


def generate_misleading_labels(total_chunks: int) -> List[str]:
    """Generate a true cryptographic derangement of sequence labels.

    For multi-chunk transfers (total_chunks > 1), this function guarantees a true derangement
    where NO element retains its original position (i.e., labels[i] never corresponds to true index i + 1).
    For a single chunk (total_chunks == 1), a derangement is impossible, so it returns ['SEQ-01/01'].

    Args:
        total_chunks: Number of chunks in the transfer (1 to 10).

    Returns:
        A list of formatted label strings (e.g., 'SEQ-04/05') where no label matches its true position.

    Raises:
        ValueError: If total_chunks is outside the supported range [1, 10].
    """
    if isinstance(total_chunks, bool) or not isinstance(total_chunks, int):
        raise TypeError(f"total_chunks must be an integer, got {type(total_chunks).__name__}.")
    if not (MIN_CHUNKS <= total_chunks <= MAX_CHUNKS):
        raise ValueError(
            f"total_chunks must be between {MIN_CHUNKS} and {MAX_CHUNKS} (got {total_chunks})."
        )

    base_numbers = list(range(1, total_chunks + 1))

    if total_chunks == 1:
        shuffled_numbers = base_numbers[:]
    else:
        # Rejection-sample with CSPRNG until a valid derangement is found
        # (no element i has shuffled_numbers[i] == base_numbers[i])
        while True:
            shuffled_numbers = base_numbers[:]
            for i in range(total_chunks - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                shuffled_numbers[i], shuffled_numbers[j] = (
                    shuffled_numbers[j],
                    shuffled_numbers[i],
                )
            
            # Check derangement condition: fixed_points == 0
            if not any(s == b for s, b in zip(shuffled_numbers, base_numbers)):
                break

    return [f"SEQ-{num:02d}/{total_chunks:02d}" for num in shuffled_numbers]


def generate_puzzle_metadata(total_chunks: int) -> List[Dict[str, Any]]:
    """Generate chain-link puzzle metadata and misleading sequence labels for a transfer.

    Creates a linked chain of chunks where:
      - Chunk 0 has entry_key == 'START'
      - Chunk (N - 1) has exit_key == 'END'
      - For every intermediate boundary i, chunk[i]['exit_key'] == chunk[i + 1]['entry_key']
      - Every chunk receives a randomized deranged misleading_label independent of its true index.
      - SECURITY NOTE: true_chunk_index is strictly omitted to prevent order leakage.

    Args:
        total_chunks: Total number of chunks in the transfer (1 to 10).

    Returns:
        A list of dictionaries ordered by true chunk sequence (0 to total_chunks - 1),
        each containing 'total_chunks', 'misleading_label', 'entry_key', and 'exit_key'.

    Raises:
        TypeError: If total_chunks is not an int.
        ValueError: If total_chunks is outside the supported [1, 10] bounds.
    """
    misleading_labels = generate_misleading_labels(total_chunks)

    allocated_keys: Set[str] = {START_KEY, END_KEY}
    intermediate_keys = [
        _generate_unique_link_key(allocated_keys) for _ in range(total_chunks - 1)
    ]

    puzzle_chain: List[Dict[str, Any]] = []
    for idx in range(total_chunks):
        entry_key = START_KEY if idx == 0 else intermediate_keys[idx - 1]
        exit_key = END_KEY if idx == total_chunks - 1 else intermediate_keys[idx]

        puzzle_chain.append(
            {
                "total_chunks": total_chunks,
                "misleading_label": misleading_labels[idx],
                "entry_key": entry_key,
                "exit_key": exit_key,
            }
        )

    return puzzle_chain


def _validate_chunk_structure(
    chunk: Dict[str, Any], position: int
) -> None:
    """Validate that a single chunk dictionary contains required puzzle fields and types."""
    if not isinstance(chunk, dict):
        raise ValueError(
            f"Item at position {position} must be a dict, got {type(chunk).__name__}."
        )

    required_str_fields = ("entry_key", "exit_key", "misleading_label")
    for field in required_str_fields:
        if field not in chunk:
            raise ValueError(f"Chunk at position {position} is missing required field '{field}'.")
        val = chunk[field]
        if not isinstance(val, str) or not val.strip():
            raise ValueError(
                f"Field '{field}' in chunk at position {position} must be a non-empty string."
            )

    if "total_chunks" in chunk:
        tc = chunk["total_chunks"]
        if isinstance(tc, bool) or not isinstance(tc, int):
            raise ValueError(
                f"Field 'total_chunks' in chunk at position {position} must be an integer."
            )


def validate_chunk_ordering(
    ordered_chunks: List[Dict[str, Any]],
    expected_total_chunks: int | None = None,
) -> bool:
    """Validate a receiver-provided chunk ordering using strictly entry and exit keys.

    Checks performed:
      1. Chunk count is within [1, 10] and matches expected_total_chunks / metadata.
      2. No duplicate chunks, duplicate misleading labels, duplicate entry keys, or
         duplicate exit keys exist.
      3. No ambiguous links (branching or cycles) exist across the chunk set.
      4. Exactly one chunk has entry_key == 'START' and is placed first (index 0).
      5. Exactly one chunk has exit_key == 'END' and is placed last (index N - 1).
      6. Every consecutive pair (i, i + 1) satisfies chunk[i]['exit_key'] == chunk[i + 1]['entry_key'].

    Args:
        ordered_chunks: List of chunk metadata dictionaries in the proposed sequence.
        expected_total_chunks: Optional expected chunk count to verify against missing chunks.

    Returns:
        True if the proposed ordering forms a complete, unbroken, unambiguous chain from
        START to END.

    Raises:
        ValueError: With a descriptive reason if the ordering or chunk set is invalid.
    """
    if not isinstance(ordered_chunks, list) or not ordered_chunks:
        raise ValueError("ordered_chunks must be a non-empty list of chunk dictionaries.")

    actual_count = len(ordered_chunks)

    if expected_total_chunks is not None:
        if isinstance(expected_total_chunks, bool) or not isinstance(expected_total_chunks, int):
            raise ValueError("expected_total_chunks must be an integer.")
        if not (MIN_CHUNKS <= expected_total_chunks <= MAX_CHUNKS):
            raise ValueError(
                f"expected_total_chunks ({expected_total_chunks}) must be between "
                f"{MIN_CHUNKS} and {MAX_CHUNKS}."
            )
        if actual_count < expected_total_chunks:
            raise ValueError(
                f"Missing chunks detected: received {actual_count} of {expected_total_chunks} chunks."
            )
        if actual_count > expected_total_chunks:
            raise ValueError(
                f"Excess or duplicate chunks detected: received {actual_count} chunks, "
                f"expected {expected_total_chunks}."
            )

    if not (MIN_CHUNKS <= actual_count <= MAX_CHUNKS):
        raise ValueError(
            f"Invalid number of chunks ({actual_count}): puzzle supports {MIN_CHUNKS} to {MAX_CHUNKS}."
        )

    seen_entry_keys: Set[str] = set()
    seen_exit_keys: Set[str] = set()
    seen_labels: Set[str] = set()

    for idx, chunk in enumerate(ordered_chunks):
        _validate_chunk_structure(chunk, idx)

        if "total_chunks" in chunk and chunk["total_chunks"] != actual_count:
            raise ValueError(
                f"Missing or excess chunks: chunk at position {idx} specifies "
                f"total_chunks={chunk['total_chunks']}, but {actual_count} chunks were provided."
            )

        entry_k = chunk["entry_key"]
        exit_k = chunk["exit_key"]
        label = chunk["misleading_label"]

        if entry_k == exit_k:
            raise ValueError(
                f"Self-loop detected at position {idx} (label '{label}'): "
                f"entry_key and exit_key cannot both be '{entry_k}'."
            )
        if entry_k == END_KEY:
            raise ValueError(
                f"Invalid key at position {idx}: entry_key cannot be reserved token '{END_KEY}'."
            )
        if exit_k == START_KEY:
            raise ValueError(
                f"Invalid key at position {idx}: exit_key cannot be reserved token '{START_KEY}'."
            )

        if entry_k in seen_entry_keys and label in seen_labels:
            raise ValueError(
                f"Duplicate chunk detected at position {idx} (label '{label}', entry_key '{entry_k}')."
            )
        if entry_k in seen_entry_keys:
            raise ValueError(
                f"Ambiguous link or duplicate entry_key '{entry_k}' detected at position {idx}."
            )
        if exit_k in seen_exit_keys:
            raise ValueError(
                f"Ambiguous link or duplicate exit_key '{exit_k}' detected at position {idx}."
            )
        if label in seen_labels:
            raise ValueError(
                f"Duplicate misleading_label '{label}' detected at position {idx}."
            )

        seen_entry_keys.add(entry_k)
        seen_exit_keys.add(exit_k)
        seen_labels.add(label)

    # Verify presence of START and END tokens in the set before checking boundary positions
    if START_KEY not in seen_entry_keys:
        raise ValueError(f"Missing initial chunk: no chunk contains entry_key='{START_KEY}'.")
    if END_KEY not in seen_exit_keys:
        raise ValueError(f"Missing terminal chunk: no chunk contains exit_key='{END_KEY}'.")

    # Verify boundary anchors
    if ordered_chunks[0]["entry_key"] != START_KEY:
        raise ValueError(
            f"Invalid start of chain: first chunk (label '{ordered_chunks[0]['misleading_label']}') "
            f"has entry_key='{ordered_chunks[0]['entry_key']}', expected '{START_KEY}'."
        )

    if ordered_chunks[-1]["exit_key"] != END_KEY:
        raise ValueError(
            f"Invalid end of chain: last chunk (label '{ordered_chunks[-1]['misleading_label']}') "
            f"has exit_key='{ordered_chunks[-1]['exit_key']}', expected '{END_KEY}'."
        )

    # Verify unbroken chain links across all consecutive chunk pairs
    for i in range(actual_count - 1):
        current_chunk = ordered_chunks[i]
        next_chunk = ordered_chunks[i + 1]
        if current_chunk["exit_key"] != next_chunk["entry_key"]:
            raise ValueError(
                f"Broken chain link between position {i} (label '{current_chunk['misleading_label']}', "
                f"exit_key='{current_chunk['exit_key']}') and position {i + 1} "
                f"(label '{next_chunk['misleading_label']}', entry_key='{next_chunk['entry_key']}')."
            )

    return True


def solve_puzzle_chain(unordered_chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reconstruct the true chunk sequence from an unordered list using entry and exit keys.

    Args:
        unordered_chunks: List of chunk dictionaries in any order.

    Returns:
        A new list of chunk dictionaries ordered from START to END.

    Raises:
        ValueError: If the chain cannot be uniquely reconstructed or fails validation.
    """
    if not isinstance(unordered_chunks, list) or not unordered_chunks:
        raise ValueError("unordered_chunks must be a non-empty list.")

    entry_map: Dict[str, Dict[str, Any]] = {}
    for idx, chunk in enumerate(unordered_chunks):
        _validate_chunk_structure(chunk, idx)
        entry_k = chunk["entry_key"]
        if entry_k in entry_map:
            raise ValueError(
                f"Ambiguous puzzle chain: multiple chunks share entry_key '{entry_k}'."
            )
        entry_map[entry_k] = chunk

    if START_KEY not in entry_map:
        raise ValueError(f"Cannot solve puzzle: no chunk has entry_key='{START_KEY}'.")

    reconstructed: List[Dict[str, Any]] = []
    current_key = START_KEY

    while len(reconstructed) < len(unordered_chunks):
        next_chunk = entry_map.get(current_key)
        if next_chunk is None:
            raise ValueError(
                f"Broken chain link while solving: no chunk has entry_key='{current_key}'."
            )
        reconstructed.append(next_chunk)
        current_key = next_chunk["exit_key"]
        if current_key == END_KEY:
            break

    # Run full validation to catch unvisited chunks (disconnected cycles), count mismatches, etc.
    validate_chunk_ordering(reconstructed, expected_total_chunks=len(unordered_chunks))
    return reconstructed


def _run_cli_demo(num_chunks: int) -> int:
    """Execute a terminal demonstration of puzzle generation, derangement validation, and chain reconstruction."""
    print(f"=== Chain-Link Matching Puzzle Demonstration ({num_chunks} Chunks) ===\n")

    try:
        true_chain = generate_puzzle_metadata(num_chunks)
    except Exception as exc:
        print(f"[ERROR] Failed to generate puzzle metadata: {exc}", file=sys.stderr)
        return 1

    # Attach sample payload strings to illustrate chunk reconstruction using local enumeration
    for idx, item in enumerate(true_chain):
        item["sample_payload"] = f"ChunkData_{idx + 1}"

    print("1. Generated Chunks (in true data order):")
    derangement_violations = 0
    for true_idx, item in enumerate(true_chain):
        label_num = int(item["misleading_label"].split("-")[1].split("/")[0])
        is_deranged_pos = (label_num != true_idx + 1)
        if not is_deranged_pos and num_chunks > 1:
            derangement_violations += 1
        
        print(
            f"   True Index: {true_idx} | "
            f"Misleading Label: {item['misleading_label']} (Deranged: {is_deranged_pos}) | "
            f"Link: [{item['entry_key']:^8} -> {item['exit_key']:^8}] | "
            f"Payload: {item['sample_payload']}"
        )

    print(f"\n   -> Derangement Check: {derangement_violations} labels matched original positions (0 required for N > 1).")

    # Simulate sorting naively by the misleading sequence label
    naive_label_order = sorted(true_chain, key=lambda c: c["misleading_label"])
    print("\n2. Receiver Naively Sorts by Misleading Sequence Labels:")
    for pos, item in enumerate(naive_label_order):
        print(
            f"   Pos {pos}: {item['misleading_label']} | "
            f"Link: [{item['entry_key']:^8} -> {item['exit_key']:^8}] | "
            f"Payload: {item['sample_payload']}"
        )

    if num_chunks > 1:
        try:
            validate_chunk_ordering(naive_label_order, expected_total_chunks=num_chunks)
        except ValueError as err:
            print(f"   -> Validation Result: REJECTED ({err})")

    # Demonstrate rejection of missing chunks
    if num_chunks > 1:
        print("\n3. Receiver Attempts Validation with a Missing Chunk:")
        try:
            validate_chunk_ordering(true_chain[:-1], expected_total_chunks=num_chunks)
        except ValueError as err:
            print(f"   -> Validation Result: REJECTED ({err})")

    # Solve and validate using the Chain-Link Matching Puzzle
    print("\n4. Solving and Validating via Entry/Exit Key Chain:")
    solved_chain = solve_puzzle_chain(naive_label_order)
    is_valid = validate_chunk_ordering(solved_chain, expected_total_chunks=num_chunks)
    reconstructed_text = " + ".join(c["sample_payload"] for c in solved_chain)
    print(f"   -> Validation Result: ACCEPTED (valid={is_valid})")
    print(f"   -> Reconstructed Sequence: {reconstructed_text}")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Demonstrate the Chain-Link Matching Puzzle with Misleading Sequence Labels."
    )
    parser.add_argument(
        "-n",
        "--chunks",
        type=int,
        default=5,
        help=f"Number of sample chunks to simulate ({MIN_CHUNKS}-{MAX_CHUNKS}, default: 5).",
    )
    args = parser.parse_args()
    sys.exit(_run_cli_demo(args.chunks))