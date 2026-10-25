# DES for Task 2 of the Rotor Machine + DES project.
# Uses CBC mode, PKCS#7 padding, and the Python standard library.

import argparse
import csv
from pathlib import Path
from secrets import token_bytes
from statistics import median
from time import perf_counter_ns
import tracemalloc

# These are the fixed DES tables from FIPS PUB 46-3.
# Table positions start at 1 and count from the leftmost bit.

IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

FP = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

EXPANSION = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)

P = (
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
)

PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)

SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

S_BOXES = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)


BLOCK_SIZE = 8


# Check that the input is bytes and has the expected length.
def require_bytes(value: bytes, name: str, length: int | None = None) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must contain exactly {length} bytes")


# Rearrange the bits using the positions in the given table.
def _permute(value: int, width: int, table: tuple[int, ...]) -> int:
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (width - position)) & 1)
    return result


# Rotate a 28-bit key half to the left.
def _rotate28(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFF


# Remove the parity bits and create the sixteen 48-bit round keys.
def generate_round_keys(key: bytes) -> tuple[int, ...]:
    require_bytes(key, "key", BLOCK_SIZE)
    state = _permute(int.from_bytes(key, "big"), 64, PC1)
    left, right = state >> 28, state & 0x0FFFFFFF
    keys = []
    for shift in SHIFTS:
        left, right = _rotate28(left, shift), _rotate28(right, shift)
        keys.append(_permute((left << 28) | right, 56, PC2))
    return tuple(keys)


# Expand the right half, mix in the round key, and apply the S-boxes.
def _feistel(right: int, subkey: int) -> int:
    mixed = _permute(right, 32, EXPANSION) ^ subkey
    substituted = 0
    for index, box in enumerate(S_BOXES):
        six_bits = (mixed >> (42 - 6 * index)) & 0x3F
        row = ((six_bits >> 4) & 2) | (six_bits & 1)
        column = (six_bits >> 1) & 0x0F
        substituted = (substituted << 4) | box[row][column]
    return _permute(substituted, 32, P)


class DES:

    # Create the round keys once for this DES key.
    def __init__(self, key: bytes):
        self._round_keys = generate_round_keys(key)

    # Return the round keys so they can be checked or displayed.
    @property
    def round_keys(self) -> tuple[int, ...]:
        return self._round_keys

    # Run one eight-byte block through all sixteen DES rounds.
    def _transform(self, block: bytes, subkeys: tuple[int, ...]) -> bytes:
        require_bytes(block, "block", BLOCK_SIZE)
        permuted = _permute(int.from_bytes(block, "big"), 64, IP)
        left, right = permuted >> 32, permuted & 0xFFFFFFFF
        for subkey in subkeys:
            left, right = right, left ^ _feistel(right, subkey)
        result = _permute((right << 32) | left, 64, FP)
        return result.to_bytes(BLOCK_SIZE, "big")

    # Encrypt one eight-byte block using the round keys in order.
    def encrypt_block(self, block: bytes) -> bytes:
        return self._transform(block, self._round_keys)

    # Decrypt one eight-byte block using the round keys in reverse order.
    def decrypt_block(self, block: bytes) -> bytes:
        return self._transform(block, self._round_keys[::-1])


# Add PKCS#7 padding to fill the last eight-byte block.
def pad(data: bytes) -> bytes:
    require_bytes(data, "data")
    count = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([count]) * count


# Check the padding bytes and remove them from the message.
def unpad(data: bytes) -> bytes:
    require_bytes(data, "data")
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("padded data must be a nonempty multiple of 8 bytes")
    count = data[-1]
    if not 1 <= count <= BLOCK_SIZE or data[-count:] != bytes([count]) * count:
        raise ValueError("invalid PKCS#7 padding (wrong key or damaged payload)")
    return data[:-count]


# XOR the matching bytes from two blocks.
def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


# Pad the message, encrypt it with CBC, and put the IV at the front.
def encrypt_bytes(plaintext: bytes, key: bytes, *, iv: bytes | None = None) -> bytes:
    require_bytes(plaintext, "plaintext")
    cipher = DES(key)
    if iv is None:
        iv = token_bytes(BLOCK_SIZE)
    require_bytes(iv, "iv", BLOCK_SIZE)
    output = bytearray(iv)
    previous = iv
    padded = pad(plaintext)
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        previous = cipher.encrypt_block(_xor(block, previous))
        output.extend(previous)
    return bytes(output)


# Read the IV, decrypt the CBC blocks, and remove the padding.
def decrypt_bytes(payload: bytes, key: bytes) -> bytes:
    require_bytes(payload, "payload")
    cipher = DES(key)
    if len(payload) < 2 * BLOCK_SIZE or len(payload) % BLOCK_SIZE:
        raise ValueError("payload must contain an 8-byte IV and complete ciphertext blocks")
    previous = payload[:BLOCK_SIZE]
    output = bytearray()
    for offset in range(BLOCK_SIZE, len(payload), BLOCK_SIZE):
        block = payload[offset:offset + BLOCK_SIZE]
        output.extend(_xor(cipher.decrypt_block(block), previous))
        previous = block
    return unpad(bytes(output))


# Convert text to UTF-8 and return the encrypted message as hex.
def encrypt_text(plaintext: str, key: bytes, *, iv: bytes | None = None) -> str:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be str")
    return encrypt_bytes(plaintext.encode("utf-8"), key, iv=iv).hex().upper()


# Decrypt a hex message and convert the result back to text.
def decrypt_text(payload_hex: str, key: bytes) -> str:
    if not isinstance(payload_hex, str):
        raise TypeError("payload_hex must be str")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as error:
        raise ValueError("payload must be hexadecimal") from error
    return decrypt_bytes(payload, key).decode("utf-8")


DEMO_KEY_HEX = "133457799BBCDFF1"
TASK_MESSAGES = ("HELLO", "HOPE", "NEW YEAR")


# Read a key written as hex and check that it contains eight bytes.
def parse_key(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("key must be hexadecimal") from error
    if len(key) != 8:
        raise argparse.ArgumentTypeError("key must contain exactly 8 bytes (16 hex digits)")
    return key


# Encrypt and decrypt the three project messages and print the results.
def run_demo(key: bytes, csv_path: Path | None = None) -> int:
    rows = []
    for message in TASK_MESSAGES:
        encrypted = encrypt_text(message, key)
        recovered = decrypt_text(encrypted, key)
        rows.append((message, encrypted, recovered, str(message == recovered)))

    print("Task-2: Implementing DES")
    print("DES-CBC | 16 rounds | UTF-8 | PKCS#7 padding")
    print(f"Demonstration key (hex): {key.hex().upper()}")
    print("Encrypted text = IV (first 16 hex digits) + ciphertext")
    print("A fresh random IV is used for each message.\n")
    headers = ("Initial Information", "Encrypted Text (hex)", "Decrypted Text", "Matches")
    widths = tuple(max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(4))
    row_format = " | ".join(f"{{:<{width}}}" for width in widths)
    print(row_format.format(*headers))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(row_format.format(*row))

    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(rows)
        print(f"\nResults saved to {csv_path}")
    return 0 if all(row[3] == "True" for row in rows) else 1


# Measure encryption time, decryption time, and Python memory use.
def benchmark(message: bytes, iterations: int) -> dict:
    key = bytes.fromhex("133457799BBCDFF1")
    iv = bytes.fromhex("1234567890ABCDEF")
    payload = encrypt_bytes(message, key, iv=iv)
    if decrypt_bytes(payload, key) != message:
        raise RuntimeError("warm-up round trip failed")
    encryption_times, decryption_times = [], []
    for _ in range(iterations):
        start = perf_counter_ns()
        encrypted = encrypt_bytes(message, key, iv=iv)
        encryption_times.append(perf_counter_ns() - start)
        start = perf_counter_ns()
        recovered = decrypt_bytes(encrypted, key)
        decryption_times.append(perf_counter_ns() - start)
        if recovered != message:
            raise RuntimeError("benchmark round trip failed")
    tracemalloc.start()
    try:
        encrypted = encrypt_bytes(message, key, iv=iv)
        decrypt_bytes(encrypted, key)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {
        "message_bytes": len(message),
        "iterations": iterations,
        "encryption_median_ms": round(median(encryption_times) / 1_000_000, 6),
        "decryption_median_ms": round(median(decryption_times) / 1_000_000, 6),
        "round_trip_peak_python_bytes": peak,
        "time_complexity": "O(n), n = input bytes; fixed 16 rounds per block",
        "space_complexity": "O(n), message and result buffers",
    }


# Read the command and run the demo, encryption, decryption, or benchmark.
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DES project")
    commands = parser.add_subparsers(dest="command")

    demo = commands.add_parser("demo", help="run HELLO, HOPE, and NEW YEAR")
    demo.add_argument("--key", type=parse_key, default=bytes.fromhex(DEMO_KEY_HEX))
    demo.add_argument("--csv", type=Path, help="save the results as CSV")

    encrypt = commands.add_parser("encrypt", help="encrypt a message")
    encrypt.add_argument("text")
    encrypt.add_argument("--key", required=True, type=parse_key)

    decrypt = commands.add_parser("decrypt", help="decrypt a hex message")
    decrypt.add_argument("payload")
    decrypt.add_argument("--key", required=True, type=parse_key)

    timing = commands.add_parser("benchmark", help="measure DES time and memory use")
    timing.add_argument("--message", default="WELCOME TO PUERTO RICO")
    timing.add_argument("--iterations", type=int, default=100)
    timing.add_argument("--csv", type=Path)

    args = parser.parse_args(argv)

    try:
        if args.command in (None, "demo"):
            key = getattr(args, "key", bytes.fromhex(DEMO_KEY_HEX))
            return run_demo(key, getattr(args, "csv", None))
        if args.command == "encrypt":
            print(encrypt_text(args.text, args.key))
        elif args.command == "decrypt":
            print(decrypt_text(args.payload, args.key))
        elif args.command == "benchmark":
            if args.iterations < 1:
                parser.error("iterations must be positive")
            result = benchmark(args.message.encode("utf-8"), args.iterations)
            print("DES-CBC benchmark (fixed test IV; random-IV generation excluded)")
            for label, value in result.items():
                print(f"{label}: {value}")
            if args.csv:
                args.csv.parent.mkdir(parents=True, exist_ok=True)
                with args.csv.open("w", newline="", encoding="utf-8") as output:
                    writer = csv.DictWriter(output, fieldnames=list(result))
                    writer.writeheader()
                    writer.writerow(result)
        return 0
    except (ValueError, OSError) as error:
        parser.exit(2, f"error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
