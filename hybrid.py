"""Rotor -> DES encryption and reverse decryption using the existing modules.
Run: python hybrid.py. Results and benchmarks print only to the terminal.
The existing rotor uppercases text and uses carry stepping.
"""

from statistics import median
from time import perf_counter_ns
import tracemalloc

from des.des import DEMO_KEY_HEX, encrypt_bytes, decrypt_bytes
from rotor_machine.rotor_machine import RotorMachine, START_POSITIONS

KEY = bytes.fromhex(DEMO_KEY_HEX)
POSITIONS = START_POSITIONS
IV = bytes.fromhex("1234567890ABCDEF")  # Fixed IV for benchmarks only.
ITERATIONS = 100
MESSAGES = ("HOW ARE YOU", "HAPPY NEW YEAR", "WELCOME TO PUERTO RICO")


def rotor_encrypt(message):
    return RotorMachine(POSITIONS).encrypt(message)


def rotor_decrypt(ciphertext):
    # Start a fresh machine at the same positions used for encryption.
    return RotorMachine(POSITIONS).decrypt(ciphertext)


def encrypt_message(message, iv=None):
    e1 = rotor_encrypt(message)
    return encrypt_bytes(e1.encode("utf-8"), KEY, iv=iv)


def decrypt_message(payload):
    d1 = decrypt_bytes(payload, KEY).decode("utf-8")
    return rotor_decrypt(d1)


def benchmark(encrypt, decrypt, message):
    """Measure median times and a separate round-trip peak Python allocation."""
    if decrypt(encrypt()) != message:
        raise RuntimeError("Warm-up round trip failed")
    encryption_times, decryption_times = [], []
    for _ in range(ITERATIONS):
        start = perf_counter_ns()
        encrypted = encrypt()
        encryption_times.append(perf_counter_ns() - start)
        start = perf_counter_ns()
        recovered = decrypt(encrypted)
        decryption_times.append(perf_counter_ns() - start)
        if recovered != message:
            raise RuntimeError("Benchmark round trip failed")
    tracemalloc.start()
    try:
        encrypted = encrypt()
        recovered = decrypt(encrypted)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    if recovered != message:
        raise RuntimeError("Memory-probe round trip failed")
    round_trips = [a + b for a, b in zip(encryption_times, decryption_times)]
    return (median(encryption_times) / 1e6, median(decryption_times) / 1e6,
            median(round_trips) / 1e6, sum(round_trips) / 1e6, peak)


def main():
    print("Task 3: Hybrid cryptosystem (Table 3)")
    print(f"Demo DES key: {KEY.hex().upper()} | Rotor positions: {POSITIONS}")
    print("E2 is hex: 8-byte IV followed by ciphertext; fresh random IV per message.\n")
    for message in MESSAGES:
        e1 = rotor_encrypt(message)
        e2 = encrypt_message(message)
        d1 = decrypt_bytes(e2, KEY).decode("utf-8")
        d2 = decrypt_message(e2)
        if e1 != d1 or message != d2:
            raise RuntimeError("Hybrid stages did not recover the original message")
        print(f"M: {message}\nE1: {e1}\nE2: {e2.hex().upper()}\n"
              f"D1: {d1}\nD2: {d2}\nMatches: True\n")

    print("Performance comparison: rotor, DES, hybrid (Table 4)")
    print("All three: O(n) time and O(n) buffer space, n = input bytes.")
    print("Rotor: 3 rotors; DES: 16 rounds/block; hybrid: rotor + DES.")
    print("Times include rotor setup / DES key scheduling; hex and I/O excluded.")
    print("Fixed benchmark IV excludes random-IV generation, matching the DES benchmark.")
    print("Peak = separate round-trip Python allocations in bytes, not process RAM.")
    print("Round trip = median encrypt + decrypt pair; Total = all timed round trips.")
    pattern = MESSAGES[-1] + " "
    messages = MESSAGES + tuple((pattern * (size // len(pattern) + 1))[:size]
                               for size in (64, 256, 1024, 4096))
    for message in messages:
        data = message.encode("utf-8")
        operations = (
            ("Rotor", lambda: rotor_encrypt(message), rotor_decrypt, message),
            ("DES", lambda: encrypt_bytes(data, KEY, iv=IV),
             lambda payload: decrypt_bytes(payload, KEY), data),
            ("Hybrid", lambda: encrypt_message(message, iv=IV), decrypt_message, message),
        )
        label = message if len(message) <= 22 else f"{len(data)} ASCII bytes"
        print(f"\nInput: {label} | {len(data)} bytes | {ITERATIONS} iterations", flush=True)
        print(f"{'Algorithm':<10} {'Encrypt ms':>12} {'Decrypt ms':>12} "
              f"{'Round trip ms':>14} {'Total ms':>12} {'Peak bytes':>12}")
        for name, encrypt, decrypt, expected in operations:
            enc, dec, total, elapsed, peak = benchmark(encrypt, decrypt, expected)
            print(f"{name:<10} {enc:>12.6f} {dec:>12.6f} "
                  f"{total:>14.6f} {elapsed:>12.6f} {peak:>12}", flush=True)


if __name__ == "__main__":
    main()
