# Checks the DES examples, padding, and project messages.
# ai gen tests
import csv
import io
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from des import DES, decrypt_bytes, decrypt_text, encrypt_bytes, encrypt_text
from des import TASK_MESSAGES, main
from des import pad, unpad

KEY = bytes.fromhex("133457799BBCDFF1")
IV = bytes.fromhex("1234567890ABCDEF")

## Generated Tests.

class BlockCipherTests(unittest.TestCase):
    # Check a DES example with a known ciphertext.
    def test_known_block_answer_in_both_directions(self):
        cipher = DES(KEY)
        plaintext = bytes.fromhex("0123456789ABCDEF")
        ciphertext = bytes.fromhex("85E813540F0AB405")
        self.assertEqual(cipher.encrypt_block(plaintext), ciphertext)
        self.assertEqual(cipher.decrypt_block(ciphertext), plaintext)

    # Check the DES result against the NIST test vector.
    def test_nist_movs_variable_plaintext_answer(self):
        cipher = DES(bytes.fromhex("0101010101010101"))
        plaintext = bytes.fromhex("8000000000000000")
        ciphertext = bytes.fromhex("95F8A5E5DD31D900")
        self.assertEqual(cipher.encrypt_block(plaintext), ciphertext)
        self.assertEqual(cipher.decrypt_block(ciphertext), plaintext)

    # Check the three block examples from FIPS 81.
    def test_fips81_ecb_answers_in_both_directions(self):
        cipher = DES(bytes.fromhex("0123456789ABCDEF"))
        pairs = (
            ("4e6f772069732074", "3fa40e8a984d4815"),
            ("68652074696d6520", "6a271787ab8883f9"),
            ("666f7220616c6c20", "893d51ec4b563b53"),
        )
        for plain_hex, cipher_hex in pairs:
            with self.subTest(plain_hex=plain_hex):
                plain, encrypted = bytes.fromhex(plain_hex), bytes.fromhex(cipher_hex)
                self.assertEqual(cipher.encrypt_block(plain), encrypted)
                self.assertEqual(cipher.decrypt_block(encrypted), plain)

    # Check the round-key sizes and the first and last round keys.
    def test_subkey_width_and_known_endpoints(self):
        keys = DES(KEY).round_keys
        self.assertEqual(len(keys), 16)
        self.assertTrue(all(0 <= value < 2**48 for value in keys))
        self.assertEqual(keys[0], 0x1B02EFFC7072)
        self.assertEqual(keys[-1], 0xCB3D8B0E17F5)

    # Check that changing only the parity bits leaves the round keys the same.
    def test_parity_bits_do_not_change_encryption(self):
        flipped = bytes(byte ^ 1 for byte in KEY)
        self.assertEqual(DES(KEY).round_keys, DES(flipped).round_keys)

    # Check that invalid keys and block sizes are rejected.
    def test_key_and_block_validation(self):
        for length in (0, 7, 9, 16):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    DES(bytes(length))
                with self.assertRaises(ValueError):
                    DES(KEY).encrypt_block(bytes(length))
                with self.assertRaises(ValueError):
                    DES(KEY).decrypt_block(bytes(length))
        with self.assertRaises(TypeError):
            DES("12345678")
        with self.assertRaises(TypeError):
            DES(KEY).encrypt_block("12345678")


class MessageTests(unittest.TestCase):
    # Check that all three project messages are recovered correctly.
    def test_required_assignment_messages(self):
        for message in TASK_MESSAGES:
            with self.subTest(message=message):
                payload = encrypt_text(message, KEY, iv=IV)
                self.assertEqual(decrypt_text(payload, KEY), message)

    # Compare the first three encrypted CBC blocks with the FIPS 81 example.
    def test_fips81_cbc_first_three_blocks(self):
        key = bytes.fromhex("0123456789ABCDEF")
        plaintext = b"Now is the time for all "
        expected = bytes.fromhex(
            "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"
        )
        payload = encrypt_bytes(plaintext, key, iv=IV)
        self.assertEqual(payload[:8], IV)
        self.assertEqual(payload[8:32], expected)
        self.assertEqual(decrypt_bytes(payload, key), plaintext)

    # Decrypt the published CBC example with a valid padding block added.
    def test_cbc_decryption_against_independent_ciphertext(self):
        key = bytes.fromhex("0123456789ABCDEF")
        known_ciphertext = bytes.fromhex(
            "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"
        )
        last_block = known_ciphertext[-8:]
        padding_input = bytes(byte ^ 8 for byte in last_block)
        padding_block = DES(key).encrypt_block(padding_input)
        self.assertEqual(
            decrypt_bytes(IV + known_ciphertext + padding_block, key),
            b"Now is the time for all ",
        )

    # Check empty messages and lengths around an eight-byte boundary.
    def test_empty_and_boundary_length_binary_messages(self):
        for length in (0, 1, 7, 8, 9, 15, 16, 17, 64, 256):
            with self.subTest(length=length):
                message = bytes(index % 256 for index in range(length))
                encrypted = encrypt_bytes(message, KEY, iv=IV)
                self.assertEqual(len(encrypted), 8 + (length // 8 + 1) * 8)
                self.assertEqual(decrypt_bytes(encrypted, KEY), message)

    # Check that spaces, Unicode characters, and null bytes are preserved.
    def test_unicode_spaces_and_nulls_are_preserved(self):
        for message in ("  NEW YEAR  ", "\x00HELLO\x00", "¡Hola, Puerto Rico! 🔐", "\n\t"):
            with self.subTest(message=message):
                self.assertEqual(decrypt_text(encrypt_text(message, KEY, iv=IV), KEY), message)

    # Check that each encryption asks for a new IV.
    def test_default_iv_is_generated_per_encryption(self):
        with patch("des.token_bytes", side_effect=[bytes(8), bytes([1]) * 8]) as random:
            first = encrypt_bytes(b"HELLO", KEY)
            second = encrypt_bytes(b"HELLO", KEY)
        self.assertEqual(random.call_count, 2)
        self.assertNotEqual(first, second)
        self.assertEqual(decrypt_bytes(first, KEY), b"HELLO")
        self.assertEqual(decrypt_bytes(second, KEY), b"HELLO")

    # Check the padding for the project messages and an empty message.
    def test_padding_examples_and_full_block(self):
        self.assertEqual(pad(b"HELLO"), b"HELLO\x03\x03\x03")
        self.assertEqual(pad(b"HOPE"), b"HOPE\x04\x04\x04\x04")
        self.assertEqual(pad(b"NEW YEAR"), b"NEW YEAR" + bytes([8]) * 8)
        self.assertEqual(unpad(pad(b"")), b"")

    # Check that incorrect padding is rejected.
    def test_invalid_padding_is_rejected(self):
        for invalid in (b"", b"A", b"A" * 7 + b"\x00", b"A" * 7 + b"\x09", b"A" * 6 + b"\x03\x02"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    unpad(invalid)

    # Change a ciphertext byte and check that the damaged padding is rejected.
    def test_damaged_padding_is_rejected(self):
        damaged = bytearray(encrypt_bytes(b"NEW YEAR", KEY, iv=IV))
        damaged[15] ^= 1
        with self.assertRaisesRegex(ValueError, "padding"):
            decrypt_bytes(bytes(damaged), KEY)

    # Check that incomplete messages and incorrectly sized IVs are rejected.
    def test_payload_and_iv_validation(self):
        for length in (0, 8, 15, 17, 23):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    decrypt_bytes(bytes(length), KEY)
        for iv in (b"", bytes(7), bytes(9)):
            with self.assertRaises(ValueError):
                encrypt_bytes(b"HELLO", KEY, iv=iv)
        with self.assertRaises(ValueError):
            decrypt_text("not hex", KEY)
        with self.assertRaises(TypeError):
            encrypt_bytes("HELLO", KEY)


class CommandLineTests(unittest.TestCase):
    # Check that the demo saves all three messages and their results.
    def test_demo_and_csv_have_all_three_verified_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "results.csv"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["demo", "--csv", str(csv_path)])
            self.assertEqual(result, 0)
            with csv_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual([row["Initial Information"] for row in rows], list(TASK_MESSAGES))
            for row in rows:
                self.assertEqual(decrypt_text(row["Encrypted Text (hex)"], KEY), row["Decrypted Text"])
                self.assertEqual(row["Matches"], "True")

    # Check the encrypt and decrypt commands together.
    def test_encrypt_and_decrypt_commands(self):
        encrypted_output = io.StringIO()
        with redirect_stdout(encrypted_output):
            self.assertEqual(main(["encrypt", "NEW YEAR", "--key", KEY.hex()]), 0)
        decrypted_output = io.StringIO()
        with redirect_stdout(decrypted_output):
            self.assertEqual(main(["decrypt", encrypted_output.getvalue().strip(), "--key", KEY.hex()]), 0)
        self.assertEqual(decrypted_output.getvalue().strip(), "NEW YEAR")


if __name__ == "__main__":
    unittest.main()
