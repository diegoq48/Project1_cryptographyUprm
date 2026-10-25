"""Implements a three-rotor encryption and decryption machine for Task 1.

The program builds three substitution rotors, steps them after each
encrypted letter, reverses the process to decrypt, and prints the
Table 2 results for HOPE, HELLO, and NEW YEAR.

This is an educational rotor cipher, not a secure encryption algorithm.
"""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SIZE = len(ALPHABET)

# Stores the fixed wirring of each rotor as a permutation of the alphabet.
ROTOR_WIRINGS = (
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
)

# Lists the Table 2 test messages and the shared starting positions.
TEST_MESSAGES = ("HOPE", "HELLO", "NEW YEAR")
START_POSITIONS = (0, 0, 0)


class Rotor:
    """Represents one substitution rotor with a position that can change."""

    def __init__(self, wiring, position=0):
        # Saves the rotor wiring and its startng position.
        self.wiring = wiring
        self.position = position

    def step(self):
        """Advances the rotor by one and reports whether it completed a full turn."""
        self.position = (self.position + 1) % SIZE
        return self.position == 0

    def substitute(self, index):
        """Sends a letter index through the rotor in the foward direction."""
        # Shifts the index, looks up the wired letter, and shifts it back.
        letter = self.wiring[(index + self.position) % SIZE]
        return (ALPHABET.index(letter) - self.position) % SIZE

    def invert(self, index):
        """Sends a letter index through the rotor in the reverse direction."""
        # Shifts the index, finds where the wiring holds it, and shifts it back.
        letter = ALPHABET[(index + self.position) % SIZE]
        return (self.wiring.index(letter) - self.position) % SIZE


class RotorMachine:
    """Combines three rotors into a machine that encrypts and decrypts text."""

    def __init__(self, positions=START_POSITIONS):
        # Checks that exactly three valid postions are given.
        if len(positions) != 3 or any(
            not isinstance(p, int) or not 0 <= p < SIZE for p in positions
        ):
            raise ValueError("Provide three integer rotor positions from 0 to 25.")
        # Builds one rotor for each wiring at its starting position.
        self.rotors = [Rotor(w, p) for w, p in zip(ROTOR_WIRINGS, positions)]

    def advance(self):
        """Steps the first rotor and carries over to the next rotor on a full turn."""
        for rotor in self.rotors:
            if not rotor.step():
                break

    def _encrypt_index(self, index):
        """Passes an index through rotors 1, 2, and 3 in order."""
        for rotor in self.rotors:
            index = rotor.substitute(index)
        return index

    def _decrypt_index(self, index):
        """Passes an index back through rotors 3, 2, and 1 in order."""
        for rotor in reversed(self.rotors):
            index = rotor.invert(index)
        return index

    def _process(self, text, convert):
        """Converts each letter of the text and steps the rotors after each one."""
        result = []
        for char in text.upper():
            # Keeps spaces and punctuaton unchanged without stepping the rotors.
            if char not in ALPHABET:
                result.append(char)
                continue
            # Converts the letter, then steps the rotors after it.
            result.append(ALPHABET[convert(ALPHABET.index(char))])
            self.advance()
        return "".join(result)

    def encrypt(self, message):
        """Returns the encrypted form of the message."""
        return self._process(message, self._encrypt_index)

    def decrypt(self, ciphertext):
        """Returns the original message recoverd from the ciphertext."""
        return self._process(ciphertext, self._decrypt_index)


def run_test(message, positions=START_POSITIONS):
    """Encrypts and decrypts one message with separate machines and checks the result."""
    # Uses seperate sender and receiver machines that start at the same positions.
    encrypted = RotorMachine(positions).encrypt(message)
    decrypted = RotorMachine(positions).decrypt(encrypted)
    assert decrypted == message, f"Round-trip failed for {message!r}"
    return message, encrypted, decrypted


def print_table(rows):
    """Prints the results in the Table 2 format."""
    print(f"{'Initial Information':<22} {'Encrypted Text':<22} {'Decrypted Text'}")
    print("-" * 62)
    for original, encrypted, decrypted in rows:
        print(f"{original:<22} {encrypted:<22} {decrypted}")


def main():
    """Runs every Table 2 test and prints the results."""
    print_table([run_test(message) for message in TEST_MESSAGES])


if __name__ == "__main__":
    main()
