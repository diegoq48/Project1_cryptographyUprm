This project implements a rotor machine, DES, and a hybrid system combining both. It requires Python 3.10 or later and uses only the Python standard library. No additional packages need to be installed.

Open a terminal in the project root directory, which contains hybrid.py and the des and rotor_machine folders. Run all commands below from that directory. Use python instead of python3 if that is the command available on your system.

To run the rotor code from the project root directory:

python3 rotor_machine/rotor_machine.py

If your terminal is already inside the rotor_machine folder, run:

python3 rotor_machine.py

After running it from that folder, use cd .. to return to the project root before running the remaining commands in this README.

This encrypts and decrypts HOPE, HELLO, and NEW YEAR and displays the original, encrypted, and decrypted messages. The machine starts at rotor positions (0, 0, 0), uses carry stepping, and converts text to uppercase.

To run DES:

python3 des/des.py

This encrypts and decrypts HELLO, HOPE, and NEW YEAR using DES-CBC with PKCS#7 padding and displays whether each recovered message matches the original.

To encrypt a different message with DES:

python3 des/des.py encrypt "HELLO" --key 133457799BBCDFF1

To decrypt it, replace PASTE_THE_HEX_OUTPUT_HERE with the complete encrypted output and use the same key:

python3 des/des.py decrypt "PASTE_THE_HEX_OUTPUT_HERE" --key 133457799BBCDFF1

The example key is provided for the project demonstration. The encrypted output includes an eight-byte IV followed by ciphertext. A fresh random IV makes the encrypted output change between runs.

To run the standalone DES benchmark:

python3 des/des.py benchmark --message "WELCOME TO PUERTO RICO" --iterations 100

This prints median encryption and decryption times, peak Python memory allocation, and computational complexity.

To run the hybrid system and compare all three algorithms:

python3 hybrid.py

The hybrid script imports the existing rotor and DES implementations. It encrypts each message with the rotor machine and then DES, and decrypts in reverse order. It runs HOW ARE YOU, HAPPY NEW YEAR, and WELCOME TO PUERTO RICO.

For each message, M is the original text, E1 is the rotor ciphertext, E2 is the DES-encrypted result in hexadecimal, D1 is the DES-decrypted rotor ciphertext, and D2 is the recovered original text. Successful results show D1 equal to E1, D2 equal to M, and Matches: True.

The script then benchmarks the rotor machine, DES, and hybrid system on those messages and on 64-, 256-, 1024-, and 4096-byte inputs. Each case uses 100 iterations. It prints median encryption, decryption, and round-trip times, total time for all timed round trips, and peak Python memory allocation. Times are in milliseconds and memory is in bytes.

Benchmarks use a fixed IV to exclude random-IV generation. Memory is measured separately from timing and represents Python allocations, rather than total process memory. Results appear only in the terminal; these commands do not create CSV files.

To run the DES tests:

python3 -m unittest discover -s des -p test_des.py -v
