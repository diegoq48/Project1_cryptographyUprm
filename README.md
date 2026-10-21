# DES project

The DES code is in `des.py`. It runs on Python 3.10 or later and uses only
standard Python libraries. Each function has a short comment explaining its job.

Run the three project messages (`HELLO`, `HOPE`, and `NEW YEAR`):

```console
python des.py
python des.py demo --csv task2_results.csv
```

Encrypt or decrypt another message:

```console
python des.py encrypt "HELLO" --key 133457799BBCDFF1
python des.py decrypt "PASTE_THE_HEX_OUTPUT_HERE" --key 133457799BBCDFF1
```

The code uses DES-CBC and PKCS#7 padding. The first 16 hex digits of the output
hold the eight-byte IV; the rest is ciphertext. Each encryption uses a new
random IV, so the encrypted output normally changes between runs. Keep the
whole output for decryption. The key above is a public example for the project.

Run the checks or measure performance:

```console
python -m unittest test_des -v
python des.py benchmark --csv des_benchmark.csv
```

Timing includes the key schedule and padding. The benchmark uses a fixed test
IV to exclude random-IV generation and measures Python allocation peaks
separately from timing. That memory value is not total process RAM.

For the hybrid project, import `encrypt_text` and `decrypt_text` from `des`.
Pass the rotor output into `encrypt_text`, and pass the result of `decrypt_text`
back into the rotor's decryption function. The byte versions are available as
`encrypt_bytes` and `decrypt_bytes`.

DES has 56 effective key bits and sixteen 48-bit round keys. The assignment's
reference to 56-bit round keys is a typo. Padding fills eight-byte blocks;
`NEW YEAR` already fills a block, so it receives a full extra padding block.
DES is for this course exercise; its short key and unauthenticated CBC output
are unsuitable for protecting real-world data.

Algorithm and test references: [FIPS 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf),
[FIPS 81, Tables B1 and C1](https://csrc.nist.gov/files/pubs/fips/81/final/docs/fips81.pdf),
and [NIST SP 800-17, Appendix B, Table 1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-17.pdf).
