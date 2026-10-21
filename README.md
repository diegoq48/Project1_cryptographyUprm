# DES project

The DES code is in `des.py`. It runs on Python 3.10 or later and uses only
standard Python libraries. 

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


Algorithm and test references: [FIPS 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf),
[FIPS 81, Tables B1 and C1](https://csrc.nist.gov/files/pubs/fips/81/final/docs/fips81.pdf),
and [NIST SP 800-17, Appendix B, Table 1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-17.pdf).
