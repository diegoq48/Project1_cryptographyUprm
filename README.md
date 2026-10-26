# Project 1 Cryptography & Network Security

This project is self continied ie no third party libraries are needed

## In order to run the rotor machine and the des machine on their own with the hardcoded values

`python rotor_machine.py` and `python des.py` respectivly while inside of their folders

## in order to run the unit tests for the des file

```
python -m unittest discover -s des -p test_des.py -v
```

## in order to run benchmarks

```
python des/des.py benchmark --message "WELCOME TO PUERTO RICO" --iterations 100
```

## in order to run the assigments hardcoded values with the hybrid approach run

`python hybrid.py` from the root of the project
