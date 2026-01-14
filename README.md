# CriptoBench: AES and T-AES Implementations and Benchmarking

This project provides block cipher implementations (**Advanced Encryption Standard - AES** and **Tweakable AES - T-AES**) along with tools for performance benchmarking and statistical analysis. It supports both software (SW) implementations and hardware acceleration using **AES-NI** instructions.

---

## Project Structure and Executables

The repository contains four main C executables and a testing script.

### 1. `encrypt` & `decrypt`

These are the core modules for encrypting and decrypting data. They read data from `stdin` and write the result to `stdout`.

| Mode | Key Lengths | Acceleration | Description |
| :--- | :--- | :--- | :--- |
| **AES-ECB** | 128, 192, 256 bits | SW | Standard AES (ECB mode). |
| **T-AES** | 128, 192, 256 bits | SW | Tweakable AES (Software). |
| **T-AES** | 128, 192, 256 bits | NI | Tweakable AES using **AES-NI** instructions. |

The encryption key is derived from a `<main_password>` via SHA-256.

#### How to Use:

The syntax depends on the selected mode:

# Standard AES-ECB
```bash
./encrypt key_len main_password 
```

# T-AES (Software)
```bash
./decrypt key_len main_password tweak_password 
```

# T-AES (AES-NI)
```bash
./encrypt key_len main_password tweak_password ni 
```
### 2. `speed` 
A dedicated tool for performance benchmarking.

Function: Measures the total execution time (Encryption + Decryption) for a 4KB data buffer.

Tests: Runs tests for AES-SW, T-AES-SW, T-AES-NI, and XTS-AES across 128, 192, and 256-bit key lengths.

Output: Reports the best time achieved in nanoseconds (ns) over 100,000 measurements.

How to use:

```bash
./speed
```

### 3. `stat` 

A module for statistical analysis of the T-AES algorithm's diffusion properties.

Function: Calculates the Hamming Distance between consecutive ciphertexts when the tweak is sequentially incremented (T vs T+1) on a fixed plaintext block. This measures the algorithm's avalanche effect.

Output: Prints the frequency distribution of Hamming distances in CSV format (Distance, Count)

How to use:
```bash
./stat 
```

## 4. `test_script.sh`

A simple shell script to verify the functional correctness of the ciphers.

Function: Executes a total of 9 end-to-end tests (encrypt followed by decrypt) covering all supported modes (AES-ECB, T-AES-SW, T-AES-NI) and key lengths (128, 192, 256).

Verification: Uses the diff command to ensure the decrypted output matches the original file exactly.

How to run:
```bash
chmod +x test_script.sh
./test_script.sh
```