# Crypto Tool

A versatile encryption/decryption utility for Python with both CLI and GUI interfaces.

[![Tests](https://github.com/GitHub-hai/crypto-tool/actions/workflows/test.yml/badge.svg)](https://github.com/GitHub-hai/crypto-tool/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

### Algorithms

| Category | Algorithms | Standard |
|----------|-----------|----------|
| **Symmetric** | AES (CBC, GCM), SM4 (CBC, ECB) | FIPS 197, GM/T 0002 |
| **Asymmetric** | RSA (OAEP, PSS), SM2 | PKCS#1, GM/T 0003 |
| **Hash** | SM3, SM3+SALT, SHA-256/384/512, MD5, SHA1 | GM/T 0004, FIPS 180-4 |
| **HMAC** | HMAC-SM3, HMAC-SHA256/384/512 | RFC 2104 |
| **KDF** | PBKDF2-HMAC-SHA256 | RFC 2898 |
| **Encoding** | Base64 (URL-safe), Hex | — |

### Interfaces

- **CLI** (`crypto-tool`) — Full-featured command-line interface with pipe/stdin support
- **GUI** (`crypto-tool-gui`) — Tkinter-based graphical interface with 4 tabs

## Installation

```bash
cd crypto-tool
pip install -e .
```

With development dependencies:

```bash
pip install -e ".[dev]"
```

## Quick Start

### CLI

```bash
# Generate keys
crypto-tool key gen-aes -o aes.key          # AES-256
crypto-tool sm4 gen-key -o sm4.key          # SM4
crypto-tool key gen-rsa                      # RSA key pair
crypto-tool sm2 gen-key                      # SM2 key pair

# Symmetric encryption
crypto-tool aes encrypt -k aes.key -t "secret message" -o encrypted.bin
crypto-tool aes decrypt -k aes.key -i encrypted.bin -o decrypted.txt

# SM4 encryption (Chinese National Standard)
crypto-tool sm4 encrypt -k sm4.key -t "你好世界" -o encrypted.bin
crypto-tool sm4 decrypt -k sm4.key -i encrypted.bin

# Asymmetric encryption (RSA, for small data)
crypto-tool rsa encrypt -k public.pem -t "hello" -o cipher.bin
crypto-tool rsa decrypt -k private.pem -i cipher.bin

# SM2 encryption
crypto-tool sm2 encrypt -k sm2_public.key -t "数据" -o cipher.bin

# Digital signatures
crypto-tool rsa sign -k private.pem -i document.pdf -o doc.sig
crypto-tool rsa verify -k public.pem -i document.pdf -s doc.sig

# SM2 signature
crypto-tool sm2 sign -k sm2_private.key --public-key sm2_public.key -i data.txt -o data.sig
crypto-tool sm2 verify -k sm2_public.key -i data.txt -s data.sig

# Hashing
crypto-tool hash digest -a sm3 -i file.txt
crypto-tool hash digest -a sm3 -s "mysalt" -t "hello world"   # SM3+SALT
crypto-tool hash digest -a sha256 -t "hello world"
crypto-tool hash hmac -a sm3 -k hmac.key -i message.txt

# Encoding
echo "hello" | crypto-tool encode b64
crypto-tool encode hex -i binary.dat
crypto-tool encode unhex -i hex.txt -o binary.dat

# Multi-line input via pipe
cat document.txt | crypto-tool aes encrypt -k key.bin --stdin -o doc.enc

# Output format selection
crypto-tool aes encrypt -k key.bin -t "test" --format hex
crypto-tool aes decrypt -k key.bin -i cipher.b64 --input-format base64
```

### GUI

```bash
crypto-tool-gui
```

A 4-tab window opens:
- **Symmetric** — AES-GCM/CBC, SM4-CBC/ECB with key generation
- **Asymmetric** — RSA, SM2 encrypt/decrypt/sign/verify
- **Hash** — SM3, SM3+SALT, SHA, MD5, HMAC
- **Encode** — Base64, Hex encode/decode

All tabs support multi-line text, file open/save, and clipboard copy.

## Python API

```python
# AES
from crypto_tool.cipher import generate_aes_key, aes_encrypt_gcm, aes_decrypt_gcm
key = generate_aes_key(256)
iv, ct, tag = aes_encrypt_gcm(b"secret", key)
pt = aes_decrypt_gcm(iv, ct, tag, key)

# SM4
from crypto_tool.cipher import generate_sm4_key, sm4_encrypt_cbc, sm4_decrypt_cbc
key = generate_sm4_key()
iv, ct = sm4_encrypt_cbc(b"data", key)
pt = sm4_decrypt_cbc(iv, ct, key)

# SM3 hash
from crypto_tool.hash_utils import sm3_hash, sm3_salted_hash, hash_data
digest = sm3_hash(b"hello")                     # Pure SM3
digest = sm3_salted_hash(b"hello", b"mysalt")   # SM3 with salt prepended: SM3(salt+data)
digest = hash_data(b"hello", "sha256")           # SHA-256

# SM2
from crypto_tool.sm_cipher import generate_sm2_keypair, sm2_encrypt, sm2_decrypt
priv, pub = generate_sm2_keypair()
ct = sm2_encrypt(b"message", pub)
pt = sm2_decrypt(ct, priv)
```

## Project Structure

```
crypto-tool/
├── .github/
│   └── workflows/
│       └── test.yml              # CI: pytest on Ubuntu/Windows/macOS
├── crypto_tool/                  # Main package
│   ├── __init__.py               # Package metadata
│   ├── cipher.py                 # AES, SM4, RSA, KDF, encoding
│   ├── sm_cipher.py              # SM2 asymmetric encryption
│   ├── hash_utils.py             # SM3, SHA, MD5, HMAC
│   ├── cli.py                    # Command-line interface (Click)
│   ├── gui.py                    # GUI interface (tkinter)
│   └── utils.py                  # File I/O, clipboard, input helpers
├── tests/                        # Test suite
│   ├── __init__.py
│   ├── test_cipher.py            # AES, SM4, RSA tests
│   ├── test_sm_cipher.py         # SM2 tests
│   └── test_hash.py              # SM3, SHA, HMAC tests
├── .gitignore
├── LICENSE                       # MIT
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── pyproject.toml                # Project configuration
```

## Running Tests

```bash
pytest -v
pytest --cov=crypto_tool
```

## Building Standalone Executables

The GUI (`crypto-tool-gui`) can be packaged into a single-file executable for distribution without requiring Python to be installed on the target machine.

### Prerequisites

```bash
pip install pyinstaller
```

### Windows (.exe)

```bash
# Single-file executable (no console window)
pyinstaller --onefile --windowed ^
    --name crypto-tool ^
    --add-data "crypto_tool;crypto_tool" ^
    -m crypto_tool.gui:main ^
    crypto_tool/gui.py

# Output: dist/crypto-tool.exe
```

With an icon (optional):

```bash
pyinstaller --onefile --windowed ^
    --name crypto-tool ^
    --icon icon.ico ^
    --add-data "crypto_tool;crypto_tool" ^
    -m crypto_tool.gui:main ^
    crypto_tool/gui.py
```

### Linux

```bash
# Single-file executable
pyinstaller --onefile \
    --name crypto-tool \
    --add-data "crypto_tool:crypto_tool" \
    -m crypto_tool.gui:main \
    crypto_tool/gui.py

# Output: dist/crypto-tool
```

### macOS

```bash
pyinstaller --onefile --windowed \
    --name crypto-tool \
    --add-data "crypto_tool:crypto_tool" \
    -m crypto_tool.gui:main \
    crypto_tool/gui.py

# Output: dist/crypto-tool
```

### CLI Standalone (all platforms)

To package the CLI instead of the GUI, omit `--windowed` and target `cli.py`:

```bash
pyinstaller --onefile \
    --name crypto-tool-cli \
    --add-data "crypto_tool:crypto_tool" \
    -m crypto_tool.cli:main \
    crypto_tool/cli.py
```

### Output Location

PyInstaller places executables in `dist/`. The `dist/` directory is already in `.gitignore` — build artifacts are never committed.

```bash
# Windows
ls dist/crypto-tool.exe

# Linux / macOS
ls dist/crypto-tool
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: crypto_tool` | Ensure `--add-data` copies the `crypto_tool` package into the bundle |
| SM2 not working | Verify `gmssl` is installed before building: `pip install gmssl>=3.2.0` |
| Large binary (>50MB) | Normal — PyInstaller bundles Python and all dependencies |

## Security Notes

- This tool uses industry-standard libraries: `cryptography`, `gmssl`
- **Never commit real keys or encrypted data** — `.gitignore` excludes `*.key`, `*.pem`, `*.enc`
- RSA and SM2 are suitable only for small data (≤ key size minus padding)
- For large files, use symmetric encryption (AES/SM4) with a randomly generated key
- Password-based key derivation uses PBKDF2 with 600,000 iterations (OWASP recommended)

## Dependencies

- [`cryptography`](https://cryptography.io/) — AES, SM3, SM4, RSA
- [`gmssl`](https://github.com/duanhongyi/gmssl) — SM2
- [`click`](https://click.palletsprojects.com/) — CLI framework

## License

MIT — see [LICENSE](LICENSE) for details.
