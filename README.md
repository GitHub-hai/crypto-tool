# Crypto Tool

A versatile encryption/decryption utility for Python with both CLI and GUI interfaces.

[![Tests](https://github.com/GitHub-hai/crypto-tool/actions/workflows/test.yml/badge.svg)](https://github.com/GitHub-hai/crypto-tool/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **Author:** WU GUOHAI · **AI Model:** DeepSeek · **AI Tool:** Claude Code
> **GitHub:** [https://github.com/GitHub-hai/crypto-tool](https://github.com/GitHub-hai/crypto-tool)

## Features

### Algorithms

| Category | Algorithms | Standard |
|----------|-----------|----------|
| **Symmetric** | AES (CBC, GCM), SM4 (CBC, ECB), ChaCha20-Poly1305 | FIPS 197, GM/T 0002, RFC 8439 |
| **Asymmetric** | RSA (OAEP, PSS), SM2, Ed25519 | PKCS#1, GM/T 0003, RFC 8032 |
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

# ChaCha20-Poly1305 (modern stream cipher)
crypto-tool chacha20 encrypt -k chacha.key -t "secret" -o encrypted.bin
crypto-tool chacha20 decrypt -k chacha.key -i encrypted.bin

# Ed25519 (modern signature-only, no encryption)
crypto-tool ed25519 gen-key
crypto-tool ed25519 sign -k ed25519_private.pem -i document.pdf -o doc.sig
crypto-tool ed25519 verify -k ed25519_public.pem -i document.pdf -s doc.sig

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
- **Symmetric** — AES-GCM/CBC, SM4-CBC/ECB, ChaCha20-Poly1305
- **Asymmetric** — RSA, SM2, Ed25519 (encrypt/decrypt/sign/verify)
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

# ChaCha20-Poly1305
from crypto_tool.cipher import chacha20_encrypt, chacha20_decrypt
key = generate_aes_key(256)
nonce, ct, tag = chacha20_encrypt(b"data", key)
pt = chacha20_decrypt(nonce, ct, tag, key)

# Ed25519 (signature-only)
from crypto_tool.cipher import generate_ed25519_keypair, ed25519_sign, ed25519_verify
priv, pub = generate_ed25519_keypair()
sig = ed25519_sign(b"message", priv)
assert ed25519_verify(b"message", sig, pub)
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
├── run_gui.py                    # PyInstaller launcher for GUI
├── run_cli.py                    # PyInstaller launcher for CLI
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

> **Important**: Use the launcher scripts (`run_gui.py`, `run_cli.py`) — they import via the package so relative imports resolve correctly. Running `crypto_tool/gui.py` directly will fail with `ImportError: attempted relative import with no known parent package`.

### Windows (.exe)

```bash
# Single-file executable (no console window)
pyinstaller --onefile --windowed ^
    --name crypto-tool ^
    run_gui.py

# Output: dist/crypto-tool.exe
```

With an icon (optional):

```bash
pyinstaller --onefile --windowed ^
    --name crypto-tool ^
    --icon icon.ico ^
    run_gui.py
```

### Linux

```bash
# Single-file executable
pyinstaller --onefile \
    --name crypto-tool \
    run_gui.py

# Output: dist/crypto-tool
```

### macOS

> **ARM (Apple Silicon) compatibility**: PyInstaller produces a binary for the
> architecture it runs on. Build on Apple Silicon (M1/M2/M3) → arm64 binary.
> Build on Intel Mac → x86_64 binary (runs on Apple Silicon via Rosetta 2).
> Cross-architecture builds are **not** supported — build on the same chip as the target.

```bash
# Build (on the target Mac architecture)
pyinstaller --onefile --windowed \
    --name crypto-tool \
    run_gui.py

# Outputs:
#   dist/crypto-tool.app  — double-click to launch
#   dist/crypto-tool      — raw binary (terminal launch)
```

#### First-launch issue (Gatekeeper)

macOS blocks unsigned apps downloaded from the internet. If the `.app` won't open:

```bash
# Remove quarantine flag (user runs this after downloading)
xattr -cr crypto-tool.app
```

Or right-click the `.app` → **Open** → confirm the dialog.

#### Build for distribution

```bash
# Ad-hoc sign (local testing)
codesign --force --deep --sign - dist/crypto-tool.app

# Notarization-ready signed build (requires Apple Developer account)
codesign --force --options runtime --deep --sign "Developer ID Application: ..." dist/crypto-tool.app
```

#### Debugging build failures

```bash
# Build in verbose mode to see import errors
pyinstaller --onefile --windowed --log-level DEBUG --name crypto-tool run_gui.py

# If tkinter is missing, install python-tk via Homebrew
brew install python-tk@3.13

# Ensure gmssl is bundled
pyinstaller --onefile --windowed --hidden-import gmssl --name crypto-tool run_gui.py
```

### CLI Standalone (all platforms)

To package the CLI instead of the GUI, omit `--windowed`:

```bash
pyinstaller --onefile \
    --name crypto-tool-cli \
    run_cli.py
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

| Issue | Platform | Solution |
|-------|----------|----------|
| `ModuleNotFoundError: crypto_tool` | All | Run `pip install -e .` first, then rebuild |
| SM2 not working in exe | All | Add `--hidden-import gmssl` |
| `.app` won't open / "damaged" | macOS | Run `xattr -cr crypto-tool.app` or right-click → Open |
| tkinter missing at build time | macOS | `brew install python-tk@3.13` |
| Binary wrong architecture | macOS | Build on the same chip as target. Intel Mac → x86_64, Apple Silicon → arm64 |
| Large binary (~30-50 MB) | All | Normal — PyInstaller bundles Python + all dependencies |

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
