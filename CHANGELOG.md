# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added
- **SM2** asymmetric encryption (GM/T 0003-2012) — encrypt, decrypt, sign, verify
- **SM3** cryptographic hash (GM/T 0004-2012) — 256-bit digest, HMAC-SM3
- **SM3+SALT** — salted SM3 hash replicating Java NationalSecret3 `encrypt(data, salt)` pattern
- **SM4** block cipher (GM/T 0002-2012) — CBC and ECB modes
- **Graphical User Interface** (tkinter) — 4-tab interface for all operations
- **Multi-line text support** — both CLI (--stdin, --text) and GUI
- **Hex encoding** — `encode hex` / `encode unhex` commands and GUI tab
- **SM2 commands**: `sm2 gen-key`, `sm2 encrypt`, `sm2 decrypt`, `sm2 sign`, `sm2 verify`
- **SM4 commands**: `sm4 gen-key`, `sm4 encrypt`, `sm4 decrypt`
- **Output format selection** — base64 or hex for ciphertext output
- **CI/CD** — GitHub Actions workflow for automated testing on Ubuntu, Windows, macOS
- **Project documentation** — CONTRIBUTING.md, CHANGELOG.md, LICENSE

### Changed
- Refactored hash utilities into `hash_utils.py` (backward compatible)
- Enhanced CLI with unified input handling (file, stdin, text)
- Updated dependencies: added `gmssl>=3.2.0` for SM2

## [0.1.0] - Initial Release

### Added
- AES encryption (CBC, GCM modes) with 128/192/256-bit keys
- RSA encryption (OAEP), signatures (PSS)
- SHA-256/384/512, MD5, SHA1 hashing
- HMAC authentication
- Password-based key derivation (PBKDF2)
- Base64 encoding/decoding (URL-safe)
- Command-line interface via Click
