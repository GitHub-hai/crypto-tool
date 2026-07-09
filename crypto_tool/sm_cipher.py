"""
SM2 asymmetric encryption module (Chinese National Cryptographic Standard).

SM2 is an elliptic curve-based public-key algorithm defined in GM/T 0003-2012.
It supports encryption, decryption, digital signatures, and key exchange.

Uses the `gmssl` library for SM2 operations.
The underlying curve is sm2p256v1 (256-bit prime field).
"""

from typing import Tuple, Optional

try:
    from gmssl import sm2 as _gmssl_sm2
    from gmssl import func as _gmssl_func

    _HAS_GMSSL = True
except ImportError:
    _HAS_GMSSL = False


def _require_gmssl():
    """Raise a helpful error if gmssl is not installed."""
    if not _HAS_GMSSL:
        raise ImportError(
            "SM2 operations require the 'gmssl' package.\n"
            "Install it with: pip install gmssl"
        )


def _create_cryptsm2(private_hex: str, public_hex: str, mode: int = 0, asn1: bool = False):
    """Create a CryptSM2 instance with the given keys."""
    _require_gmssl()
    # Strip "04" prefix from public key if present
    pub = public_hex.lstrip("04") if public_hex.startswith("04") else public_hex
    return _gmssl_sm2.CryptSM2(
        private_key=private_hex,
        public_key=pub,
        mode=mode,
        asn1=asn1,
    )


# ── Key Generation ───────────────────────────────────────────────────────

def generate_sm2_keypair() -> Tuple[str, str]:
    """Generate an SM2 key pair.

    Returns:
        Tuple of (private_key_hex, public_key_hex).
        - private_key_hex: 64-character hex string (32 bytes)
        - public_key_hex: 128-character hex string (64 bytes, x||y, no 04 prefix)
    """
    _require_gmssl()

    private_hex = _gmssl_func.random_hex(64)
    # Use a temporary instance to access the _kg (point multiplication) method
    temp = _gmssl_sm2.CryptSM2(private_key=private_hex, public_key="00" * 64)
    # Compute public key point: private_key * G (generator point)
    public_point = temp._kg(int(private_hex, 16), temp.ecc_table["g"])
    return private_hex, public_point


# ── Encryption / Decryption ──────────────────────────────────────────────

def sm2_encrypt(plaintext: bytes, public_key_hex: str, mode: int = 0) -> bytes:
    """Encrypt data using SM2 public key.

    Args:
        plaintext: Data to encrypt.
        public_key_hex: SM2 public key as a 128-char hex string (x||y).
        mode: Ciphertext format — 0 for C1C2C3, 1 for C1C3C2.

    Returns:
        Encrypted ciphertext bytes.
    """
    sm2_crypt = _create_cryptsm2(private_hex="00" * 64, public_hex=public_key_hex, mode=mode)
    return sm2_crypt.encrypt(plaintext)


def sm2_decrypt(ciphertext: bytes, private_key_hex: str, mode: int = 0) -> bytes:
    """Decrypt data using SM2 private key.

    Args:
        ciphertext: Encrypted data.
        private_key_hex: SM2 private key as a 64-char hex string.
        mode: Ciphertext format — must match the mode used during encryption.

    Returns:
        Decrypted plaintext bytes.
    """
    sm2_crypt = _create_cryptsm2(private_hex=private_key_hex, public_hex="00" * 64, mode=mode)
    return sm2_crypt.decrypt(ciphertext)


# ── Digital Signature ────────────────────────────────────────────────────

def sm2_sign(data: bytes, private_key_hex: str, public_key_hex: str = "",
             asn1: bool = False) -> str:
    """Sign data using SM2 with SM3 hash (SM2withSM3).

    The signature follows the GM/T 0003.2-2012 standard:
    Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
    e = SM3(Z || M)
    sign(e, private_key)

    Args:
        data: Data to sign.
        private_key_hex: SM2 private key as a 64-char hex string.
        public_key_hex: SM2 public key (required for Z value computation).
        asn1: If True, return DER-encoded signature.

    Returns:
        Hex-encoded signature string (128 chars r||s, or DER hex if asn1=True).
    """
    sm2_crypt = _create_cryptsm2(private_hex=private_key_hex, public_hex=public_key_hex, asn1=asn1)
    return sm2_crypt.sign_with_sm3(data)


def sm2_verify(data: bytes, signature: str, public_key_hex: str,
               asn1: bool = False) -> bool:
    """Verify an SM2 signature (SM2withSM3).

    Args:
        data: Original data.
        signature: Hex-encoded signature string.
        public_key_hex: SM2 public key as a 128-char hex string.
        asn1: If True, signature is DER-encoded.

    Returns:
        True if the signature is valid.
    """
    sm2_crypt = _create_cryptsm2(private_hex="00" * 64, public_hex=public_key_hex, asn1=asn1)
    return sm2_crypt.verify_with_sm3(signature, data)


# ── Raw Sign/Verify (pre-hashed data) ────────────────────────────────────

def sm2_sign_raw(digest: bytes, private_key_hex: str, public_key_hex: str = "",
                 random_hex: Optional[str] = None, asn1: bool = False) -> str:
    """Sign a pre-computed hash digest directly.

    This is the low-level SM2 signing operation (no automatic SM3 hashing).

    Args:
        digest: Pre-computed hash digest (typically SM3 output).
        private_key_hex: SM2 private key as a 64-char hex string.
        public_key_hex: SM2 public key (unused for raw sign, but required by gmssl).
        random_hex: Random k value (auto-generated if None).
        asn1: If True, return DER-encoded signature.

    Returns:
        Hex-encoded signature string.
    """
    _require_gmssl()
    if random_hex is None:
        random_hex = _gmssl_func.random_hex(64)
    sm2_crypt = _create_cryptsm2(private_hex=private_key_hex, public_hex=public_key_hex, asn1=asn1)
    return sm2_crypt.sign(digest, random_hex)


def sm2_verify_raw(digest: bytes, signature: str, public_key_hex: str,
                   asn1: bool = False) -> bool:
    """Verify a signature against a pre-computed hash digest.

    This is the low-level SM2 verification operation.

    Args:
        digest: Pre-computed hash digest.
        signature: Hex-encoded signature string.
        public_key_hex: SM2 public key as a 128-char hex string.
        asn1: If True, signature is DER-encoded.

    Returns:
        True if the signature is valid.
    """
    sm2_crypt = _create_cryptsm2(private_hex="00" * 64, public_hex=public_key_hex, asn1=asn1)
    return sm2_crypt.verify(signature, digest)


# ── Key Serialization ────────────────────────────────────────────────────

def sm2_keypair_to_pem(private_hex: str, public_hex: str) -> Tuple[str, str]:
    """Convert SM2 key pair to PEM-style format strings.

    Since gmssl doesn't use standard PEM, we use a simple armored format.

    Args:
        private_hex: 64-char private key hex string.
        public_hex: 128-char public key hex string.

    Returns:
        Tuple of (private_pem_str, public_pem_str).
    """
    private_pem = (
        "-----BEGIN SM2 PRIVATE KEY-----\n"
        + private_hex + "\n"
        + "-----END SM2 PRIVATE KEY-----"
    )
    public_pem = (
        "-----BEGIN SM2 PUBLIC KEY-----\n"
        + "04" + public_hex + "\n"
        + "-----END SM2 PUBLIC KEY-----"
    )
    return private_pem, public_pem


def load_sm2_public_key_from_pem(pem_str: str) -> str:
    """Extract SM2 public key hex from armored format.

    Args:
        pem_str: PEM-style armored public key string.

    Returns:
        128-char hex string (without 04 prefix).
    """
    lines = pem_str.strip().split("\n")
    key_data = "".join(line.strip() for line in lines
                       if not line.startswith("-----"))
    if key_data.startswith("04"):
        key_data = key_data[2:]
    return key_data


def load_sm2_private_key_from_pem(pem_str: str) -> str:
    """Extract SM2 private key hex from armored format.

    Args:
        pem_str: PEM-style armored private key string.

    Returns:
        64-char hex string.
    """
    lines = pem_str.strip().split("\n")
    key_data = "".join(line.strip() for line in lines
                       if not line.startswith("-----"))
    return key_data
