"""
Core encryption and decryption module.

Supported algorithms:
- AES (CBC, GCM modes)
- SM4 (CBC, ECB modes) — Chinese national block cipher
- RSA (OAEP padding, PSS signatures)
- ChaCha20-Poly1305
"""

import os
import base64
import hashlib
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidSignature

# Re-export hash utilities for backward compatibility
from .hash_utils import (
    hash_data,
    sm3_hash,
    sm3_salted_hash,
    hmac_sign,
    hmac_verify,
    derive_key,
    to_hex,
    from_hex,
    to_base64,
    from_base64,
)


# ── AES Symmetric Encryption ────────────────────────────────────────────

def generate_aes_key(key_size: int = 256) -> bytes:
    """Generate a random AES key.

    Args:
        key_size: Key size in bits (128, 192, or 256).

    Returns:
        Raw key bytes.
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size must be 128, 192, or 256")
    return os.urandom(key_size // 8)


def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt data using AES-CBC mode with PKCS7 padding.

    Args:
        plaintext: Data to encrypt.
        key: AES key (16, 24, or 32 bytes).

    Returns:
        Tuple of (iv, ciphertext).
    """
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-CBC mode with PKCS7 padding.

    Args:
        iv: Initialization vector (16 bytes).
        ciphertext: Encrypted data.
        key: AES key (16, 24, or 32 bytes).

    Returns:
        Decrypted plaintext bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def aes_encrypt_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Encrypt data using AES-GCM mode (authenticated encryption).

    Args:
        plaintext: Data to encrypt.
        key: AES key (16, 24, or 32 bytes).
        aad: Additional authenticated data.

    Returns:
        Tuple of (iv, ciphertext, tag).
    """
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


def aes_decrypt_gcm(iv: bytes, ciphertext: bytes, tag: bytes, key: bytes, aad: bytes = b"") -> Optional[bytes]:
    """Decrypt data using AES-GCM mode.

    Args:
        iv: Initialization vector (12 bytes recommended).
        ciphertext: Encrypted data.
        tag: Authentication tag.
        key: AES key.
        aad: Additional authenticated data.

    Returns:
        Decrypted plaintext bytes, or None if authentication fails.
    """
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        return None


# ── SM4 Symmetric Encryption (Chinese National Standard) ────────────────

SM4_KEY_SIZE = 16  # SM4 uses 128-bit key
SM4_BLOCK_SIZE = 128  # bits


def generate_sm4_key() -> bytes:
    """Generate a random SM4 key (128-bit).

    Returns:
        16-byte raw key.
    """
    return os.urandom(SM4_KEY_SIZE)


def sm4_encrypt_cbc(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt data using SM4-CBC mode with PKCS7 padding.

    Args:
        plaintext: Data to encrypt.
        key: SM4 key (must be 16 bytes / 128 bits).

    Returns:
        Tuple of (iv, ciphertext).
    """
    if len(key) != SM4_KEY_SIZE:
        raise ValueError(f"SM4 key must be {SM4_KEY_SIZE} bytes, got {len(key)}")

    iv = os.urandom(16)
    padder = padding.PKCS7(SM4_BLOCK_SIZE).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def sm4_decrypt_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using SM4-CBC mode with PKCS7 padding.

    Args:
        iv: Initialization vector (16 bytes).
        ciphertext: Encrypted data.
        key: SM4 key (must be 16 bytes).

    Returns:
        Decrypted plaintext bytes.
    """
    if len(key) != SM4_KEY_SIZE:
        raise ValueError(f"SM4 key must be {SM4_KEY_SIZE} bytes, got {len(key)}")

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(SM4_BLOCK_SIZE).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def sm4_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using SM4-ECB mode with PKCS7 padding.

    Note: ECB mode is less secure than CBC. Use only for compatibility.

    Args:
        plaintext: Data to encrypt.
        key: SM4 key (must be 16 bytes).

    Returns:
        Ciphertext bytes.
    """
    if len(key) != SM4_KEY_SIZE:
        raise ValueError(f"SM4 key must be {SM4_KEY_SIZE} bytes, got {len(key)}")

    padder = padding.PKCS7(SM4_BLOCK_SIZE).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.SM4(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def sm4_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using SM4-ECB mode with PKCS7 padding.

    Args:
        ciphertext: Encrypted data.
        key: SM4 key (must be 16 bytes).

    Returns:
        Decrypted plaintext bytes.
    """
    if len(key) != SM4_KEY_SIZE:
        raise ValueError(f"SM4 key must be {SM4_KEY_SIZE} bytes, got {len(key)}")

    cipher = Cipher(algorithms.SM4(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(SM4_BLOCK_SIZE).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


# ── RSA Asymmetric Encryption ───────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA key pair.

    Args:
        key_size: Key size in bits (≥2048 recommended).

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def rsa_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt data using RSA-OAEP with SHA-256.

    Args:
        plaintext: Data to encrypt (size limited by key size).
        public_key: RSA public key.

    Returns:
        Ciphertext bytes.
    """
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt data using RSA-OAEP with SHA-256.

    Args:
        ciphertext: Encrypted data.
        private_key: RSA private key.

    Returns:
        Decrypted plaintext bytes.
    """
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign data using RSA-PSS with SHA-256.

    Args:
        data: Data to sign.
        private_key: RSA private key.

    Returns:
        Signature bytes.
    """
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify an RSA-PSS signature.

    Args:
        data: Original data.
        signature: Signature to verify.
        public_key: RSA public key.

    Returns:
        True if signature is valid.
    """
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to PEM bytes."""
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key to PEM bytes."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_from_pem(pem_data: bytes) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""
    return load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_public_key_from_pem(pem_data: bytes) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM bytes."""
    return load_pem_public_key(pem_data, backend=default_backend())


# ── ChaCha20-Poly1305 (Authenticated Stream Cipher) ─────────────────────

def chacha20_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Encrypt data using ChaCha20-Poly1305 (IETF variant).

    Args:
        plaintext: Data to encrypt.
        key: 256-bit (32-byte) key.
        aad: Additional authenticated data.

    Returns:
        Tuple of (nonce, ciphertext, tag).
    """
    nonce = os.urandom(12)
    algorithm = algorithms.ChaCha20Poly1305(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def chacha20_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes,
                     aad: bytes = b"") -> Optional[bytes]:
    """Decrypt data using ChaCha20-Poly1305.

    Returns None if authentication fails.
    """
    try:
        algorithm = algorithms.ChaCha20Poly1305(key)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        return None


# ── Ed25519 (Modern Elliptic-Curve Signatures) ──────────────────────────

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 key pair.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def ed25519_sign(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign data using Ed25519."""
    return private_key.sign(data)


def ed25519_verify(data: bytes, signature: bytes,
                   public_key: ed25519.Ed25519PublicKey) -> bool:
    """Verify an Ed25519 signature."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def serialize_ed25519_private_key(key: ed25519.Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key to PEM bytes."""
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def serialize_ed25519_public_key(key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to PEM bytes."""
    return key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def load_ed25519_private_key_from_pem(pem_data: bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes."""
    return load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_ed25519_public_key_from_pem(pem_data: bytes) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes."""
    return load_pem_public_key(pem_data, backend=default_backend())
