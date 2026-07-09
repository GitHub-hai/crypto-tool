"""
Tests for the SM2 cipher module.
"""

import pytest

from crypto_tool.sm_cipher import (
    generate_sm2_keypair,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign,
    sm2_verify,
    sm2_sign_raw,
    sm2_verify_raw,
    sm2_keypair_to_pem,
    load_sm2_public_key_from_pem,
    load_sm2_private_key_from_pem,
)


class TestSM2:
    """SM2 asymmetric encryption tests."""

    def test_keypair_generation(self):
        private_hex, public_hex = generate_sm2_keypair()

        # Private key: 64 hex chars (32 bytes)
        assert len(private_hex) == 64
        # Public key: 128 hex chars (64 bytes, x||y)
        assert len(public_hex) == 128

        # Keys should be valid hex
        int(private_hex, 16)
        int(public_hex, 16)

    def test_multiple_keypairs_unique(self):
        pairs = [generate_sm2_keypair() for _ in range(5)]
        priv_keys = [p[0] for p in pairs]
        pub_keys = [p[1] for p in pairs]

        # All private keys should be unique
        assert len(set(priv_keys)) == 5
        # All public keys should be unique
        assert len(set(pub_keys)) == 5

    def test_encrypt_decrypt(self):
        priv, pub = generate_sm2_keypair()
        plaintext = b"SM2 encryption test message."

        ciphertext = sm2_encrypt(plaintext, pub)
        assert ciphertext != plaintext

        decrypted = sm2_decrypt(ciphertext, priv)
        assert decrypted == plaintext

    def test_encrypt_decrypt_binary(self):
        priv, pub = generate_sm2_keypair()
        plaintext = bytes(range(50))  # binary data

        ciphertext = sm2_encrypt(plaintext, pub)
        decrypted = sm2_decrypt(ciphertext, priv)
        assert decrypted == plaintext

    def test_encrypt_decrypt_chinese(self):
        priv, pub = generate_sm2_keypair()
        plaintext = "SM2国密算法测试数据".encode("utf-8")

        ciphertext = sm2_encrypt(plaintext, pub)
        decrypted = sm2_decrypt(ciphertext, priv)
        assert decrypted == plaintext
        assert decrypted.decode("utf-8") == "SM2国密算法测试数据"

    def test_encrypt_decrypt_multi_line(self):
        priv, pub = generate_sm2_keypair()
        plaintext = b"Line one\nLine two\nLine three\n\nEnd."

        ciphertext = sm2_encrypt(plaintext, pub)
        decrypted = sm2_decrypt(ciphertext, priv)
        assert decrypted == plaintext

    def test_sign_verify(self):
        priv, pub = generate_sm2_keypair()
        data = b"Data to be signed with SM2."

        signature = sm2_sign(data, priv, pub)
        # Signature should be a hex string (128 chars for r||s)
        assert len(signature) == 128

        valid = sm2_verify(data, signature, pub)
        assert valid

    def test_sign_verify_invalid(self):
        priv, pub = generate_sm2_keypair()
        data = b"Original message."
        signature = sm2_sign(data, priv, pub)

        # Verify with tampered data
        assert not sm2_verify(b"Tampered message.", signature, pub)

    def test_sign_verify_wrong_key(self):
        priv1, pub1 = generate_sm2_keypair()
        _, pub2 = generate_sm2_keypair()

        data = b"Test message."
        signature = sm2_sign(data, priv1, pub1)

        # Verify with wrong public key should fail
        assert not sm2_verify(data, signature, pub2)

    def test_raw_sign_verify(self):
        """Test raw sign/verify without SM3 hashing."""
        from crypto_tool.hash_utils import sm3_hash

        priv, pub = generate_sm2_keypair()
        data = b"Raw sign test."
        digest = bytes.fromhex(sm3_hash(data))

        signature = sm2_sign_raw(digest, priv, pub)
        assert len(signature) == 128

        valid = sm2_verify_raw(digest, signature, pub)
        assert valid

    def test_key_pem_serialization(self):
        """Test SM2 key serialization to PEM-like format."""
        priv, pub = generate_sm2_keypair()

        private_pem, public_pem = sm2_keypair_to_pem(priv, pub)

        assert "BEGIN SM2 PRIVATE KEY" in private_pem
        assert "BEGIN SM2 PUBLIC KEY" in public_pem

        # Round-trip
        loaded_priv = load_sm2_private_key_from_pem(private_pem)
        loaded_pub = load_sm2_public_key_from_pem(public_pem)

        assert loaded_priv == priv
        assert loaded_pub == pub

    def test_key_pem_roundtrip_encrypt(self):
        """Test encrypt/decrypt after PEM serialization round-trip."""
        priv, pub = generate_sm2_keypair()
        _, public_pem = sm2_keypair_to_pem(priv, pub)
        private_pem, _ = sm2_keypair_to_pem(priv, pub)

        loaded_priv = load_sm2_private_key_from_pem(private_pem)
        loaded_pub = load_sm2_public_key_from_pem(public_pem)

        plaintext = b"Key serialization round-trip test."
        ct = sm2_encrypt(plaintext, loaded_pub)
        pt = sm2_decrypt(ct, loaded_priv)

        assert pt == plaintext

    def test_ciphertext_mode_compatibility(self):
        """Test both C1C2C3 (mode 0) and C1C3C2 (mode 1) formats."""
        priv, pub = generate_sm2_keypair()
        plaintext = b"Mode compatibility test."

        # C1C2C3 format (default)
        ct_mode0 = sm2_encrypt(plaintext, pub, mode=0)
        assert sm2_decrypt(ct_mode0, priv, mode=0) == plaintext

        # C1C3C2 format
        ct_mode1 = sm2_encrypt(plaintext, pub, mode=1)
        assert sm2_decrypt(ct_mode1, priv, mode=1) == plaintext

        # Different ciphertexts
        assert ct_mode0 != ct_mode1
