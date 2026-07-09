"""
Tests for the cipher module (AES, SM4, RSA, encoding).
"""

import pytest

from crypto_tool.cipher import (
    generate_aes_key,
    aes_encrypt_cbc,
    aes_decrypt_cbc,
    aes_encrypt_gcm,
    aes_decrypt_gcm,
    generate_sm4_key,
    sm4_encrypt_cbc,
    sm4_decrypt_cbc,
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    serialize_private_key,
    serialize_public_key,
    load_private_key_from_pem,
    load_public_key_from_pem,
    # Re-exports from hash_utils
    hash_data,
    hmac_sign,
    derive_key,
    to_base64,
    from_base64,
    to_hex,
    from_hex,
)


class TestAES:
    """AES symmetric encryption tests."""

    def test_key_generation(self):
        for size in (128, 192, 256):
            key = generate_aes_key(size)
            assert len(key) == size // 8

    def test_key_generation_invalid(self):
        with pytest.raises(ValueError):
            generate_aes_key(512)

    def test_cbc_encrypt_decrypt(self):
        key = generate_aes_key(256)
        plaintext = b"Hello, World! This is a test message."

        iv, ciphertext = aes_encrypt_cbc(plaintext, key)
        assert ciphertext != plaintext
        decrypted = aes_decrypt_cbc(iv, ciphertext, key)
        assert decrypted == plaintext

    def test_cbc_binary_data(self):
        key = generate_aes_key(256)
        plaintext = bytes(range(256))

        iv, ciphertext = aes_encrypt_cbc(plaintext, key)
        decrypted = aes_decrypt_cbc(iv, ciphertext, key)
        assert decrypted == plaintext

    def test_gcm_encrypt_decrypt(self):
        key = generate_aes_key(256)
        plaintext = b"Secret message for GCM mode."

        iv, ciphertext, tag = aes_encrypt_gcm(plaintext, key)
        decrypted = aes_decrypt_gcm(iv, ciphertext, tag, key)
        assert decrypted == plaintext

    def test_gcm_with_aad(self):
        key = generate_aes_key(256)
        plaintext = b"Data with AAD."
        aad = b"authenticated metadata"

        iv, ciphertext, tag = aes_encrypt_gcm(plaintext, key, aad)
        decrypted = aes_decrypt_gcm(iv, ciphertext, tag, key, aad)
        assert decrypted == plaintext

    def test_gcm_tampered(self):
        key = generate_aes_key(256)
        iv, ciphertext, tag = aes_encrypt_gcm(b"tamper test", key)

        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        result = aes_decrypt_gcm(iv, bytes(tampered), tag, key)
        assert result is None

    def test_gcm_wrong_key(self):
        key1 = generate_aes_key(256)
        key2 = generate_aes_key(256)
        iv, ciphertext, tag = aes_encrypt_gcm(b"wrong key test", key1)

        result = aes_decrypt_gcm(iv, ciphertext, tag, key2)
        assert result is None

    def test_multi_line_text(self):
        """AES should handle multi-line text correctly."""
        key = generate_aes_key(256)
        plaintext = b"Line 1\nLine 2\nLine 3\n\nEnd of message."

        iv, ct, tag = aes_encrypt_gcm(plaintext, key)
        decrypted = aes_decrypt_gcm(iv, ct, tag, key)
        assert decrypted == plaintext

    def test_unicode_text(self):
        """AES should handle Unicode text (UTF-8)."""
        key = generate_aes_key(256)
        plaintext = "你好，世界！这是测试。🔐".encode("utf-8")

        iv, ct, tag = aes_encrypt_gcm(plaintext, key)
        decrypted = aes_decrypt_gcm(iv, ct, tag, key)
        assert decrypted == plaintext
        assert decrypted.decode("utf-8") == "你好，世界！这是测试。🔐"


class TestSM4:
    """SM4 symmetric encryption tests (Chinese National Standard)."""

    def test_key_generation(self):
        key = generate_sm4_key()
        assert len(key) == 16

    def test_cbc_encrypt_decrypt(self):
        key = generate_sm4_key()
        plaintext = b"SM4-CBC encryption test."

        iv, ciphertext = sm4_encrypt_cbc(plaintext, key)
        assert ciphertext != plaintext
        decrypted = sm4_decrypt_cbc(iv, ciphertext, key)
        assert decrypted == plaintext

    def test_cbc_binary_data(self):
        key = generate_sm4_key()
        plaintext = bytes(range(256))

        iv, ciphertext = sm4_encrypt_cbc(plaintext, key)
        decrypted = sm4_decrypt_cbc(iv, ciphertext, key)
        assert decrypted == plaintext

    def test_ecb_encrypt_decrypt(self):
        key = generate_sm4_key()
        plaintext = b"SM4-ECB mode test."

        ciphertext = sm4_encrypt_ecb(plaintext, key)
        assert ciphertext != plaintext
        decrypted = sm4_decrypt_ecb(ciphertext, key)
        assert decrypted == plaintext

    def test_wrong_key_cbc(self):
        key1 = generate_sm4_key()
        key2 = generate_sm4_key()
        iv, ct = sm4_encrypt_cbc(b"test", key1)

        # Decrypting with wrong key should fail (PKCS7 padding validation)
        with pytest.raises(ValueError, match="padding"):
            sm4_decrypt_cbc(iv, ct, key2)

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            sm4_encrypt_cbc(b"test", b"too short")
        with pytest.raises(ValueError):
            sm4_encrypt_cbc(b"test", b"this key is way too long for SM4")

    def test_multi_line_text(self):
        key = generate_sm4_key()
        plaintext = b"SM4 multi-line:\nLine 1\nLine 2\nLine 3\n"

        iv, ct = sm4_encrypt_cbc(plaintext, key)
        pt = sm4_decrypt_cbc(iv, ct, key)
        assert pt == plaintext

    def test_chinese_text(self):
        """SM4 should handle Chinese text correctly."""
        key = generate_sm4_key()
        plaintext = "国密SM4分组密码算法测试".encode("utf-8")

        iv, ct = sm4_encrypt_cbc(plaintext, key)
        pt = sm4_decrypt_cbc(iv, ct, key)
        assert pt == plaintext
        assert pt.decode("utf-8") == "国密SM4分组密码算法测试"


class TestRSA:
    """RSA asymmetric encryption tests."""

    def test_keypair_generation(self):
        private_key, public_key = generate_rsa_keypair(2048)
        assert private_key.key_size == 2048

    def test_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keypair(2048)
        plaintext = b"RSA test message."

        ciphertext = rsa_encrypt(plaintext, public_key)
        decrypted = rsa_decrypt(ciphertext, private_key)
        assert decrypted == plaintext

    def test_sign_verify(self):
        private_key, public_key = generate_rsa_keypair(2048)
        data = b"Data to be signed."

        signature = rsa_sign(data, private_key)
        assert rsa_verify(data, signature, public_key)

    def test_sign_verify_invalid(self):
        private_key, public_key = generate_rsa_keypair(2048)
        data = b"Original data."
        signature = rsa_sign(data, private_key)

        assert not rsa_verify(b"Tampered data.", signature, public_key)

    def test_key_serialization(self):
        private_key, public_key = generate_rsa_keypair(2048)

        priv_pem = serialize_private_key(private_key)
        pub_pem = serialize_public_key(public_key)

        loaded_priv = load_private_key_from_pem(priv_pem)
        loaded_pub = load_public_key_from_pem(pub_pem)

        ciphertext = rsa_encrypt(b"serialization test", loaded_pub)
        decrypted = rsa_decrypt(ciphertext, loaded_priv)
        assert decrypted == b"serialization test"


class TestHashing:
    """Hashing utility tests."""

    def test_hash_sha256(self):
        digest = hash_data(b"hello", "sha256")
        expected = (
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert digest == expected

    def test_hash_md5(self):
        digest = hash_data(b"hello", "md5")
        assert len(digest) == 32

    def test_hash_sha512(self):
        digest = hash_data(b"hello", "sha512")
        assert len(digest) == 128

    def test_hmac(self):
        result = hmac_sign(b"message", b"key", "sha256")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_derive_key(self):
        salt = b"12345678abcdefgh"
        key = derive_key("my_password", salt)
        assert len(key) == 32

        key2 = derive_key("my_password", salt)
        assert key == key2

        key3 = derive_key("other_password", salt)
        assert key != key3


class TestEncoding:
    """Encoding utility tests."""

    def test_base64_roundtrip(self):
        original = b"\x00\xff\xab\x12" * 10
        encoded = to_base64(original)
        decoded = from_base64(encoded)
        assert decoded == original

    def test_base64_string(self):
        encoded = to_base64(b"hello world")
        assert isinstance(encoded, str)

    def test_hex_roundtrip(self):
        original = b"\x00\xff\xab\x12\xde\xad\xbe\xef" * 4
        encoded = to_hex(original)
        decoded = from_hex(encoded)
        assert decoded == original

    def test_hex_format(self):
        encoded = to_hex(b"\xab\xcd\xef")
        assert encoded == "abcdef"
        assert len(encoded) == 6
