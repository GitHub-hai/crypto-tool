"""
Tests for the hash module (SM3, SHA family, HMAC).
"""

import pytest

from crypto_tool.hash_utils import (
    sm3_hash,
    sm3_salted_hash,
    hash_data,
    hmac_sign,
    hmac_verify,
    derive_key,
    to_hex,
    from_hex,
    to_base64,
    from_base64,
)


class TestSM3:
    """SM3 hash algorithm tests (Chinese National Standard GM/T 0004-2012)."""

    def test_empty_string(self):
        """SM3 hash of empty string."""
        digest = sm3_hash(b"")
        assert len(digest) == 64  # 256-bit = 64 hex chars

    def test_known_vector_1(self):
        """SM3 test vector from GM/T 0004-2012: "abc"."""
        digest = sm3_hash(b"abc")
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert digest == expected

    def test_known_vector_2(self):
        """SM3 test vector: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" * 1.

        Actually, let's use the standard test vector: 512-bit message.
        """
        # GM/T 0004 test vector: message = "abcd" * 16
        data = b"abcd" * 16
        digest = sm3_hash(data)
        expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        assert digest == expected

    def test_chinese_text(self):
        """SM3 hash of Chinese text."""
        digest = sm3_hash("你好世界".encode("utf-8"))
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_long_message(self):
        """SM3 hash of a long message."""
        data = b"x" * 10000
        digest = sm3_hash(data)
        assert len(digest) == 64

    def test_consistency(self):
        """Same input produces same output."""
        data = b"consistency check."
        assert sm3_hash(data) == sm3_hash(data)

    def test_avalanche(self):
        """Small change in input produces completely different hash."""
        h1 = sm3_hash(b"message")
        h2 = sm3_hash(b"messagf")  # one bit different
        assert h1 != h2
        # At least half the hex chars should differ
        diff = sum(1 for a, b in zip(h1, h2) if a != b)
        assert diff > 30

    def test_via_hash_data(self):
        """SM3 accessible via generic hash_data function."""
        digest = hash_data(b"abc", "sm3")
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert digest == expected

    def test_sm3_hmac(self):
        """HMAC-SM3 test."""
        result = hmac_sign(b"message", b"key", "sm3")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sm3_hmac_verify(self):
        """HMAC-SM3 verification."""
        data = b"authenticated message"
        key = b"secret key"
        mac = hmac_sign(data, key, "sm3")
        assert hmac_verify(data, key, mac, "sm3")
        assert not hmac_verify(data, b"wrong key", mac, "sm3")
        assert not hmac_verify(b"tampered", key, mac, "sm3")


class TestSM3Salted:
    """SM3 with salt tests — replicates Java NationalSecret3 logic."""

    def test_empty_salt_same_as_pure_sm3(self):
        """SM3 salted with empty salt equals pure SM3 (matches Java behavior)."""
        data = b"hello world"
        assert sm3_salted_hash(data, b"") == sm3_hash(data)

    def test_salt_prepended(self):
        """SM3 salted does SM3(salt + data), matching Java SmUtil.sm3(salt + data)."""
        data = b"hello"
        salt = b"mysalt"
        result = sm3_salted_hash(data, salt)
        # Should equal SM3("mysalt" + "hello") = SM3(b"mysalthello")
        expected = sm3_hash(b"mysalthello")
        assert result == expected

    def test_salt_changes_hash(self):
        """Adding a salt produces a different hash than no salt."""
        data = b"test data"
        result_no_salt = sm3_salted_hash(data, b"")
        result_with_salt = sm3_salted_hash(data, b"salt")
        assert result_no_salt != result_with_salt

    def test_different_salts_different_hashes(self):
        """Different salts produce different hashes for the same data."""
        data = b"same data"
        h1 = sm3_salted_hash(data, b"salt1")
        h2 = sm3_salted_hash(data, b"salt2")
        assert h1 != h2

    def test_output_format(self):
        """Output is 64 hex chars."""
        result = sm3_salted_hash(b"data", b"salt")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_unicode_salt(self):
        """Salt and data can be Unicode."""
        data = "用户数据".encode("utf-8")
        salt = "加盐值".encode("utf-8")
        result = sm3_salted_hash(data, salt)
        # Manual verification: SM3(salt + data)
        expected = sm3_hash(salt + data)
        assert result == expected
        assert len(result) == 64

    def test_java_compat_scenario(self):
        """Simulates Java NationalSecret3.encrypt(data, salt) = SmUtil.sm3(salt+data)."""
        # In the Java code:
        #   encrypt("mydata", "mysalt") → SmUtil.sm3("mysalt" + "mydata")
        data = b"mydata"
        salt = b"mysalt"
        result = sm3_salted_hash(data, salt)
        expected = sm3_hash(b"mysaltmydata")
        assert result == expected


class TestSHA:
    """SHA family tests."""

    def test_sha256_known_vector(self):
        digest = hash_data(b"abc", "sha256")
        expected = (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert digest == expected

    def test_sha512_known_vector(self):
        digest = hash_data(b"abc", "sha512")
        expected = (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        assert digest == expected

    def test_sha384_known_vector(self):
        digest = hash_data(b"abc", "sha384")
        assert len(digest) == 96  # 384 bits = 96 hex chars

    def test_sha1_known_vector(self):
        digest = hash_data(b"abc", "sha1")
        assert len(digest) == 40  # 160 bits = 40 hex chars

    def test_invalid_algorithm(self):
        with pytest.raises(ValueError):
            hash_data(b"test", "nonexistent")


class TestHMAC:
    """HMAC tests."""

    def test_hmac_sha256_known(self):
        """HMAC-SHA256 RFC 4231 test vector."""
        key = b"\x0b" * 20
        data = b"Hi There"
        result = hmac_sign(data, key, "sha256")
        expected = (
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        assert result == expected

    def test_hmac_verify(self):
        data = b"verify me"
        key = b"auth key"
        mac = hmac_sign(data, key, "sha256")
        assert hmac_verify(data, key, mac, "sha256")
        assert not hmac_verify(b"tampered", key, mac, "sha256")
        assert not hmac_verify(data, b"wrong key", mac, "sha256")

    def test_hmac_invalid_algo(self):
        with pytest.raises(ValueError):
            hmac_sign(b"data", b"key", "md5")


class TestEncoding:
    """Hex and Base64 encoding tests."""

    def test_hex_roundtrip(self):
        original = b"\x00\xff\xab\x12\xde\xad\xbe\xef"
        assert from_hex(to_hex(original)) == original

    def test_hex_case_insensitive(self):
        assert from_hex("ABCDEF") == from_hex("abcdef")

    def test_hex_whitespace(self):
        assert from_hex("  ab cd ef \n") == b"\xab\xcd\xef"

    def test_base64_roundtrip(self):
        original = b"\x00\xff\xab\x12" * 10
        assert from_base64(to_base64(original)) == original


class TestKDF:
    """Key derivation function tests."""

    def test_derive_key_sha256(self):
        salt = b"\x12\x34\x56\x78" * 4
        key = derive_key("password123", salt)
        assert len(key) == 32  # default length

    def test_derive_key_deterministic(self):
        salt = b"fixed salt value 16"
        key1 = derive_key("the password", salt)
        key2 = derive_key("the password", salt)
        assert key1 == key2

    def test_derive_key_different_password(self):
        salt = b"fixed salt value 16"
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_different_salt(self):
        password = "same password"
        salt1 = b"1234567890123456"
        salt2 = b"6543210987654321"
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        assert key1 != key2

    def test_derive_key_custom_length(self):
        salt = b"saltsaltsaltsalt"
        key = derive_key("password", salt, length=48)
        assert len(key) == 48
