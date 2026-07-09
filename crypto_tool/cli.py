"""
Command-line interface for the crypto tool.

Supports AES, SM4, RSA, SM2, hashing, HMAC, and encoding operations.
Multi-line input via --stdin, --text, or file (-i).
"""

import os
import sys
import click

from .cipher import (
    generate_aes_key,
    aes_encrypt_cbc,
    aes_decrypt_cbc,
    aes_encrypt_gcm,
    aes_decrypt_gcm,
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    serialize_private_key,
    serialize_public_key,
    load_private_key_from_pem,
    load_public_key_from_pem,
    # SM4
    generate_sm4_key,
    sm4_encrypt_cbc,
    sm4_decrypt_cbc,
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    # Re-exports from hash_utils
    hash_data,
    sm3_hash,
    sm3_salted_hash,
    hmac_sign,
    derive_key,
    to_hex,
    from_hex,
    to_base64,
    from_base64,
    # ChaCha20
    chacha20_encrypt,
    chacha20_decrypt,
    # Ed25519
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    load_ed25519_private_key_from_pem,
    load_ed25519_public_key_from_pem,
)
from .sm_cipher import (
    generate_sm2_keypair,
    sm2_encrypt,
    sm2_decrypt,
    sm2_sign,
    sm2_verify,
    sm2_keypair_to_pem,
    load_sm2_public_key_from_pem,
    load_sm2_private_key_from_pem,
)
from .utils import (
    read_file,
    write_file,
    ensure_dir,
    file_exists,
    get_file_size,
    prompt_password,
    format_bytes,
    is_pipe,
    get_stdin_data,
    get_input_data,
)


# ── Shared Options ──────────────────────────────────────────────────────

def _input_options(f):
    """Decorator adding input source options to a command."""
    options = [
        click.option("-i", "--input", "input_file", default=None,
                     help="Input file (use '-' for stdin)."),
        click.option("-t", "--text", default=None,
                     help="Input text string directly."),
        click.option("-I", "--stdin", "use_stdin", is_flag=True, default=False,
                     help="Read input from stdin (also auto-detected for pipes)."),
    ]
    for opt in reversed(options):
        f = opt(f)
    return f


def _resolve_input(input_file, text, use_stdin):
    """Resolve input data from multiple possible sources.

    Returns bytes or None if no input was provided.
    """
    if text is not None:
        return text.encode("utf-8")
    if use_stdin or is_pipe():
        return get_stdin_data()
    if input_file is not None:
        if input_file == "-":
            return get_stdin_data()
        return read_file(input_file)
    # Auto-detect pipe
    if is_pipe():
        return get_stdin_data()
    return None


def _resolve_output(output_file, data, default_ext=".out"):
    """Write data to file or stdout."""
    if output_file:
        write_file(output_file, data)
        click.echo(f"Output written to: {output_file} ({format_bytes(len(data))})")
    else:
        # Write binary to stdout; use text wrapper for readability when possible
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


@click.group()
@click.version_option(
    version="0.2.0",
    message=(
        "Crypto Tool %(version)s\n"
        "Author:   WU GUOHAI\n"
        "AI Model: DeepSeek\n"
        "AI Tool:  Claude Code\n"
        "License:  MIT\n"
        "GitHub:   https://github.com/GitHub-hai/crypto-tool"
    ),
)
def main():
    """Crypto Tool — Encrypt, decrypt, hash, and sign data.

    Supports: AES, SM4 (symmetric), RSA, SM2 (asymmetric),
    SM3, SHA-256/384/512, MD5 (hashing), Base64, Hex (encoding).

    Author: WU GUOHAI | GitHub: https://github.com/GitHub-hai/crypto-tool

    \b
    Input can be provided via:
      -i FILE       Read from file (use '-' for stdin)
      -t TEXT       Provide text directly
      -I, --stdin   Read from stdin (also auto-detected for pipes)
    """
    pass


# ── Key Generation ──────────────────────────────────────────────────────

@main.group("key")
def key_group():
    """Generate and manage cryptographic keys."""
    pass


@key_group.command("gen-aes")
@click.option("-s", "--size", type=click.Choice(["128", "192", "256"]), default="256",
              help="AES key size in bits.")
@click.option("-o", "--output", default=None, help="Output file for the key.")
def gen_aes(size, output):
    """Generate a random AES key."""
    key = generate_aes_key(int(size))
    key_b64 = to_base64(key)

    if output:
        write_file(output, key)
        click.echo(f"AES-{size} key written to: {output}")
    else:
        click.echo(f"AES-{size} key (base64): {key_b64}")


@key_group.command("gen-rsa")
@click.option("-s", "--size", type=int, default=2048, help="RSA key size in bits.")
@click.option("--private-out", default="private.pem", help="Output file for private key.")
@click.option("--public-out", default="public.pem", help="Output file for public key.")
def gen_rsa(size, private_out, public_out):
    """Generate an RSA key pair."""
    private_key, public_key = generate_rsa_keypair(size)

    write_file(private_out, serialize_private_key(private_key))
    write_file(public_out, serialize_public_key(public_key))

    click.echo(f"RSA-{size} key pair generated:")
    click.echo(f"  Private key: {private_out}")
    click.echo(f"  Public key:  {public_out}")


# ── AES Encryption/Decryption ───────────────────────────────────────────

@main.group("aes")
def aes_group():
    """AES symmetric encryption operations."""
    pass


@aes_group.command("encrypt")
@click.option("-m", "--mode", type=click.Choice(["cbc", "gcm"]), default="gcm",
              help="AES encryption mode.")
@click.option("-k", "--key-file", default=None, help="File containing the AES key.")
@click.option("--password", is_flag=True, help="Derive key from password instead of key file.")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--format", "out_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Output encoding format for ciphertext.")
@_input_options
def aes_encrypt(mode, key_file, password, output, out_fmt, input_file, text, use_stdin):
    """Encrypt data using AES."""
    plaintext = _resolve_input(input_file, text, use_stdin)
    if plaintext is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    if password:
        pwd = prompt_password()
        salt = os.urandom(16)
        key = derive_key(pwd, salt)
    else:
        if not key_file:
            raise click.UsageError("Either -k/--key-file or --password is required.")
        key = read_file(key_file)
        salt = None

    if mode == "gcm":
        iv, ciphertext, tag = aes_encrypt_gcm(plaintext, key)
        packaged = (salt or b"") + iv + tag + ciphertext
    else:
        iv, ciphertext = aes_encrypt_cbc(plaintext, key)
        packaged = (salt or b"") + iv + ciphertext

    if out_fmt == "hex":
        output_data = to_hex(packaged).encode("ascii")
    else:
        output_data = to_base64(packaged).encode("ascii")

    _resolve_output(output, output_data)
    if output:
        click.echo(f"Encrypted ({format_bytes(len(plaintext))} → {format_bytes(len(packaged))}) "
                    f"using AES-{mode.upper()}")


@aes_group.command("decrypt")
@click.option("-m", "--mode", type=click.Choice(["cbc", "gcm"]), default="gcm",
              help="AES encryption mode.")
@click.option("-k", "--key-file", default=None, help="File containing the AES key.")
@click.option("--password", is_flag=True, help="Derive key from password instead of key file.")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--input-format", "in_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Input encoding format of ciphertext.")
@_input_options
def aes_decrypt(mode, key_file, password, output, in_fmt, input_file, text, use_stdin):
    """Decrypt data using AES."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    if in_fmt == "hex":
        data = from_hex(encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data)
    else:
        data = from_base64(encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data)

    if password:
        salt = data[:16]
        data = data[16:]
        pwd = prompt_password(confirm=False)
        key = derive_key(pwd, salt)
    else:
        if not key_file:
            raise click.UsageError("Either -k/--key-file or --password is required.")
        key = read_file(key_file)

    if mode == "gcm":
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        plaintext = aes_decrypt_gcm(iv, ciphertext, tag, key)
        if plaintext is None:
            click.echo("Error: Authentication failed. Wrong key or corrupted data.", err=True)
            sys.exit(1)
    else:
        iv = data[:16]
        ciphertext = data[16:]
        plaintext = aes_decrypt_cbc(iv, ciphertext, key)

    _resolve_output(output, plaintext)
    if output:
        click.echo(f"Decrypted ({format_bytes(len(data))} → {format_bytes(len(plaintext))})")


# ── SM4 Encryption/Decryption ───────────────────────────────────────────

@main.group("sm4")
def sm4_group():
    """SM4 symmetric encryption (Chinese National Standard)."""
    pass


@sm4_group.command("gen-key")
@click.option("-o", "--output", default=None, help="Output file for the key.")
def sm4_gen_key(output):
    """Generate a random SM4 key (128-bit)."""
    key = generate_sm4_key()
    key_hex = to_hex(key)

    if output:
        write_file(output, key)
        click.echo(f"SM4 key written to: {output}")
    else:
        click.echo(f"SM4 key (hex): {key_hex}")


@sm4_group.command("encrypt")
@click.option("-m", "--mode", type=click.Choice(["cbc", "ecb"]), default="cbc",
              help="SM4 encryption mode. CBC recommended.")
@click.option("-k", "--key-file", required=True, help="File containing the SM4 key (16 bytes).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--format", "out_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Output encoding format.")
@_input_options
def sm4_encrypt(mode, key_file, output, out_fmt, input_file, text, use_stdin):
    """Encrypt data using SM4."""
    plaintext = _resolve_input(input_file, text, use_stdin)
    if plaintext is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    key = read_file(key_file)

    if mode == "cbc":
        iv, ciphertext = sm4_encrypt_cbc(plaintext, key)
        packaged = iv + ciphertext
    else:
        ciphertext = sm4_encrypt_ecb(plaintext, key)
        packaged = ciphertext

    if out_fmt == "hex":
        output_data = to_hex(packaged).encode("ascii")
    else:
        output_data = to_base64(packaged).encode("ascii")

    _resolve_output(output, output_data)
    if output:
        click.echo(f"Encrypted ({format_bytes(len(plaintext))} → {format_bytes(len(packaged))}) "
                    f"using SM4-{mode.upper()}")


@sm4_group.command("decrypt")
@click.option("-m", "--mode", type=click.Choice(["cbc", "ecb"]), default="cbc",
              help="SM4 encryption mode.")
@click.option("-k", "--key-file", required=True, help="File containing the SM4 key (16 bytes).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--input-format", "in_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Input encoding format of ciphertext.")
@_input_options
def sm4_decrypt(mode, key_file, output, in_fmt, input_file, text, use_stdin):
    """Decrypt data using SM4."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    data = from_hex(raw) if in_fmt == "hex" else from_base64(raw)
    key = read_file(key_file)

    try:
        if mode == "cbc":
            iv = data[:16]
            ciphertext = data[16:]
            plaintext = sm4_decrypt_cbc(iv, ciphertext, key)
        else:
            plaintext = sm4_decrypt_ecb(data, key)
    except ValueError as e:
        click.echo(f"Error: Decryption failed — {e}. Wrong key or corrupted data.", err=True)
        sys.exit(1)

    _resolve_output(output, plaintext)
    if output:
        click.echo(f"Decrypted ({format_bytes(len(data))} → {format_bytes(len(plaintext))})")


# ── ChaCha20-Poly1305 Encryption/Decryption ─────────────────────────────

@main.group("chacha20")
def chacha20_group():
    """ChaCha20-Poly1305 authenticated encryption."""
    pass


@chacha20_group.command("encrypt")
@click.option("-k", "--key-file", required=True, help="File containing the 32-byte key.")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--format", "out_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Output encoding format.")
@_input_options
def chacha20_encrypt_cmd(key_file, output, out_fmt, input_file, text, use_stdin):
    """Encrypt data using ChaCha20-Poly1305."""
    plaintext = _resolve_input(input_file, text, use_stdin)
    if plaintext is None:
        raise click.UsageError("No input provided.")
    key = read_file(key_file)
    nonce, ciphertext, tag = chacha20_encrypt(plaintext, key)
    packaged = nonce + tag + ciphertext
    output_data = to_hex(packaged).encode("ascii") if out_fmt == "hex" else to_base64(packaged).encode("ascii")
    _resolve_output(output, output_data)
    if output:
        click.echo(f"Encrypted ({format_bytes(len(plaintext))} → {format_bytes(len(packaged))}) using ChaCha20-Poly1305")


@chacha20_group.command("decrypt")
@click.option("-k", "--key-file", required=True, help="File containing the 32-byte key.")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--input-format", "in_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Input encoding format.")
@_input_options
def chacha20_decrypt_cmd(key_file, output, in_fmt, input_file, text, use_stdin):
    """Decrypt data using ChaCha20-Poly1305."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided.")
    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    data = from_hex(raw) if in_fmt == "hex" else from_base64(raw)
    key = read_file(key_file)
    if len(data) < 28:
        raise click.UsageError("Ciphertext too short.")
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    plaintext = chacha20_decrypt(nonce, ciphertext, tag, key)
    if plaintext is None:
        click.echo("Error: Authentication failed. Wrong key or corrupted data.", err=True)
        sys.exit(1)
    _resolve_output(output, plaintext)
    if output:
        click.echo(f"Decrypted ({format_bytes(len(data))} → {format_bytes(len(plaintext))})")


# ── Ed25519 Signatures ──────────────────────────────────────────────────

@main.group("ed25519")
def ed25519_group():
    """Ed25519 digital signatures (signature-only, no encryption)."""
    pass


@ed25519_group.command("gen-key")
@click.option("--private-out", default="ed25519_private.pem", help="Output file for private key.")
@click.option("--public-out", default="ed25519_public.pem", help="Output file for public key.")
def ed25519_gen_key(private_out, public_out):
    """Generate an Ed25519 key pair."""
    priv, pub = generate_ed25519_keypair()
    write_file(private_out, serialize_ed25519_private_key(priv))
    write_file(public_out, serialize_ed25519_public_key(pub))
    click.echo(f"Ed25519 key pair generated:\n  Private: {private_out}\n  Public:  {public_out}")


@ed25519_group.command("sign")
@click.option("-k", "--key-file", required=True, help="Private key file (PEM).")
@click.option("-o", "--output", default=None, help="Output file for signature.")
@_input_options
def ed25519_sign_cmd(key_file, output, input_file, text, use_stdin):
    """Sign data using Ed25519."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")
    private_key = load_ed25519_private_key_from_pem(read_file(key_file))
    signature = ed25519_sign(data, private_key)
    sig_output = to_base64(signature).encode("ascii")
    _resolve_output(output, sig_output)
    if output:
        click.echo(f"Signed. Signature: {format_bytes(len(signature))}")


@ed25519_group.command("verify")
@click.option("-k", "--key-file", required=True, help="Public key file (PEM).")
@click.option("-s", "--signature", "sig_file", required=True, help="Signature file.")
@_input_options
def ed25519_verify_cmd(key_file, sig_file, input_file, text, use_stdin):
    """Verify an Ed25519 signature."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")
    public_key = load_ed25519_public_key_from_pem(read_file(key_file))
    sig_b64 = read_file(sig_file, binary=False).strip()
    signature = from_base64(sig_b64)
    if ed25519_verify(data, signature, public_key):
        click.echo("✓ Signature is valid.")
    else:
        click.echo("✗ Signature is INVALID.", err=True)
        sys.exit(1)


# ── RSA Encryption/Decryption ───────────────────────────────────────────

@main.group("rsa")
def rsa_group():
    """RSA asymmetric encryption operations."""
    pass


@rsa_group.command("encrypt")
@click.option("-k", "--key-file", required=True, help="Public key file (PEM).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--format", "out_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Output encoding format.")
@_input_options
def rsa_encrypt_cmd(key_file, output, out_fmt, input_file, text, use_stdin):
    """Encrypt data using RSA (for small files ≤ key size - padding)."""
    plaintext = _resolve_input(input_file, text, use_stdin)
    if plaintext is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    public_key = load_public_key_from_pem(read_file(key_file))
    ciphertext = rsa_encrypt(plaintext, public_key)

    output_data = to_hex(ciphertext).encode("ascii") if out_fmt == "hex" else to_base64(ciphertext).encode("ascii")
    _resolve_output(output, output_data)
    if output:
        click.echo(f"Encrypted ({format_bytes(len(plaintext))} → {format_bytes(len(ciphertext))})")


@rsa_group.command("decrypt")
@click.option("-k", "--key-file", required=True, help="Private key file (PEM).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--input-format", "in_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Input encoding format.")
@_input_options
def rsa_decrypt_cmd(key_file, output, in_fmt, input_file, text, use_stdin):
    """Decrypt data using RSA."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided.")

    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    ciphertext = from_hex(raw) if in_fmt == "hex" else from_base64(raw)
    private_key = load_private_key_from_pem(read_file(key_file))

    plaintext = rsa_decrypt(ciphertext, private_key)
    _resolve_output(output, plaintext)
    if output:
        click.echo(f"Decrypted ({format_bytes(len(ciphertext))} → {format_bytes(len(plaintext))})")


@rsa_group.command("sign")
@click.option("-k", "--key-file", required=True, help="Private key file (PEM).")
@click.option("-o", "--output", default=None, help="Output file for signature.")
@_input_options
def rsa_sign_cmd(key_file, output, input_file, text, use_stdin):
    """Sign data using RSA-PSS."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    private_key = load_private_key_from_pem(read_file(key_file))
    signature = rsa_sign(data, private_key)

    sig_output = to_base64(signature).encode("ascii")
    _resolve_output(output, sig_output)
    if output:
        click.echo(f"Signed. Signature size: {format_bytes(len(signature))}")


@rsa_group.command("verify")
@click.option("-k", "--key-file", required=True, help="Public key file (PEM).")
@click.option("-s", "--signature", "sig_file", required=True, help="Signature file.")
@_input_options
def rsa_verify_cmd(key_file, sig_file, input_file, text, use_stdin):
    """Verify an RSA-PSS signature."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    public_key = load_public_key_from_pem(read_file(key_file))
    sig_b64 = read_file(sig_file, binary=False).strip()
    signature = from_base64(sig_b64)

    if rsa_verify(data, signature, public_key):
        click.echo("✓ Signature is valid.")
    else:
        click.echo("✗ Signature is INVALID.", err=True)
        sys.exit(1)


# ── SM2 Asymmetric Encryption ───────────────────────────────────────────

@main.group("sm2")
def sm2_group():
    """SM2 asymmetric encryption (Chinese National Standard)."""
    pass


@sm2_group.command("gen-key")
@click.option("--private-out", default="sm2_private.key", help="Output file for private key.")
@click.option("--public-out", default="sm2_public.key", help="Output file for public key.")
def sm2_gen_key(private_out, public_out):
    """Generate an SM2 key pair."""
    private_hex, public_hex = generate_sm2_keypair()
    private_pem, public_pem = sm2_keypair_to_pem(private_hex, public_hex)

    write_file(private_out, private_pem.encode("ascii"))
    write_file(public_out, public_pem.encode("ascii"))

    click.echo(f"SM2 key pair generated:")
    click.echo(f"  Private key: {private_out}")
    click.echo(f"  Public key:  {public_out}")


@sm2_group.command("encrypt")
@click.option("-k", "--key-file", required=True, help="Public key file (PEM armored).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--format", "out_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Output encoding format.")
@click.option("--cipher-mode", "c_mode", type=click.Choice(["C1C2C3", "C1C3C2"]),
              default="C1C2C3", help="Ciphertext format mode.")
@_input_options
def sm2_encrypt_cmd(key_file, output, out_fmt, c_mode, input_file, text, use_stdin):
    """Encrypt data using SM2 public key (for small data)."""
    plaintext = _resolve_input(input_file, text, use_stdin)
    if plaintext is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    pem_str = read_file(key_file, binary=False)
    public_hex = load_sm2_public_key_from_pem(pem_str)
    mode = 0 if c_mode == "C1C2C3" else 1

    ciphertext = sm2_encrypt(plaintext, public_hex, mode=mode)

    output_data = to_hex(ciphertext).encode("ascii") if out_fmt == "hex" else to_base64(ciphertext).encode("ascii")
    _resolve_output(output, output_data)
    if output:
        click.echo(f"Encrypted ({format_bytes(len(plaintext))} → {format_bytes(len(ciphertext))})")


@sm2_group.command("decrypt")
@click.option("-k", "--key-file", required=True, help="Private key file (PEM armored).")
@click.option("-o", "--output", default=None, help="Output file (stdout if omitted).")
@click.option("--input-format", "in_fmt", type=click.Choice(["base64", "hex"]), default="base64",
              help="Input encoding format.")
@click.option("--cipher-mode", "c_mode", type=click.Choice(["C1C2C3", "C1C3C2"]),
              default="C1C2C3", help="Ciphertext format mode (must match encryption).")
@_input_options
def sm2_decrypt_cmd(key_file, output, in_fmt, c_mode, input_file, text, use_stdin):
    """Decrypt data using SM2 private key."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided.")

    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    ciphertext = from_hex(raw) if in_fmt == "hex" else from_base64(raw)
    pem_str = read_file(key_file, binary=False)
    private_hex = load_sm2_private_key_from_pem(pem_str)
    mode = 0 if c_mode == "C1C2C3" else 1

    plaintext = sm2_decrypt(ciphertext, private_hex, mode=mode)
    _resolve_output(output, plaintext)
    if output:
        click.echo(f"Decrypted ({format_bytes(len(ciphertext))} → {format_bytes(len(plaintext))})")


@sm2_group.command("sign")
@click.option("-k", "--key-file", required=True, help="Private key file (PEM armored).")
@click.option("--public-key", default=None, help="Public key file (PEM armored). Required for SM2.")
@click.option("-o", "--output", default=None, help="Output file for signature.")
@_input_options
def sm2_sign_cmd(key_file, public_key, output, input_file, text, use_stdin):
    """Sign data using SM2 (SM2withSM3)."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    pem_str = read_file(key_file, binary=False)
    private_hex = load_sm2_private_key_from_pem(pem_str)

    public_hex = ""
    if public_key:
        pub_pem = read_file(public_key, binary=False)
        public_hex = load_sm2_public_key_from_pem(pub_pem)

    signature = sm2_sign(data, private_hex, public_hex)
    sig_output = signature.encode("ascii")

    _resolve_output(output, sig_output)
    if output:
        click.echo(f"Signed. Signature: {len(signature)} hex chars")


@sm2_group.command("verify")
@click.option("-k", "--key-file", required=True, help="Public key file (PEM armored).")
@click.option("-s", "--signature", "sig_file", required=True, help="Signature file.")
@_input_options
def sm2_verify_cmd(key_file, sig_file, input_file, text, use_stdin):
    """Verify an SM2 signature."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    pem_str = read_file(key_file, binary=False)
    public_hex = load_sm2_public_key_from_pem(pem_str)
    signature = read_file(sig_file, binary=False).strip()

    if sm2_verify(data, signature, public_hex):
        click.echo("✓ Signature is valid.")
    else:
        click.echo("✗ Signature is INVALID.", err=True)
        sys.exit(1)


# ── Hashing ─────────────────────────────────────────────────────────────

@main.group("hash")
def hash_group():
    """Hash and HMAC operations."""
    pass


@hash_group.command("digest")
@click.option("-a", "--algorithm",
              type=click.Choice(["sm3", "md5", "sha1", "sha256", "sha384", "sha512"]),
              default="sha256", help="Hash algorithm.")
@click.option("-s", "--salt", default=None,
              help="Salt string for SM3+SALT mode (prepended to data). Ignored for other algorithms.")
@click.option("-o", "--output", default=None, help="Output file for digest.")
@_input_options
def hash_digest(algorithm, output, salt, input_file, text, use_stdin):
    """Compute the hash digest of input data.

    When --salt is provided with SM3, the mode becomes SM3+SALT:
    SM3(salt_bytes + data), replicating the Java NationalSecret3 encrypt() logic.
    """
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided. Use -i, -t, --stdin, or pipe data.")

    if salt is not None and algorithm == "sm3":
        digest = sm3_salted_hash(data, salt.encode("utf-8"))
        algo_label = "SM3+SALT"
    else:
        digest = hash_data(data, algorithm)
        algo_label = algorithm.upper()

    if output:
        write_file(output, digest.encode("ascii"))
        click.echo(f"Digest written to: {output}")
    click.echo(f"{algo_label}: {digest}")


@hash_group.command("hmac")
@click.option("-a", "--algorithm", type=click.Choice(["sm3", "sha256", "sha384", "sha512"]),
              default="sha256", help="HMAC hash algorithm.")
@click.option("-k", "--key-file", required=True, help="File containing the secret key.")
@click.option("-o", "--output", default=None, help="Output file for HMAC.")
@_input_options
def hmac_cmd(algorithm, key_file, output, input_file, text, use_stdin):
    """Compute HMAC of input data."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    key = read_file(key_file)
    result = hmac_sign(data, key, algorithm)

    if output:
        write_file(output, result.encode("ascii"))
        click.echo(f"HMAC written to: {output}")
    click.echo(f"HMAC-{algorithm.upper()}: {result}")


# ── Encoding ────────────────────────────────────────────────────────────

@main.group("encode")
def encode_group():
    """Base64 and Hex encoding utilities."""
    pass


@encode_group.command("b64")
@click.option("-o", "--output", default=None, help="Output file.")
@_input_options
def encode_b64(output, input_file, text, use_stdin):
    """Base64-encode input data."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    encoded = to_base64(data)
    if output:
        write_file(output, encoded.encode("ascii"))
        click.echo(f"Encoded → {output}")
    else:
        click.echo(encoded)


@encode_group.command("b64d")
@click.option("-o", "--output", default=None, help="Output file.")
@_input_options
def decode_b64(output, input_file, text, use_stdin):
    """Base64-decode input data."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided.")

    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    decoded = from_base64(raw.strip())

    if output:
        write_file(output, decoded)
        click.echo(f"Decoded → {output} ({format_bytes(len(decoded))})")
    else:
        sys.stdout.buffer.write(decoded)
        sys.stdout.buffer.flush()


@encode_group.command("hex")
@click.option("-o", "--output", default=None, help="Output file.")
@_input_options
def encode_hex(output, input_file, text, use_stdin):
    """Hex-encode input data."""
    data = _resolve_input(input_file, text, use_stdin)
    if data is None:
        raise click.UsageError("No input provided.")

    encoded = to_hex(data)
    if output:
        write_file(output, encoded.encode("ascii"))
        click.echo(f"Hex encoded → {output}")
    else:
        click.echo(encoded)


@encode_group.command("unhex")
@click.option("-o", "--output", default=None, help="Output file.")
@_input_options
def decode_hex(output, input_file, text, use_stdin):
    """Hex-decode input data."""
    encoded_data = _resolve_input(input_file, text, use_stdin)
    if encoded_data is None:
        raise click.UsageError("No input provided.")

    raw = encoded_data.decode("ascii") if isinstance(encoded_data, bytes) else encoded_data
    decoded = from_hex(raw.strip())

    if output:
        write_file(output, decoded)
        click.echo(f"Hex decoded → {output} ({format_bytes(len(decoded))})")
    else:
        sys.stdout.buffer.write(decoded)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
