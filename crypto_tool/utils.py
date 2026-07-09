"""
Utility functions for the crypto tool.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Union


def read_file(path: str, binary: bool = True) -> Union[bytes, str]:
    """Read file contents.

    Args:
        path: Path to the file.
        binary: Read in binary mode if True, text mode otherwise.

    Returns:
        File contents as bytes (or str if binary=False).
    """
    mode = "rb" if binary else "r"
    with open(path, mode) as f:
        return f.read()


def write_file(path: str, data: bytes) -> None:
    """Write binary data to a file.

    Args:
        path: Path to the file.
        data: Data to write.
    """
    with open(path, "wb") as f:
        f.write(data)


def ensure_dir(path: str) -> None:
    """Create a directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def file_exists(path: str) -> bool:
    """Check if a file exists."""
    return os.path.isfile(path)


def get_file_size(path: str) -> int:
    """Get file size in bytes."""
    return os.path.getsize(path)


def prompt_password(confirm: bool = True) -> str:
    """Securely prompt for a password.

    Args:
        confirm: Whether to ask for confirmation.

    Returns:
        Password string.
    """
    import getpass

    password = getpass.getpass("Enter password: ")
    if confirm:
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return password


def format_bytes(size: int) -> str:
    """Format byte count into a human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# ── Input Helpers ───────────────────────────────────────────────────────

def is_pipe() -> bool:
    """Check if stdin is connected to a pipe (not a TTY)."""
    return not sys.stdin.isatty()


def get_stdin_data() -> bytes:
    """Read all data from stdin.

    Returns:
        Raw bytes from stdin.
    """
    return sys.stdin.buffer.read()


def get_input_data(input_file: Optional[str] = None,
                   text: Optional[str] = None,
                   use_stdin: bool = False) -> Optional[bytes]:
    """Resolve input data from multiple possible sources.

    Priority: text > stdin/pipe > file

    Args:
        input_file: Path to input file (or '-' for stdin).
        text: Direct text input.
        use_stdin: Force reading from stdin.

    Returns:
        Input data as bytes, or None if no input is available.
    """
    if text is not None:
        return text.encode("utf-8")

    if use_stdin or is_pipe():
        return get_stdin_data()

    if input_file is not None:
        if input_file == "-":
            return get_stdin_data()
        return read_file(input_file)

    # Auto-detect pipe as last resort
    if is_pipe():
        return get_stdin_data()

    return None


# ── Clipboard Helpers (cross-platform) ──────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard.

    Args:
        text: Text to copy.

    Returns:
        True on success, False on failure.
    """
    try:
        if sys.platform == "win32":
            import subprocess
            subprocess.run(["clip"], input=text.encode("utf-16le"), check=False,
                           creationflags=0x08000000)  # CREATE_NO_WINDOW
            return True
        elif sys.platform == "darwin":
            import subprocess
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=False)
            return True
        else:
            # Linux: try xclip or xsel
            import subprocess
            for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "-ib"]):
                try:
                    subprocess.run(cmd, input=text.encode("utf-8"), check=True)
                    return True
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
            return False
    except Exception:
        return False
