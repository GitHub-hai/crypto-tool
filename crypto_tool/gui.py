"""
Graphical User Interface for the Crypto Tool.

A tkinter-based tabbed GUI supporting symmetric encryption (AES, SM4),
asymmetric encryption (RSA, SM2), hashing (SM3, SHA, MD5), and encoding.
Features multi-line text input/output, file operations, and clipboard support.
"""

import os
import sys
import webbrowser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
from typing import Optional

# Import crypto modules
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
    generate_sm4_key,
    sm4_encrypt_cbc,
    sm4_decrypt_cbc,
    sm4_encrypt_ecb,
    sm4_decrypt_ecb,
    chacha20_encrypt,
    chacha20_decrypt,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    serialize_ed25519_private_key,
    serialize_ed25519_public_key,
    load_ed25519_private_key_from_pem,
    load_ed25519_public_key_from_pem,
    hash_data,
    sm3_hash,
    sm3_salted_hash,
    hmac_sign,
    derive_key,
    to_hex,
    from_hex,
    to_base64,
    from_base64,
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
from .utils import copy_to_clipboard, format_bytes


class CryptoGUI:
    """Main GUI application class."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Crypto Tool - 加解密工具箱")
        self.root.geometry("960x680")
        self.root.minsize(800, 600)

        self._setup_style()
        self._create_widgets()
        self._set_status("Ready")

    def _show_about(self):
        """Show About dialog with clickable GitHub link."""
        dialog = tk.Toplevel(self.root)
        dialog.title("About Crypto Tool")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack()

        from crypto_tool import __version__

        ttk.Label(frame, text=f"Crypto Tool — 加解密工具箱  v{__version__}",
                  font=("", 12, "bold")).pack(pady=(0, 10))

        info = (
            "A versatile encryption/decryption utility supporting\n"
            "AES, SM2, SM3, SM4, RSA, SHA, HMAC, and more.\n\n"
            "Author:   WU GUOHAI\n"
            "AI Model: DeepSeek\n"
            "AI Tool:  Claude Code\n"
            "License:  MIT"
        )
        ttk.Label(frame, text=info, justify="left").pack(pady=(0, 10))

        # Clickable GitHub link
        github_url = "https://github.com/GitHub-hai/crypto-tool"
        link = ttk.Label(
            frame, text=github_url,
            foreground="#0366d6", cursor="hand2",
            font=("", 9, "underline"),
        )
        link.pack()
        link.bind("<Button-1>", lambda e: webbrowser.open(github_url))

        ttk.Button(frame, text="OK", command=dialog.destroy,
                   width=10).pack(pady=(15, 0))

        # Center on parent
        dialog.update_idletasks()
        w, h = dialog.winfo_width(), dialog.winfo_height()
        pw, ph = self.root.winfo_width(), self.root.winfo_height()
        px, py = self.root.winfo_x(), self.root.winfo_y()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        dialog.geometry(f"+{x}+{y}")

    def _setup_style(self):
        """Configure ttk styles."""
        self.style = ttk.Style()
        self.style.theme_use("clam" if sys.platform != "win32" else "vista")

        self.style.configure("Title.TLabel", font=("", 11, "bold"))
        self.style.configure("Status.TLabel", relief="sunken", padding=(5, 2))

    def _set_status(self, message: str):
        """Update the status bar text."""
        self._status_var.set(message)
        self.root.update_idletasks()

    def _create_widgets(self):
        """Build the main UI structure."""
        # Status bar — pack first to reserve bottom space
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", side="bottom")

        self._status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(status_frame, textvariable=self._status_var,
                               relief="sunken", anchor="w", padding=(5, 2))
        status_bar.pack(side="left", fill="x", expand=True)

        # GitHub link + About — right side of status bar
        github_url = "https://github.com/GitHub-hai/crypto-tool"
        ttk.Button(status_frame, text="About",
                   command=self._show_about,
                   width=8).pack(side="right", padx=(0, 3), pady=1)
        gh_link = ttk.Label(
            status_frame,
            text=github_url,
            foreground="#0366d6", cursor="hand2",
            font=("Consolas", 8, "underline"),
        )
        gh_link.pack(side="right", padx=(0, 8))
        gh_link.bind("<Button-1>", lambda e: webbrowser.open(github_url))

        # Notebook (tabs) — fills remaining space above status bar
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=(5, 0))

        # Create each tab
        self._create_symmetric_tab()
        self._create_asymmetric_tab()
        self._create_hash_tab()
        self._create_encode_tab()

    # ── Helper Methods ──────────────────────────────────────────────────

    def _make_input_frame(self, parent, label_text: str, height: int = 10):
        """Create a labeled, scrolled text input area.

        Returns:
            Tuple of (frame, text_widget).
        """
        frame = ttk.LabelFrame(parent, text=label_text)
        text_widget = scrolledtext.ScrolledText(
            frame, height=height, wrap=tk.WORD,
            font=("Consolas", 10), undo=True,
        )
        text_widget.pack(fill="both", expand=True, padx=3, pady=3)
        return frame, text_widget

    def _make_key_row(self, parent, label: str, row: int, browse_cmd=None, gen_cmd=None):
        """Create a key input row with label, entry, and optional buttons.

        Returns the StringVar for the entry.
        """
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="e", padx=(5, 2), pady=3)
        var = tk.StringVar()
        entry = ttk.Entry(parent, textvariable=var, width=50)
        entry.grid(row=row, column=1, columnspan=2, sticky="ew", padx=2, pady=3)

        col = 3
        if browse_cmd:
            ttk.Button(parent, text="Browse", command=browse_cmd).grid(
                row=row, column=col, padx=2, pady=3)
            col += 1
        if gen_cmd:
            ttk.Button(parent, text="Generate", command=gen_cmd).grid(
                row=row, column=col, padx=2, pady=3)
            col += 1

        return var

    def _browse_file(self, var: tk.StringVar, title: str = "Open File",
                     filetypes=None):
        """Browse for a file and set the StringVar to the selected path."""
        if filetypes is None:
            filetypes = [("All Files", "*.*")]
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if path:
            var.set(path)

    def _save_file(self, data: bytes, title: str = "Save File",
                   filetypes=None):
        """Save bytes data to a file."""
        if filetypes is None:
            filetypes = [("All Files", "*.*")]
        path = filedialog.asksaveasfilename(title=title, filetypes=filetypes)
        if path:
            with open(path, "wb") as f:
                f.write(data)
            self._set_status(f"Saved to: {path}")

    def _copy_to_clipboard(self, text_widget: scrolledtext.ScrolledText):
        """Copy output text to system clipboard."""
        text = text_widget.get("1.0", "end-1c")
        if text:
            if copy_to_clipboard(text):
                self._set_status("Copied to clipboard")
            else:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self._set_status("Copied to clipboard")

    def _load_file_content(self, text_widget: scrolledtext.ScrolledText):
        """Load a file's content into a text widget."""
        path = filedialog.askopenfilename(title="Open File")
        if path:
            try:
                with open(path, "rb") as f:
                    data = f.read()
                # Try to display as text, fall back to base64
                try:
                    text_widget.delete("1.0", "end")
                    text_widget.insert("1.0", data.decode("utf-8"))
                except UnicodeDecodeError:
                    text_widget.delete("1.0", "end")
                    text_widget.insert("1.0", to_base64(data))
                self._set_status(f"Loaded: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")

    def _get_input_bytes(self, text_widget: scrolledtext.ScrolledText,
                         input_format: str = "text") -> Optional[bytes]:
        """Get the content of a text widget as bytes.

        Args:
            text_widget: The text widget to read from.
            input_format: "text" (UTF-8), "base64", or "hex".

        Returns:
            Bytes or None if empty.
        """
        text = text_widget.get("1.0", "end-1c").strip()
        if not text:
            return None

        if input_format == "text":
            return text.encode("utf-8")
        elif input_format == "base64":
            return from_base64(text)
        elif input_format == "hex":
            return from_hex(text)
        return text.encode("utf-8")

    def _clear_text(self, *widgets):
        """Clear one or more text widgets."""
        for w in widgets:
            w.delete("1.0", "end")

    # ── Tab 1: Symmetric Encryption ────────────────────────────────────

    def _create_symmetric_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Symmetric")

        # Control area — wraps on narrow windows
        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(fill="x", padx=5, pady=5)

        # Row 0: Algorithm
        ttk.Label(ctrl_frame, text="Algorithm:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self._sym_algo = tk.StringVar(value="SM4-ECB")
        algo_combo = ttk.Combobox(ctrl_frame, textvariable=self._sym_algo,
                                  values=["AES-GCM", "AES-CBC", "SM4-CBC", "SM4-ECB", "ChaCha20"],
                                  state="readonly", width=12)
        algo_combo.grid(row=0, column=1, sticky="w", padx=(0, 15), pady=2)
        self._sym_use_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl_frame, text="Password", variable=self._sym_use_pwd).grid(
            row=0, column=2, sticky="w", padx=(10, 0), pady=2)

        # Row 1: Key File
        ttk.Label(ctrl_frame, text="Key File:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
        self._sym_key_var = tk.StringVar()
        ttk.Entry(ctrl_frame, textvariable=self._sym_key_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
        ttk.Button(ctrl_frame, text="Browse",
                   command=lambda: self._browse_file(self._sym_key_var)).grid(row=1, column=3, padx=2, pady=2)
        ttk.Button(ctrl_frame, text="Generate",
                   command=self._gen_sym_key).grid(row=1, column=4, padx=2, pady=2)

        ctrl_frame.columnconfigure(1, weight=1)

        # Input area
        input_frame, self._sym_input = self._make_input_frame(tab, "Input (Plaintext / Ciphertext)")
        input_frame.pack(fill="both", expand=True, padx=5, pady=(0, 3))

        # Input toolbar
        in_toolbar = ttk.Frame(tab)
        in_toolbar.pack(fill="x", padx=5)
        ttk.Button(in_toolbar, text="Open File",
                   command=lambda: self._load_file_content(self._sym_input)).pack(side="left", padx=2)
        ttk.Button(in_toolbar, text="Clear Input",
                   command=lambda: self._clear_text(self._sym_input)).pack(side="left", padx=2)
        ttk.Label(in_toolbar, text="Input Format:").pack(side="left", padx=(20, 5))
        self._sym_in_fmt = tk.StringVar(value="text")
        for fmt_val, fmt_name in [("text", "Text"), ("base64", "Base64"), ("hex", "Hex")]:
            ttk.Radiobutton(in_toolbar, text=fmt_name, variable=self._sym_in_fmt,
                            value=fmt_val).pack(side="left", padx=2)

        # Action buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="▶ Encrypt",
                   command=self._sym_encrypt).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="▶ Decrypt",
                   command=self._sym_decrypt).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="⇅ Swap",
                   command=self._sym_swap).pack(side="left", padx=3)

        # Line-by-line mode
        self._sym_line_mode = tk.BooleanVar(value=True)
        ttk.Checkbutton(btn_frame, text="Line-by-line",
                        variable=self._sym_line_mode).pack(side="left", padx=(15, 0))
        ttk.Label(btn_frame, text="(每行独立加解密)").pack(side="left")

        ttk.Label(btn_frame, text="Output Format:").pack(side="left", padx=(20, 5))
        self._sym_out_fmt = tk.StringVar(value="hex")
        for fmt_val, fmt_name in [("base64", "Base64"), ("hex", "Hex")]:
            ttk.Radiobutton(btn_frame, text=fmt_name, variable=self._sym_out_fmt,
                            value=fmt_val).pack(side="left", padx=2)

        # Output area
        out_frame, self._sym_output = self._make_input_frame(tab, "Output")
        out_frame.pack(fill="both", expand=True, padx=5, pady=(3, 0))

        out_toolbar = ttk.Frame(tab)
        out_toolbar.pack(fill="x", padx=5)
        ttk.Button(out_toolbar, text="📋 Copy",
                   command=lambda: self._copy_to_clipboard(self._sym_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="💾 Save",
                   command=lambda: self._save_output_text(self._sym_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="Clear Output",
                   command=lambda: self._clear_text(self._sym_output)).pack(side="left", padx=2)

    def _gen_sym_key(self):
        """Generate a symmetric key based on selected algorithm."""
        algo = self._sym_algo.get()
        if algo.startswith("SM4"):
            key = generate_sm4_key()
            self._sym_key_var.set(to_hex(key))
        elif algo == "ChaCha20":
            key = generate_aes_key(256)  # ChaCha20 uses 256-bit key
            self._sym_key_var.set(to_base64(key))
        else:  # AES
            key = generate_aes_key(256)
            self._sym_key_var.set(to_base64(key))
        self._set_status(f"Generated {algo} key")

    def _prompt_password(self, prompt="Enter password:") -> Optional[str]:
        """Show a tkinter password dialog."""
        return simpledialog.askstring("Password", prompt, show="*")

    def _sym_encrypt(self):
        """Perform symmetric encryption (single-block or line-by-line)."""
        text = self._sym_input.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Input Required", "Please enter data to encrypt.")
            return

        algo = self._sym_algo.get()
        use_pwd = self._sym_use_pwd.get()
        line_mode = self._sym_line_mode.get()
        in_fmt = self._sym_in_fmt.get()

        try:
            if use_pwd:
                pwd = self._prompt_password()
                if not pwd:
                    return
                import hashlib
                salt = os.urandom(16)
                key = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 600000, dklen=32)
                pwd_salt = salt
            else:
                if algo.startswith("SM4"):
                    key = self._load_key_bytes_for_algo("SM4")
                else:
                    key = self._load_key_bytes_for_algo("AES")

            if line_mode and in_fmt == "text":
                lines = text.split("\n")
                results = []
                for content in lines:
                    if not content.strip():
                        results.append("")
                        continue
                    if use_pwd:
                        line_salt = os.urandom(16)
                        import hashlib
                        line_key = hashlib.pbkdf2_hmac("sha256", pwd.encode(), line_salt, 600000, dklen=32)
                        ct_bytes = line_salt + self._encrypt_line(algo, content.encode("utf-8"), line_key)
                    else:
                        ct_bytes = self._encrypt_line(algo, content.encode("utf-8"), key)
                    out_fmt_val = self._sym_out_fmt.get()
                    results.append(to_hex(ct_bytes) if out_fmt_val == "hex" else to_base64(ct_bytes))

                output = "\n".join(results)
                self._sym_output.delete("1.0", "end")
                self._sym_output.insert("1.0", output)
                count = sum(1 for r in results if r)
                self._set_status(f"✓ Line-by-line encrypted: {count} lines with {algo}")
            else:
                input_data = self._get_input_bytes(self._sym_input, in_fmt)
                if input_data is None:
                    return
                if use_pwd:
                    ct_bytes = pwd_salt + self._encrypt_line(algo, input_data, key)
                else:
                    ct_bytes = self._encrypt_line(algo, input_data, key)
                out_fmt_val = self._sym_out_fmt.get()
                output = to_hex(ct_bytes) if out_fmt_val == "hex" else to_base64(ct_bytes)
                self._sym_output.delete("1.0", "end")
                self._sym_output.insert("1.0", output)
                self._set_status(
                    f"✓ Encrypted with {algo} ({len(input_data)} → {len(ct_bytes)} bytes)")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def _encrypt_line(self, algo: str, data: bytes, key: bytes) -> bytes:
        """Encrypt a single block of data with the selected algorithm.

        Returns raw packaged bytes (nonce/iv + [tag] + ciphertext).
        """
        if algo == "AES-GCM":
            iv, ct, tag = aes_encrypt_gcm(data, key)
            return iv + tag + ct
        elif algo == "AES-CBC":
            iv, ct = aes_encrypt_cbc(data, key)
            return iv + ct
        elif algo == "ChaCha20":
            nonce, ct, tag = chacha20_encrypt(data, key)
            return nonce + tag + ct
        elif algo == "SM4-CBC":
            iv, ct = sm4_encrypt_cbc(data, key)
            return iv + ct
        elif algo == "SM4-ECB":
            return sm4_encrypt_ecb(data, key)
        else:
            raise ValueError(f"Unknown algorithm: {algo}")

    def _sym_decrypt(self):
        """Perform symmetric decryption (single-block or line-by-line)."""
        text = self._sym_input.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Input Required", "Please enter ciphertext to decrypt.")
            return

        algo = self._sym_algo.get()
        use_pwd = self._sym_use_pwd.get()
        line_mode = self._sym_line_mode.get()
        in_fmt = self._sym_in_fmt.get()

        try:
            if use_pwd:
                pwd = self._prompt_password()
                if not pwd:
                    return
            else:
                if algo.startswith("SM4"):
                    key = self._load_key_bytes_for_algo("SM4")
                else:
                    key = self._load_key_bytes_for_algo("AES")

            if line_mode and in_fmt in ("base64", "hex", "text"):
                if in_fmt == "text":
                    first_line = text.strip().split("\n")[0].strip()
                    if first_line and all(c in "0123456789abcdefABCDEF" for c in first_line) and len(first_line) >= 32:
                        in_fmt = "hex"
                    else:
                        in_fmt = "base64"

                lines = text.split("\n")
                results = []
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        results.append("")
                        continue
                    try:
                        data = from_hex(stripped) if in_fmt == "hex" else from_base64(stripped)
                    except Exception:
                        results.append(f"[INVALID: {stripped[:30]}...]")
                        continue

                    if use_pwd:
                        salt = data[:16]
                        data_bytes = data[16:]
                        import hashlib
                        line_key = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 600000, dklen=32)
                    else:
                        line_key = key
                        data_bytes = data

                    pt = self._decrypt_line(algo, data_bytes, line_key)
                    if pt is None:
                        results.append("[AUTH FAILED]")
                    else:
                        try:
                            results.append(pt.decode("utf-8"))
                        except UnicodeDecodeError:
                            results.append(to_base64(pt))

                output = "\n".join(results)
                self._sym_output.delete("1.0", "end")
                self._sym_output.insert("1.0", output)
                count = sum(1 for r in results if r and not r.startswith("["))
                self._set_status(f"✓ Line-by-line decrypted: {count} lines with {algo}")
            else:
                try:
                    data = from_hex(text) if in_fmt == "hex" else from_base64(text)
                except Exception as e:
                    messagebox.showerror("Decode Error", f"Invalid {in_fmt} input: {e}")
                    return

                if use_pwd:
                    salt = data[:16]
                    data_bytes = data[16:]
                    import hashlib
                    key = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 600000, dklen=32)
                else:
                    data_bytes = data

                pt = self._decrypt_line(algo, data_bytes, key)
                if pt is None:
                    messagebox.showerror("Error", "Authentication failed. Wrong key or corrupted data.")
                    return

                try:
                    text_out = pt.decode("utf-8")
                except UnicodeDecodeError:
                    text_out = to_base64(pt)

                self._sym_output.delete("1.0", "end")
                self._sym_output.insert("1.0", text_out)
                self._set_status(f"✓ Decrypted ({len(data)} → {len(pt)} bytes)")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"{e}\n\nWrong key, corrupted data, or mode mismatch.")

    def _decrypt_line(self, algo: str, data: bytes, key: bytes) -> Optional[bytes]:
        """Decrypt a single block of data. Returns plaintext bytes or None."""
        if algo == "AES-GCM":
            if len(data) < 28:
                raise ValueError("Ciphertext too short for AES-GCM")
            iv, tag, ct = data[:12], data[12:28], data[28:]
            return aes_decrypt_gcm(iv, ct, tag, key)
        elif algo == "AES-CBC":
            iv, ct = data[:16], data[16:]
            return aes_decrypt_cbc(iv, ct, key)
        elif algo == "ChaCha20":
            if len(data) < 28:
                raise ValueError("Ciphertext too short for ChaCha20")
            nonce, tag, ct = data[:12], data[12:28], data[28:]
            return chacha20_decrypt(nonce, ct, tag, key)
        elif algo == "SM4-CBC":
            iv, ct = data[:16], data[16:]
            return sm4_decrypt_cbc(iv, ct, key)
        elif algo == "SM4-ECB":
            return sm4_decrypt_ecb(data, key)
        else:
            raise ValueError(f"Unknown algorithm: {algo}")

    def _load_key_bytes_for_algo(self, algo_type: str) -> bytes:
        """Load a key from file or hex/base64 string."""
        key_str = self._sym_key_var.get().strip()
        if not key_str:
            raise ValueError("Key not provided.")

        if os.path.isfile(key_str):
            with open(key_str, "rb") as f:
                return f.read()

        # Try to decode as hex or base64
        try:
            return from_hex(key_str)
        except Exception:
            pass
        try:
            return from_base64(key_str)
        except Exception:
            pass

        # Treat as raw text → bytes
        return key_str.encode("utf-8")

    def _sym_swap(self):
        """Swap input and output text."""
        in_text = self._sym_input.get("1.0", "end-1c")
        out_text = self._sym_output.get("1.0", "end-1c")
        self._sym_input.delete("1.0", "end")
        self._sym_input.insert("1.0", out_text)
        self._sym_output.delete("1.0", "end")
        self._sym_output.insert("1.0", in_text)
        self._set_status("Swapped input/output")

    def _save_output_text(self, text_widget: scrolledtext.ScrolledText):
        """Save text widget content to a file."""
        text = text_widget.get("1.0", "end-1c")
        if text:
            self._save_file(text.encode("utf-8"), "Save Output", [("Text Files", "*.txt"), ("All Files", "*.*")])

    # ── Tab 2: Asymmetric Encryption ────────────────────────────────────

    def _create_asymmetric_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Asymmetric")

        # Algorithm
        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(ctrl_frame, text="Algorithm:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self._asym_algo = tk.StringVar(value="RSA")
        ttk.Combobox(ctrl_frame, textvariable=self._asym_algo,
                     values=["RSA", "SM2", "Ed25519"], state="readonly",
                     width=10).grid(row=0, column=1, sticky="w", padx=(0, 15))

        # Key rows
        key_frame = ttk.Frame(tab)
        key_frame.pack(fill="x", padx=5)

        self._asym_pub_var = tk.StringVar()
        self._asym_priv_var = tk.StringVar()

        # Row 0: Public key
        ttk.Label(key_frame, text="Public Key:").grid(row=0, column=0, sticky="e", padx=5, pady=2)
        ttk.Entry(key_frame, textvariable=self._asym_pub_var, width=55).grid(
            row=0, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
        ttk.Button(key_frame, text="Browse",
                   command=lambda: self._browse_file(self._asym_pub_var)).grid(row=0, column=3, padx=2)
        ttk.Button(key_frame, text="Generate Key Pair",
                   command=self._gen_asym_key).grid(row=0, column=4, padx=5)

        # Row 1: Private key
        ttk.Label(key_frame, text="Private Key:").grid(row=1, column=0, sticky="e", padx=5, pady=2)
        ttk.Entry(key_frame, textvariable=self._asym_priv_var, width=55).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
        ttk.Button(key_frame, text="Browse",
                   command=lambda: self._browse_file(self._asym_priv_var)).grid(row=1, column=3, padx=2)

        key_frame.columnconfigure(1, weight=1)

        # Input
        in_frame, self._asym_input = self._make_input_frame(tab, "Input", height=8)
        in_frame.pack(fill="both", expand=True, padx=5, pady=3)

        in_toolbar = ttk.Frame(tab)
        in_toolbar.pack(fill="x", padx=5)
        ttk.Button(in_toolbar, text="Open File",
                   command=lambda: self._load_file_content(self._asym_input)).pack(side="left", padx=2)
        ttk.Button(in_toolbar, text="Clear",
                   command=lambda: self._clear_text(self._asym_input)).pack(side="left", padx=2)
        ttk.Label(in_toolbar, text="Input Format:").pack(side="left", padx=(20, 5))
        self._asym_in_fmt = tk.StringVar(value="text")
        for fmt_val, fmt_name in [("text", "Text"), ("base64", "Base64"), ("hex", "Hex")]:
            ttk.Radiobutton(in_toolbar, text=fmt_name, variable=self._asym_in_fmt,
                            value=fmt_val).pack(side="left", padx=2)

        # Action buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="▶ Encrypt",
                   command=self._asym_encrypt).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="▶ Decrypt",
                   command=self._asym_decrypt).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="✍ Sign",
                   command=self._asym_sign).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="✓ Verify",
                   command=self._asym_verify).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="⇅ Swap",
                   command=self._asym_swap).pack(side="left", padx=3)

        ttk.Label(btn_frame, text="Output Format:").pack(side="left", padx=(20, 5))
        self._asym_out_fmt = tk.StringVar(value="base64")
        for fmt_val, fmt_name in [("base64", "Base64"), ("hex", "Hex")]:
            ttk.Radiobutton(btn_frame, text=fmt_name, variable=self._asym_out_fmt,
                            value=fmt_val).pack(side="left", padx=2)

        # Output
        out_frame, self._asym_output = self._make_input_frame(tab, "Output", height=8)
        out_frame.pack(fill="both", expand=True, padx=5, pady=3)

        out_toolbar = ttk.Frame(tab)
        out_toolbar.pack(fill="x", padx=5)
        ttk.Button(out_toolbar, text="📋 Copy",
                   command=lambda: self._copy_to_clipboard(self._asym_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="💾 Save",
                   command=lambda: self._save_output_text(self._asym_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="Clear",
                   command=lambda: self._clear_text(self._asym_output)).pack(side="left", padx=2)

    def _gen_asym_key(self):
        """Generate an asymmetric key pair."""
        algo = self._asym_algo.get()
        if algo == "RSA":
            priv, pub = generate_rsa_keypair(2048)
            priv_pem = serialize_private_key(priv)
            pub_pem = serialize_public_key(pub)

            # Save to files
            priv_path = filedialog.asksaveasfilename(
                title="Save Private Key", defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All Files", "*.*")])
            if priv_path:
                with open(priv_path, "wb") as f:
                    f.write(priv_pem)
                self._asym_priv_var.set(priv_path)

            pub_path = filedialog.asksaveasfilename(
                title="Save Public Key", defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All Files", "*.*")])
            if pub_path:
                with open(pub_path, "wb") as f:
                    f.write(pub_pem)
                self._asym_pub_var.set(pub_path)

            self._set_status(f"Generated RSA-2048 key pair")
        elif algo == "SM2":
            priv_hex, pub_hex = generate_sm2_keypair()
            priv_pem, pub_pem = sm2_keypair_to_pem(priv_hex, pub_hex)

            priv_path = filedialog.asksaveasfilename(
                title="Save SM2 Private Key", defaultextension=".key",
                filetypes=[("Key files", "*.key"), ("All Files", "*.*")])
            if priv_path:
                with open(priv_path, "w") as f:
                    f.write(priv_pem)
                self._asym_priv_var.set(priv_path)

            pub_path = filedialog.asksaveasfilename(
                title="Save SM2 Public Key", defaultextension=".key",
                filetypes=[("Key files", "*.key"), ("All Files", "*.*")])
            if pub_path:
                with open(pub_path, "w") as f:
                    f.write(pub_pem)
                self._asym_pub_var.set(pub_path)

            self._set_status(f"Generated SM2 key pair")
        else:  # Ed25519
            priv, pub = generate_ed25519_keypair()
            priv_pem = serialize_ed25519_private_key(priv)
            pub_pem = serialize_ed25519_public_key(pub)

            priv_path = filedialog.asksaveasfilename(
                title="Save Ed25519 Private Key", defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All Files", "*.*")])
            if priv_path:
                with open(priv_path, "wb") as f:
                    f.write(priv_pem)
                self._asym_priv_var.set(priv_path)

            pub_path = filedialog.asksaveasfilename(
                title="Save Ed25519 Public Key", defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All Files", "*.*")])
            if pub_path:
                with open(pub_path, "wb") as f:
                    f.write(pub_pem)
                self._asym_pub_var.set(pub_path)

            self._set_status(f"Generated Ed25519 key pair")

    def _load_pub_key(self):
        """Load the public key from the configured file."""
        algo = self._asym_algo.get()
        path = self._asym_pub_var.get().strip()
        if not path or not os.path.isfile(path):
            raise ValueError(f"Public key file not found: {path}")
        return path, algo

    def _load_priv_key(self):
        """Load the private key from the configured file."""
        algo = self._asym_algo.get()
        path = self._asym_priv_var.get().strip()
        if not path or not os.path.isfile(path):
            raise ValueError(f"Private key file not found: {path}")
        return path, algo

    def _asym_encrypt(self):
        input_data = self._get_input_bytes(self._asym_input, self._asym_in_fmt.get())
        if input_data is None:
            messagebox.showwarning("Input Required", "Please enter data to encrypt.")
            return
        try:
            path, algo = self._load_pub_key()
            if algo == "RSA":
                with open(path, "rb") as f:
                    pk = load_public_key_from_pem(f.read())
                ct = rsa_encrypt(input_data, pk)
            elif algo == "SM2":
                with open(path, "r") as f:
                    pub_hex = load_sm2_public_key_from_pem(f.read())
                ct = sm2_encrypt(input_data, pub_hex)
            else:  # Ed25519 is signature-only
                messagebox.showwarning("Not Supported",
                                       "Ed25519 is signature-only, cannot encrypt.")
                return

            out = to_hex(ct) if self._asym_out_fmt.get() == "hex" else to_base64(ct)
            self._asym_output.delete("1.0", "end")
            self._asym_output.insert("1.0", out)
            self._set_status(f"✓ Encrypted with {algo} ({len(input_data)} → {len(ct)} bytes)")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def _asym_decrypt(self):
        encoded = self._asym_input.get("1.0", "end-1c").strip()
        if not encoded:
            messagebox.showwarning("Input Required", "Please enter ciphertext to decrypt.")
            return
        try:
            in_fmt = self._asym_in_fmt.get()
            ct = from_hex(encoded) if in_fmt == "hex" else from_base64(encoded)
        except Exception as e:
            messagebox.showerror("Decode Error", str(e))
            return

        try:
            path, algo = self._load_priv_key()
            if algo == "RSA":
                with open(path, "rb") as f:
                    sk = load_private_key_from_pem(f.read())
                pt = rsa_decrypt(ct, sk)
            elif algo == "SM2":
                with open(path, "r") as f:
                    priv_hex = load_sm2_private_key_from_pem(f.read())
                pt = sm2_decrypt(ct, priv_hex)
            else:
                messagebox.showwarning("Not Supported",
                                       "Ed25519 is signature-only, cannot decrypt.")
                return

            try:
                text_out = pt.decode("utf-8")
            except UnicodeDecodeError:
                text_out = to_base64(pt)

            self._asym_output.delete("1.0", "end")
            self._asym_output.insert("1.0", text_out)
            self._set_status(f"✓ Decrypted with {algo} ({len(ct)} → {len(pt)} bytes)")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def _asym_sign(self):
        input_data = self._get_input_bytes(self._asym_input, self._asym_in_fmt.get())
        if input_data is None:
            messagebox.showwarning("Input Required", "Please enter data to sign.")
            return
        try:
            path, algo = self._load_priv_key()
            if algo == "RSA":
                with open(path, "rb") as f:
                    sk = load_private_key_from_pem(f.read())
                sig = rsa_sign(input_data, sk)
                out = to_base64(sig)
            elif algo == "Ed25519":
                with open(path, "rb") as f:
                    sk = load_ed25519_private_key_from_pem(f.read())
                sig = ed25519_sign(input_data, sk)
                out = to_base64(sig)
            else:
                with open(path, "r") as f:
                    priv_hex = load_sm2_private_key_from_pem(f.read())
                pub_hex = ""
                pub_path = self._asym_pub_var.get().strip()
                if pub_path and os.path.isfile(pub_path):
                    with open(pub_path, "r") as f:
                        pub_hex = load_sm2_public_key_from_pem(f.read())
                out = sm2_sign(input_data, priv_hex, pub_hex)

            self._asym_output.delete("1.0", "end")
            self._asym_output.insert("1.0", out)
            self._set_status(f"✓ Signed with {algo}")
        except Exception as e:
            messagebox.showerror("Sign Error", str(e))

    def _asym_verify(self):
        input_data = self._get_input_bytes(self._asym_input, self._asym_in_fmt.get())
        if input_data is None:
            messagebox.showwarning("Input Required", "Please enter the original data to verify.")
            return
        sig_text = self._asym_output.get("1.0", "end-1c").strip()
        if not sig_text:
            messagebox.showwarning("Signature Required",
                                   "Please paste/load the signature in the output area.")
            return
        try:
            path, algo = self._load_pub_key()
            if algo == "RSA":
                with open(path, "rb") as f:
                    pk = load_public_key_from_pem(f.read())
                sig = from_base64(sig_text)
                valid = rsa_verify(input_data, sig, pk)
            elif algo == "Ed25519":
                with open(path, "rb") as f:
                    pk = load_ed25519_public_key_from_pem(f.read())
                sig = from_base64(sig_text)
                valid = ed25519_verify(input_data, sig, pk)
            else:
                with open(path, "r") as f:
                    pub_hex = load_sm2_public_key_from_pem(f.read())
                valid = sm2_verify(input_data, sig_text, pub_hex)

            if valid:
                messagebox.showinfo("Verification", "✓ Signature is VALID.")
                self._set_status("✓ Signature verified — valid")
            else:
                messagebox.showwarning("Verification", "✗ Signature is INVALID.")
                self._set_status("✗ Signature verification FAILED")
        except Exception as e:
            messagebox.showerror("Verification Error", str(e))

    def _asym_swap(self):
        in_text = self._asym_input.get("1.0", "end-1c")
        out_text = self._asym_output.get("1.0", "end-1c")
        self._asym_input.delete("1.0", "end")
        self._asym_input.insert("1.0", out_text)
        self._asym_output.delete("1.0", "end")
        self._asym_output.insert("1.0", in_text)
        self._set_status("Swapped input/output")

    # ── Tab 3: Hash ─────────────────────────────────────────────────────

    def _create_hash_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Hash")

        # Control area — wraps on narrow windows
        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(fill="x", padx=5, pady=5)

        # Row 0: Algorithm + HMAC checkbox
        ttk.Label(ctrl_frame, text="Algorithm:").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=2)
        self._hash_algo = tk.StringVar(value="SHA256")
        algo_combo = ttk.Combobox(ctrl_frame, textvariable=self._hash_algo,
                                  values=["SM3", "SM3+SALT", "MD5", "SHA1", "SHA256", "SHA384", "SHA512"],
                                  state="readonly", width=10)
        algo_combo.grid(row=0, column=1, sticky="w", pady=2)
        algo_combo.bind("<<ComboboxSelected>>", self._on_hash_algo_changed)

        self._hash_hmac = tk.BooleanVar(value=False)
        self._hash_hmac_cb = ttk.Checkbutton(ctrl_frame, text="HMAC Mode",
                                              variable=self._hash_hmac,
                                              command=self._toggle_hmac_key)
        self._hash_hmac_cb.grid(row=0, column=2, sticky="w", padx=(10, 0), pady=2)

        # Row 1: Salt (shown only for SM3+SALT)
        self._hash_salt_label = ttk.Label(ctrl_frame, text="Salt:")
        self._hash_salt = tk.StringVar()
        self._hash_salt_entry = ttk.Entry(ctrl_frame, textvariable=self._hash_salt)
        self._hash_salt_help = ttk.Label(ctrl_frame, text="(prepended: SM3(salt+data))", foreground="gray")

        # Row 1: HMAC Key (shown only for HMAC mode)
        self._hash_hmac_key_label = ttk.Label(ctrl_frame, text="HMAC Key:")
        self._hash_hmac_key = tk.StringVar()
        self._hash_hmac_key_entry = ttk.Entry(ctrl_frame, textvariable=self._hash_hmac_key)
        self._hash_hmac_key_btn = ttk.Button(ctrl_frame, text="Browse",
                                              command=lambda: self._browse_file(self._hash_hmac_key))
        # Hidden by default (HMAC Mode unchecked)

        ctrl_frame.columnconfigure(1, weight=1)

        # Input
        in_frame, self._hash_input = self._make_input_frame(tab, "Input Data", height=10)
        in_frame.pack(fill="both", expand=True, padx=5, pady=3)

        in_toolbar = ttk.Frame(tab)
        in_toolbar.pack(fill="x", padx=5)
        ttk.Button(in_toolbar, text="Open File",
                   command=lambda: self._load_file_content(self._hash_input)).pack(side="left", padx=2)
        ttk.Button(in_toolbar, text="Clear",
                   command=lambda: self._clear_text(self._hash_input)).pack(side="left", padx=2)

        # Compute button
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="▶ Compute",
                   command=self._compute_hash).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="📋 Copy Digest",
                   command=lambda: self._copy_to_clipboard(self._hash_output)).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Clear Digest",
                   command=lambda: self._clear_text(self._hash_output)).pack(side="left", padx=3)

        # Output
        out_frame, self._hash_output = self._make_input_frame(tab, "Digest", height=5)
        out_frame.pack(fill="both", expand=True, padx=5, pady=3)

    def _toggle_hmac_key(self):
        """Show/hide HMAC Key field. Hides salt row if shown."""
        if self._hash_hmac.get():
            self._hash_salt_label.grid_forget()
            self._hash_salt_entry.grid_forget()
            self._hash_salt_help.grid_forget()
            self._hash_hmac_key_label.grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
            self._hash_hmac_key_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
            self._hash_hmac_key_btn.grid(row=1, column=3, padx=2, pady=2)
        else:
            self._hash_hmac_key_label.grid_forget()
            self._hash_hmac_key_entry.grid_forget()
            self._hash_hmac_key_btn.grid_forget()

    def _on_hash_algo_changed(self, event=None):
        """Show/hide salt input. Hides HMAC key row if shown."""
        if self._hash_algo.get() == "SM3+SALT":
            self._hash_hmac_key_label.grid_forget()
            self._hash_hmac_key_entry.grid_forget()
            self._hash_hmac_key_btn.grid_forget()
            self._hash_salt_label.grid(row=1, column=0, sticky="w", padx=(0, 5), pady=2)
            self._hash_salt_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=2, pady=2)
            self._hash_salt_help.grid(row=1, column=3, sticky="w", padx=2, pady=2)
        else:
            self._hash_salt_label.grid_forget()
            self._hash_salt_entry.grid_forget()
            self._hash_salt_help.grid_forget()

    def _compute_hash(self):
        """Compute hash or HMAC of input data."""
        data = self._get_input_bytes(self._hash_input, "text")
        if data is None:
            messagebox.showwarning("Input Required", "Please enter data to hash.")
            return

        algo_raw = self._hash_algo.get()
        algo = algo_raw.lower()
        try:
            if self._hash_hmac.get():
                key_path = self._hash_hmac_key.get().strip()
                if os.path.isfile(key_path):
                    with open(key_path, "rb") as f:
                        key = f.read()
                else:
                    key = key_path.encode("utf-8")
                result = hmac_sign(data, key, algo)
                label = f"HMAC-{algo_raw}"
            elif algo == "sm3+salt":
                salt_str = self._hash_salt.get()
                salt_bytes = salt_str.encode("utf-8")
                result = sm3_salted_hash(data, salt_bytes)
                label = "SM3+SALT"
            else:
                result = hash_data(data, algo)
                label = algo_raw

            self._hash_output.delete("1.0", "end")
            self._hash_output.insert("1.0", result)
            self._set_status(f"✓ {label}: {result[:32]}...")
        except Exception as e:
            messagebox.showerror("Hash Error", str(e))

    # ── Tab 4: Encoding ─────────────────────────────────────────────────

    def _create_encode_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Encode")

        ctrl_frame = ttk.Frame(tab)
        ctrl_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(ctrl_frame, text="Format:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self._enc_op = tk.StringVar(value="Base64")
        ttk.Combobox(ctrl_frame, textvariable=self._enc_op,
                     values=["Base64", "Hex"],
                     state="readonly", width=10).grid(row=0, column=1, sticky="w")

        # Input
        in_frame, self._enc_input = self._make_input_frame(tab, "Input", height=10)
        in_frame.pack(fill="both", expand=True, padx=5, pady=3)

        in_toolbar = ttk.Frame(tab)
        in_toolbar.pack(fill="x", padx=5)
        ttk.Button(in_toolbar, text="Open File",
                   command=lambda: self._load_file_content(self._enc_input)).pack(side="left", padx=2)
        ttk.Button(in_toolbar, text="Clear Input",
                   command=lambda: self._clear_text(self._enc_input)).pack(side="left", padx=2)

        # Encode / Decode buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_frame, text="▶ Encode",
                   command=self._encode_action).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="▶ Decode",
                   command=self._decode_action).pack(side="left", padx=3)

        # Output
        out_frame, self._enc_output = self._make_input_frame(tab, "Output", height=10)
        out_frame.pack(fill="both", expand=True, padx=5, pady=3)

        out_toolbar = ttk.Frame(tab)
        out_toolbar.pack(fill="x", padx=5)
        ttk.Button(out_toolbar, text="📋 Copy",
                   command=lambda: self._copy_to_clipboard(self._enc_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="💾 Save",
                   command=lambda: self._save_output_text(self._enc_output)).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="⇅ Swap",
                   command=self._enc_swap).pack(side="left", padx=2)
        ttk.Button(out_toolbar, text="Clear Both",
                   command=lambda: self._clear_text(self._enc_input, self._enc_output)).pack(side="left", padx=2)

    def _encode_action(self):
        """Encode input in the selected format."""
        text = self._enc_input.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Input Required", "Please enter data to encode.")
            return

        fmt = self._enc_op.get()
        try:
            if fmt.startswith("Base64"):
                result = to_base64(text.encode("utf-8"))
            else:
                result = to_hex(text.encode("utf-8"))
        except Exception as e:
            messagebox.showerror("Encode Error", str(e))
            return

        self._enc_output.delete("1.0", "end")
        self._enc_output.insert("1.0", result)
        self._set_status(f"✓ {fmt}")

    def _decode_action(self):
        """Decode input from the selected format."""
        text = self._enc_input.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Input Required", "Please enter data to decode.")
            return

        fmt = self._enc_op.get()
        try:
            if fmt.startswith("Base64"):
                decoded = from_base64(text)
            else:
                decoded = from_hex(text)
            try:
                result = decoded.decode("utf-8")
            except UnicodeDecodeError:
                result = f"[Binary data — {len(decoded)} bytes]\n" + to_hex(decoded)
        except Exception as e:
            messagebox.showerror("Decode Error", str(e))
            return

        self._enc_output.delete("1.0", "end")
        self._enc_output.insert("1.0", result)
        self._set_status(f"✓ {fmt}")

    def _enc_swap(self):
        """Swap input and output in the encoding tab."""
        in_text = self._enc_input.get("1.0", "end-1c")
        out_text = self._enc_output.get("1.0", "end-1c")
        self._enc_input.delete("1.0", "end")
        self._enc_input.insert("1.0", out_text)
        self._enc_output.delete("1.0", "end")
        self._enc_output.insert("1.0", in_text)
        self._set_status("Swapped input/output")


def _enable_high_dpi():
    """Enable high-DPI awareness on Windows for crisp rendering."""
    if sys.platform == "win32":
        try:
            from ctypes import windll
            # Windows 10 1703+: Per-Monitor DPI v2
            windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)  # System DPI
            except Exception:
                pass


def main():
    """Entry point for the GUI application."""
    _enable_high_dpi()
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
