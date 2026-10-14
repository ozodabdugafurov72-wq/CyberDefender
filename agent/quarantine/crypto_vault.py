from __future__ import annotations

"""Small AES-256-GCM envelope used by quarantine storage.

Keys are local files inherited from the installer's protected vault ACL.  Key
bytes, plaintext, and authentication errors are never included in exceptions.
"""

import os
import secrets
import stat
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultCipherError(RuntimeError):
    pass


class VaultCipher:
    MAGIC = b"CDQV2\x00\x01"
    NONCE_BYTES = 12
    KEY_BYTES = 32

    def __init__(self, root: str | Path, *, key_name: str = ".vault-aes256.key", create: bool = True) -> None:
        self.root = Path(root).expanduser().absolute()
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not self.root.is_dir():
            raise VaultCipherError("VAULT_ROOT_UNAVAILABLE")
        self.key_path = self.root / key_name
        self._key = self._load_or_create_key(create=create)

    def _load_or_create_key(self, *, create: bool) -> bytes:
        try:
            if self.key_path.is_symlink():
                raise VaultCipherError("VAULT_KEY_REPARSE_REJECTED")
            if not self.key_path.exists():
                if not create:
                    raise VaultCipherError("VAULT_KEY_UNAVAILABLE")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_BINARY"):
                    flags |= os.O_BINARY
                try:
                    fd = os.open(str(self.key_path), flags, 0o600)
                except FileExistsError:
                    fd = None
                if fd is not None:
                    try:
                        key = secrets.token_bytes(self.KEY_BYTES)
                        if os.write(fd, key) != len(key):
                            raise VaultCipherError("VAULT_KEY_WRITE_FAILED")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            with self.key_path.open("rb") as handle:
                key = handle.read(self.KEY_BYTES + 1)
            if len(key) != self.KEY_BYTES:
                raise VaultCipherError("VAULT_KEY_INVALID")
            return key
        except VaultCipherError:
            raise
        except Exception as exc:
            raise VaultCipherError("VAULT_KEY_UNAVAILABLE") from exc

    @classmethod
    def is_encrypted(cls, value: bytes) -> bool:
        return value.startswith(cls.MAGIC)

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or not isinstance(aad, bytes) or not aad:
            raise VaultCipherError("VAULT_ENCRYPT_INPUT_INVALID")
        nonce = secrets.token_bytes(self.NONCE_BYTES)
        return self.MAGIC + nonce + AESGCM(self._key).encrypt(nonce, plaintext, aad)

    def decrypt(self, envelope: bytes, *, aad: bytes) -> bytes:
        if not isinstance(envelope, bytes) or not envelope.startswith(self.MAGIC):
            raise VaultCipherError("VAULT_ENVELOPE_INVALID")
        offset = len(self.MAGIC)
        nonce = envelope[offset:offset + self.NONCE_BYTES]
        ciphertext = envelope[offset + self.NONCE_BYTES:]
        if len(nonce) != self.NONCE_BYTES or len(ciphertext) < 16 or not aad:
            raise VaultCipherError("VAULT_ENVELOPE_INVALID")
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise VaultCipherError("VAULT_AUTHENTICATION_FAILED") from exc


class ImmutableFileCapture:
    """Read and delete the exact opened file without a path re-open race."""

    def __init__(self, path: str | Path, *, max_bytes: int) -> None:
        self.path = Path(path)
        self.max_bytes = int(max_bytes)
        self.raw = b""
        self._handle = None
        self._fd: int | None = None
        self._identity: tuple[int, int, int, int] | None = None
        self._deleted = False

    def __enter__(self) -> "ImmutableFileCapture":
        try:
            if os.name == "nt":
                import win32con
                import win32file

                self._handle = win32file.CreateFile(
                    str(self.path),
                    win32con.GENERIC_READ | win32con.DELETE,
                    win32con.FILE_SHARE_READ,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_SEQUENTIAL_SCAN |
                    getattr(win32con, "FILE_FLAG_OPEN_REPARSE_POINT", 0x00200000),
                    None,
                )
                information = win32file.GetFileInformationByHandle(self._handle)
                attributes = int(information[0])
                if attributes & (
                    getattr(win32con, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    | getattr(win32con, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
                ):
                    raise VaultCipherError("SOURCE_REPARSE_OR_NONREGULAR_REJECTED")
                if len(information) > 7 and int(information[7]) != 1:
                    raise VaultCipherError("SOURCE_HARDLINK_REJECTED")
                size = int(win32file.GetFileSize(self._handle))
                if size < 0 or size > self.max_bytes:
                    raise VaultCipherError("SOURCE_SIZE_LIMIT")
                chunks = []
                remaining = size
                while remaining:
                    _, chunk = win32file.ReadFile(self._handle, min(1024 * 1024, remaining))
                    if not chunk:
                        raise VaultCipherError("SOURCE_SHORT_READ")
                    chunks.append(bytes(chunk))
                    remaining -= len(chunk)
                self.raw = b"".join(chunks)
            else:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                self._fd = os.open(str(self.path), flags)
                before = os.fstat(self._fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > self.max_bytes:
                    raise VaultCipherError("SOURCE_NOT_BOUNDED_REGULAR_FILE")
                chunks = []
                remaining = int(before.st_size)
                while remaining:
                    chunk = os.read(self._fd, min(1024 * 1024, remaining))
                    if not chunk:
                        raise VaultCipherError("SOURCE_SHORT_READ")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(self._fd)
                identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                if identity_before != identity_after:
                    raise VaultCipherError("SOURCE_CHANGED_DURING_CAPTURE")
                self._identity = identity_after
                self.raw = b"".join(chunks)
            return self
        except VaultCipherError:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise VaultCipherError("SOURCE_IMMUTABLE_OPEN_FAILED") from exc

    def delete_exact(self) -> None:
        if self._deleted:
            raise VaultCipherError("SOURCE_ALREADY_DELETED")
        try:
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes

                class FILE_DISPOSITION_INFO(ctypes.Structure):
                    _fields_ = [("DeleteFile", wintypes.BOOL)]

                info = FILE_DISPOSITION_INFO(True)
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                set_information = kernel32.SetFileInformationByHandle
                set_information.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
                set_information.restype = wintypes.BOOL
                ok = set_information(wintypes.HANDLE(int(self._handle)), 4, ctypes.byref(info), ctypes.sizeof(info))
                if not ok:
                    raise OSError(ctypes.get_last_error(), "SetFileInformationByHandle")
                self._handle.Close()
                self._handle = None
                if self.path.exists():
                    raise VaultCipherError("SOURCE_DELETE_NOT_COMMITTED")
            else:
                current = os.stat(self.path, follow_symlinks=False)
                identity = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                if identity != self._identity:
                    raise VaultCipherError("SOURCE_PATH_IDENTITY_CHANGED")
                os.unlink(self.path)
            self._deleted = True
        except VaultCipherError:
            raise
        except Exception as exc:
            raise VaultCipherError("SOURCE_EXACT_DELETE_FAILED") from exc

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.Close()
            finally:
                self._handle = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()
