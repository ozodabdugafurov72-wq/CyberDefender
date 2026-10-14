from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from agent.quarantine.crypto_vault import ImmutableFileCapture, VaultCipherError


class ImmutableCaptureTests(unittest.TestCase):
    def test_opened_identity_cannot_be_replaced_then_deleted_by_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cd-immutable-") as directory:
            root = Path(directory)
            target = root / "target.bin"
            replacement = root / "replacement.bin"
            target.write_bytes(b"original")
            replacement.write_bytes(b"replacement")
            with ImmutableFileCapture(target, max_bytes=1024) as capture:
                self.assertEqual(capture.raw, b"original")
                replaced = False
                try:
                    os.replace(replacement, target)
                    replaced = True
                except OSError:
                    # Windows denies write/delete sharing while the immutable
                    # handle is held.  That is the desired production path.
                    pass
                if replaced:
                    with self.assertRaises(VaultCipherError):
                        capture.delete_exact()
                    self.assertEqual(target.read_bytes(), b"replacement")
                else:
                    capture.delete_exact()
                    self.assertFalse(target.exists())
                    self.assertEqual(replacement.read_bytes(), b"replacement")


if __name__ == "__main__":
    unittest.main()
