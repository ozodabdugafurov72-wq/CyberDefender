from __future__ import annotations

import unittest

from scripts.verify_windows_acl import (
    AclVerificationError,
    evaluate_acl,
)


class WindowsAclVerifierTests(unittest.TestCase):
    def test_stock_inherit_only_creator_owner_does_not_grant_root_access(self) -> None:
        result = evaluate_acl("S-1-5-32-544", [
            (0, 0x18, 0x10000000, "S-1-3-0"),
            (0, 0x00, 0x10000000, "S-1-5-18"),
            (0, 0x00, 0x10000000, "S-1-5-32-544"),
            (0, 0x00, 0x00120089, "S-1-5-32-545"),
        ])
        self.assertEqual(result["status"], "PASS")

    def test_creator_owner_write_without_inherit_only_is_rejected(self) -> None:
        with self.assertRaisesRegex(AclVerificationError, "ACL_UNPRIVILEGED_WRITE_OR_CONTROL"):
            evaluate_acl("S-1-5-32-544", [(0, 0x08, 0x10000000, "S-1-3-0")])

    def test_sid_native_acl_accepts_read_only_users_and_privileged_writers(self) -> None:
        result = evaluate_acl("S-1-5-32-544", [
            (0, 0x00120089, "S-1-5-32-545"),
            (0, 0x10000000, "S-1-5-18"),
            (0, 0x10000000, "S-1-5-32-544"),
        ])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["principal_resolution"], "SID_NATIVE")

    def test_users_write_modify_acl_and_owner_rights_fail_closed(self) -> None:
        for mask in (0x2, 0x4, 0x40, 0x40000000, 0x10000000, 0x40000, 0x80000):
            with self.subTest(mask=mask), self.assertRaises(AclVerificationError):
                evaluate_acl("S-1-5-18", [(0, mask, "S-1-5-32-545")])

    def test_unknown_sid_is_not_resolved_and_unknown_allow_ace_is_denied(self) -> None:
        result = evaluate_acl("S-1-5-18", [(0, 0x00120089, "S-1-5-21-1-2-3-999")])
        self.assertEqual(result["status"], "PASS")
        with self.assertRaisesRegex(AclVerificationError, "ACL_UNPRIVILEGED_WRITE_OR_CONTROL"):
            evaluate_acl("S-1-5-18", [(0, 0x40000000, "S-1-5-21-1-2-3-999")])
        with self.assertRaises(AclVerificationError):
            evaluate_acl("S-1-5-18", [(9, 0x1, "S-1-5-21-1-2-3-999")])

    def test_unprivileged_owner_is_rejected(self) -> None:
        with self.assertRaises(AclVerificationError):
            evaluate_acl("S-1-5-32-545", [])


if __name__ == "__main__":
    unittest.main()
