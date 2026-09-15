from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from tests.support.fake_process_sensor_ipc_v1 import snapshot
from agent.sensors.rust_process_v05_contract import compare_enrichment, validate_v05_snapshot


class ComparisonTests(unittest.TestCase):
    @staticmethod
    def python_from_rust(rust):
        r = rust["processes"][0]
        return {
            "sensor": "ProcessSensor",
            "version": "1.0",
            "timestamp": time.time(),
            "process_count": 1,
            "processes": [{
                "pid": r["pid"],
                "ppid": r["ppid"],
                "name": r["name"],
                "exe": r["exe"],
                "username": r["username"],
                "cmdline": list(r["cmdline"]),
                "create_time": r["create_time"],
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            }],
        }

    def test_aligned(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "ENRICHMENT_ALIGNED")
        self.assertEqual(result["fields"]["exe"]["matches"], 1)
        self.assertEqual(result["fields"]["username"]["matches"], 1)
        self.assertEqual(result["fields"]["cmdline"]["matches"], 1)

    def test_coverage_gap_not_silent(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        raw["processes"][0]["cmdline"] = None
        raw["processes"][0]["enrichment_status"]["cmdline"] = {"status": "ACCESS_DENIED"}
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "ENRICHMENT_ALIGNED_WITH_COVERAGE_GAPS")
        self.assertEqual(result["fields"]["cmdline"]["missing"], 1)

    def test_mismatch_requires_review(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        raw["processes"][0]["exe"] = "C:\\different.exe"
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["fields"]["exe"]["mismatches"], 1)

    def test_raw_name_variant_is_observable_but_not_identity_failure(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        # Simulate Windows API display-name divergence while executable path
        # still proves the same image.
        python_snapshot["processes"][0]["name"] = "DISPLAY_ALIAS.exe"
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "ENRICHMENT_ALIGNED_WITH_NAME_VARIANTS")
        self.assertEqual(result["raw_name_differences"]["count"], 1)
        self.assertEqual(result["fields"]["exe"]["mismatches"], 0)
        self.assertEqual(result["identity_disagreements"]["count"], 0)

    def test_name_variant_plus_executable_mismatch_still_requires_review(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        python_snapshot["processes"][0]["name"] = "DISPLAY_ALIAS.exe"
        raw["processes"][0]["exe"] = "C:\\different.exe"
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["fields"]["exe"]["mismatches"], 1)

    def test_memory_compression_windows_alias_is_narrowly_accepted(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = "MemCompression"
        py["exe"] = ""
        rr["name"] = "Memory Compression"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "ACCESS_DENIED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(
            result["verdict"],
            "ENRICHMENT_ALIGNED_WITH_SYSTEM_NAME_ALIASES",
        )
        self.assertEqual(result["known_system_name_aliases"]["count"], 1)
        self.assertEqual(result["canonical_name_conflicts"]["count"], 0)

    def test_memory_compression_live_windows_pseudo_exe_token_is_accepted(self):
        """Regression for the exact Windows observation from the real v1.3 gate.

        psutil reported both name and exe as ``MemCompression`` while the Rust
        Toolhelp/native path reported ``Memory Compression`` and could not
        collect a real executable image path.
        """
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["pid"] = 3644
        py["ppid"] = 4
        py["name"] = "MemCompression"
        py["exe"] = "MemCompression"
        rr["pid"] = 3644
        rr["ppid"] = 4
        rr["name"] = "Memory Compression"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "QUERY_FAILED"}

        # Keep both sides on the exact same identity fixture.
        python_snapshot["processes"][0]["create_time"] = rr["create_time"]

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(
            result["verdict"],
            "ENRICHMENT_ALIGNED_WITH_SYSTEM_NAME_ALIASES",
        )
        self.assertEqual(result["known_system_name_aliases"]["count"], 1)
        self.assertEqual(
            result["known_system_name_aliases"]["examples"][0]["classification"],
            "WINDOWS_MEMORY_COMPRESSION_PSEUDO_IMAGE_ALIAS",
        )
        self.assertEqual(result["canonical_name_conflicts"]["count"], 0)
        self.assertEqual(result["python_pseudo_image_tokens"]["count"], 1)
        # The pseudo token is telemetry, not an executable path coverage claim.
        self.assertEqual(result["fields"]["exe"]["python_available"], 0)
        self.assertEqual(result["fields"]["exe"]["missing"], 0)

    def test_exact_v13_live_windows_two_row_fixture_is_resolved(self):
        """Broad regression from the user's real Windows v1.3 output."""
        status = lambda exe_status: {
            "exe": {"status": exe_status},
            "username": {"status": "QUERY_FAILED"},
            "sid": {"status": "QUERY_FAILED"},
            "cmdline": {"status": "QUERY_FAILED"},
            "session_id": {"status": "QUERY_FAILED"},
            "integrity_level": {"status": "QUERY_FAILED"},
            "cpu_percent": {"status": "NOT_COLLECTED_V05_CORE"},
            "memory_percent": {"status": "NOT_COLLECTED_V05_CORE"},
        }
        python_snapshot = {
            "processes": [
                {
                    "pid": 188,
                    "ppid": 4,
                    "name": "",
                    "exe": "",
                    "username": None,
                    "cmdline": None,
                    "create_time": 1000.0,
                },
                {
                    "pid": 3644,
                    "ppid": 4,
                    "name": "MemCompression",
                    "exe": "MemCompression",
                    "username": None,
                    "cmdline": None,
                    "create_time": 2000.0,
                },
            ],
        }
        rust_snapshot = {
            "partial": False,
            "skipped": 0,
            "processes": [
                {
                    "pid": 188,
                    "ppid": 4,
                    "name": "Secure System",
                    "exe": None,
                    "username": None,
                    "cmdline": None,
                    "create_time": 1000.0,
                    "enrichment_status": status("QUERY_FAILED"),
                },
                {
                    "pid": 3644,
                    "ppid": 4,
                    "name": "Memory Compression",
                    "exe": None,
                    "username": None,
                    "cmdline": None,
                    "create_time": 2000.0,
                    "enrichment_status": status("QUERY_FAILED"),
                },
            ],
        }
        result = compare_enrichment(python_snapshot, rust_snapshot)
        self.assertEqual(result["identity_disagreements"]["count"], 0)
        self.assertEqual(result["parent_disagreements"]["count"], 0)
        self.assertEqual(result["raw_name_differences"]["count"], 2)
        self.assertEqual(result["known_system_name_aliases"]["count"], 2)
        self.assertEqual(result["canonical_name_conflicts"]["count"], 0)
        self.assertEqual(result["fields"]["exe"]["python_available"], 0)
        self.assertEqual(
            result["verdict"],
            "ENRICHMENT_ALIGNED_WITH_SYSTEM_NAME_ALIASES",
        )

    def test_memory_compression_alias_rejects_unknown_pseudo_exe_token(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = "MemCompression"
        py["exe"] = "NotTheMemoryCompressionToken"
        rr["name"] = "Memory Compression"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "QUERY_FAILED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["known_system_name_aliases"]["count"], 0)
        self.assertEqual(result["canonical_name_conflicts"]["count"], 1)

    def test_secure_system_blank_psutil_name_gap_is_narrowly_accepted(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = ""
        py["exe"] = ""
        rr["name"] = "Secure System"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "ACCESS_DENIED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(
            result["verdict"],
            "ENRICHMENT_ALIGNED_WITH_SYSTEM_NAME_ALIASES",
        )
        self.assertEqual(result["known_system_name_aliases"]["count"], 1)
        self.assertEqual(result["canonical_name_conflicts"]["count"], 0)

    def test_memory_compression_alias_direction_is_not_symmetric(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = "Memory Compression"
        py["exe"] = ""
        rr["name"] = "MemCompression"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "QUERY_FAILED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["known_system_name_aliases"]["count"], 0)

    def test_secure_system_alias_rejects_unknown_python_pseudo_exe_token(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = ""
        py["exe"] = "UnexpectedKernelToken"
        rr["name"] = "Secure System"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "QUERY_FAILED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["known_system_name_aliases"]["count"], 0)

    def test_unknown_exeless_name_divergence_still_requires_review(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = "MysteryA"
        py["exe"] = ""
        rr["name"] = "MysteryB"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "ACCESS_DENIED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["known_system_name_aliases"]["count"], 0)
        self.assertEqual(result["canonical_name_conflicts"]["count"], 1)
        self.assertEqual(
            result["canonical_name_conflicts"]["examples"][0]["reason"],
            "CANONICAL_NAME_CONFLICT",
        )

    def test_memory_alias_does_not_apply_when_image_path_exists(self):
        raw = snapshot(2, "epoch")
        python_snapshot = self.python_from_rust(raw)
        py = python_snapshot["processes"][0]
        rr = raw["processes"][0]

        py["name"] = "MemCompression"
        py["exe"] = r"C:\Windows\System32\malicious.exe"
        rr["name"] = "Memory Compression"
        rr["exe"] = None
        rr["enrichment_status"]["exe"] = {"status": "ACCESS_DENIED"}

        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")
        self.assertEqual(result["known_system_name_aliases"]["count"], 0)
        self.assertGreaterEqual(result["canonical_name_conflicts"]["count"], 1)


class UsernameSidBackedParityTests(unittest.TestCase):
    def _fixture(self):
        raw = snapshot(2, "epoch")
        python_snapshot = ComparisonTests.python_from_rust(raw)
        return raw, python_snapshot

    def test_sid_backed_username_display_variant_is_not_hard_mismatch(self):
        raw, python_snapshot = self._fixture()
        python_snapshot["processes"][0]["username"] = "NT AUTHORITY\\SYSTEM"
        raw["processes"][0]["username"] = "NT AUTHORITY\\LOCALIZED-SYSTEM"
        raw["processes"][0]["sid"] = "S-1-5-18"
        raw["processes"][0]["enrichment_status"]["username"] = {"status": "COLLECTED"}
        raw["processes"][0]["enrichment_status"]["sid"] = {"status": "COLLECTED"}
        rust = validate_v05_snapshot(raw, now=time.time())
        with patch(
            "agent.sensors.rust_process_v05_contract._resolve_windows_username_sid",
            return_value="S-1-5-18",
        ):
            result = compare_enrichment(python_snapshot, rust)
        user = result["fields"]["username"]
        self.assertEqual(user["mismatches"], 0)
        self.assertEqual(user["sid_backed_display_variants"], 1)
        self.assertEqual(user["matches"], 1)
        self.assertEqual(user["exact_matches"], 0)
        self.assertEqual(
            result["verdict"],
            "ENRICHMENT_ALIGNED_WITH_SID_BACKED_USERNAME_VARIANTS",
        )

    def test_username_display_variant_without_collected_sid_remains_hard(self):
        raw, python_snapshot = self._fixture()
        python_snapshot["processes"][0]["username"] = "DOMAIN\\user"
        raw["processes"][0]["username"] = "OTHER\\user"
        raw["processes"][0]["sid"] = None
        raw["processes"][0]["enrichment_status"]["username"] = {"status": "COLLECTED"}
        raw["processes"][0]["enrichment_status"]["sid"] = {"status": "QUERY_FAILED"}
        rust = validate_v05_snapshot(raw, now=time.time())
        result = compare_enrichment(python_snapshot, rust)
        user = result["fields"]["username"]
        self.assertEqual(user["mismatches"], 1)
        self.assertEqual(user["sid_backed_display_variants"], 0)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")

    def test_resolved_python_sid_mismatch_remains_hard(self):
        raw, python_snapshot = self._fixture()
        python_snapshot["processes"][0]["username"] = "DOMAIN\\user"
        raw["processes"][0]["username"] = "OTHER\\user"
        raw["processes"][0]["sid"] = "S-1-5-18"
        raw["processes"][0]["enrichment_status"]["username"] = {"status": "COLLECTED"}
        raw["processes"][0]["enrichment_status"]["sid"] = {"status": "COLLECTED"}
        rust = validate_v05_snapshot(raw, now=time.time())
        with patch(
            "agent.sensors.rust_process_v05_contract._resolve_windows_username_sid",
            return_value="S-1-5-19",
        ):
            result = compare_enrichment(python_snapshot, rust)
        user = result["fields"]["username"]
        self.assertEqual(user["mismatches"], 1)
        self.assertEqual(user["sid_backed_display_variants"], 0)
        self.assertEqual(result["verdict"], "REVIEW_REQUIRED")

    def test_invalid_sid_cannot_suppress_username_mismatch(self):
        raw, python_snapshot = self._fixture()
        python_snapshot["processes"][0]["username"] = "DOMAIN\\user"
        raw["processes"][0]["username"] = "OTHER\\user"
        raw["processes"][0]["sid"] = "NOT-A-SID"
        raw["processes"][0]["enrichment_status"]["username"] = {"status": "COLLECTED"}
        raw["processes"][0]["enrichment_status"]["sid"] = {"status": "COLLECTED"}
        # Wire validation correctly rejects malformed SID values before compare.
        with self.assertRaises(Exception):
            validate_v05_snapshot(raw, now=time.time())


if __name__ == "__main__":
    unittest.main(verbosity=2)
