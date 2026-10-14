from __future__ import annotations

import unittest
from pathlib import Path

from scripts.scan_repository_secrets import scan_sensitive_log_sinks


class SecretLogStaticAnalysisTests(unittest.TestCase):
    def test_direct_and_formatted_secret_logging_is_rejected(self) -> None:
        source = """
import logging
fleet_token = 'runtime-value'
logging.info('connected')
logging.error('token=%s', fleet_token)
print(f'remote={fleet_token}')
"""
        findings = scan_sensitive_log_sinks(Path("fixture.py"), source)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("fleet_token" in item for item in findings))

    def test_secret_use_outside_log_sink_is_allowed(self) -> None:
        source = """
fleet_token = load_secret()
headers = {'Authorization': 'Bearer ' + fleet_token}
send(headers)
"""
        self.assertEqual(scan_sensitive_log_sinks(Path("fixture.py"), source), [])


if __name__ == "__main__":
    unittest.main()
