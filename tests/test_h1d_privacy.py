import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import agent.service_diagnostics as diagnostics
from agent.service_crash_store import no_reparse


class PrivacyTests(unittest.TestCase):
    def test_secret_messages_and_exception_names_are_not_emitted(self):
        secret="SYNTHETIC_STORAGE_KEY_FLEET_TOKEN_CMDLINE_AUTHORIZATION"
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            with patch.object(diagnostics,"_log_dir",return_value=directory),patch.object(diagnostics,"protected_path",side_effect=no_reparse):
                diagnostics.write_service_log("CyberDefenderAgent",secret,exc=RuntimeError(secret))
                diagnostics.write_service_log("CyberDefenderAgent","FATAL",exc=type(secret,(Exception,),{})(secret))
                diagnostics.write_service_log(secret,"FATAL",exc=RuntimeError(secret))
                diagnostics.write_service_log("../"+secret,"FATAL")
            text=(directory/"CyberDefenderAgent.jsonl").read_text()
            self.assertNotIn(secret,text)
            rows=[json.loads(line) for line in text.splitlines()]
            self.assertEqual(rows[0]["event"],"UNCLASSIFIED")
            self.assertEqual(rows[1]["exception_category"],"OTHER_EXCEPTION")
            self.assertLessEqual(max(map(len,text.splitlines())),512)

    def test_service_separation_and_bounded_rotation(self):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            with patch.object(diagnostics,"_log_dir",return_value=directory),patch.object(diagnostics,"protected_path",side_effect=no_reparse),patch.object(diagnostics,"_MAX_BYTES",512):
                def emit(service):
                    for _ in range(30): diagnostics.write_service_log(service,"FATAL")
                threads=[threading.Thread(target=emit,args=(service,)) for service in ("CyberDefenderAgent","CyberDefenderOwnerUI")]
                for t in threads:t.start()
                for t in threads:t.join()
            files=list(directory.glob("*.jsonl*"))
            self.assertEqual(len(files),6)
            for path in files:
                self.assertLess(path.stat().st_size,1024)
                for line in path.read_text().splitlines():
                    self.assertIn(json.loads(line)["service"],path.name)

    def test_storage_failure_is_nonfatal(self):
        with patch.object(diagnostics,"_log_dir",side_effect=OSError()):
            diagnostics.write_service_log("CyberDefenderAgent","FATAL",exc=RuntimeError("secret"))


if __name__ == "__main__": unittest.main()
