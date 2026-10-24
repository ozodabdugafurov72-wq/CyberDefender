import json
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "agent_release" / "agent_only_transactional_deploy.ps1"
PACKAGE = ROOT.parent / "release-artifacts" / "agent-release-10ee" / "CD_AGENT_10ee_integration_A.zip"


def test_wrapper_is_default_read_only_and_agent_only():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "[switch]$Apply" in text
    assert "if($Apply.IsPresent)" in text
    assert "CyberDefenderControlPlane" in text
    assert "CyberDefenderOwnerUI" in text
    assert "-AuthorizeRecoveryProbe" not in text
    assert "Start-Service" not in text
    assert "Stop-Service" not in text
    assert "sc.exe" not in text
    assert "ProgramData" in text and "Snapshot-Digest" in text
    assert "AGENT_ONLY_AUTHORIZED" in text


def test_wrapper_has_exact_candidate_and_baseline_pins():
    text = SCRIPT.read_text(encoding="utf-8")
    for value in (
        "4a6f7b49cd9eb2ef366d66d4aaa84720d4da0fad",
        "564e0bf3d715048aa6dd16f35846f8556bf288d462e0384dc07af838e3fa0533",
        "7368ccfc91f605b3f3aa96de804a950d1797699021a5236b66a607e643878bb2",
        "6917043b433cc4eac884300ee301f230d54d436c4b4f500fcb9864c2b6a49d86",
        "c5030219ba3a996013b8ab0dda48f60743e5c665",
        "6240488d506d1fb7ebac264fa0a1dbc7c05e1a74c65d5a2667fc98603af346bf",
    ):
        assert value in text


def test_isolated_package_has_transactional_inputs():
    with zipfile.ZipFile(PACKAGE) as archive:
        names = set(archive.namelist())
        assert "PINNED_MANIFEST.json" in names
        assert "release/scripts/agent_release/agent_service_bootstrap.py" in names
        assert "release/native/process_sensor_v0_5_1/target/release/cyberdefender-process-sensor.exe" in names
        manifest = json.loads(archive.read("PINNED_MANIFEST.json"))
        assert manifest["commit"] == "4a6f7b49cd9eb2ef366d66d4aaa84720d4da0fad"
        assert manifest["purpose"] == "REVIEW_AND_PREFLIGHT_ONLY_NOT_AN_INSTALLER"
