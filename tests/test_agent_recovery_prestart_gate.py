from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

from agent.service_crash_guard import fresh_record
from scripts.agent_release.agent_service_bootstrap import (
    _guard_admission_preview,
    _strict_spool_snapshot,
)


record = fresh_record("CyberDefenderAgent")
record.update(
    state="PROBE",
    generation=14,
    attempts_since_stable=2,
    probes_used=1,
    repair_count=17,
    active_attempt=True,
    clean_stop=False,
)
preview = _guard_admission_preview(record, authorize=True)
assert preview == {
    "state": "PROBE",
    "generation": 15,
    "attempts_since_stable": 3,
    "probes_used": 1,
    "active_attempt": True,
}
assert record["generation"] == 14 and record["active_attempt"] is True

with tempfile.TemporaryDirectory(prefix="cd-prestart-gate-") as raw:
    spool = Path(raw)
    state = {"schema_version": "1", "status": "ACKED", "acked_ids": ["a", "b"]}
    (spool / "acked_state.json").write_text(json.dumps(state), encoding="utf-8")
    (spool / "pending.jsonl").write_text(
        json.dumps({"event_id": "pending-1", "event": {}}) + "\n",
        encoding="utf-8",
    )
    count, size, pending = _strict_spool_snapshot(spool)
    assert count == 2 and size > 0 and pending == {"pending-1"}

installer = (root / "scripts/install_agent_release.ps1").read_text(encoding="utf-8-sig")
plan = installer.index("'--recovery-plan-copy'")
plan_pass = installer.index("PLAN_PASS:")
authorize = installer.index("if($AuthorizeRecoveryProbe) { Authorize-AgentProbe }", plan_pass)
prestart = installer.index("Assert-AgentPreStartGates", authorize)
switch = installer.index("Set-AgentBinary $newBin", prestart)
assert plan < plan_pass < authorize < prestart < switch
print("PASS authenticated probe preview + strict spool schema + PLAN/APPLY gate ordering")
