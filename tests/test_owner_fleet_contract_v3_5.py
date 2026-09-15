from __future__ import annotations
import tempfile
from pathlib import Path
from control_plane.distribution_repository import DistributionRepository
import dashboard_owner.server as server

with tempfile.TemporaryDirectory(prefix="cd_owner_fleet_") as td:
    db=Path(td)/"distribution.db"; repo=DistributionRepository(db)
    d=repo.begin_download(artifact_name="x.zip"); repo.complete_download(d,bytes_sent=9)
    repo.register_endpoint(endpoint_id="ep",hostname="host",health_state="HEALTHY",service_state="RUNNING")
    repo.close()
    server.DISTRIBUTION_DB_FILE=db
    snap=server.fleet_snapshot()
    assert snap["summary"]["downloads_completed"]==1
    assert snap["summary"]["online"]==1
    assert snap["read_only"] is True and snap["authoritative"] is False
    state=server.build_state()
    assert state["schema"]=="cyberdefender.owner-master-control.v3.5"
    assert "fleet" in state and state["application_foundation"]["milestone"]=="P0.8.5"
print("PASS | Owner schema v3.5 exposes real fleet telemetry")
print("PASS | distribution telemetry remains non-authoritative")
print("PASS | P0.8.5 application foundation is explicit")
print("RESULT: PASS")
