from __future__ import annotations
import tempfile
from pathlib import Path
from control_plane.distribution_repository import DistributionRepository
from dashboard_owner.fleet_read_model import FleetReadModel

with tempfile.TemporaryDirectory(prefix="cd_dist_repo_") as td:
    db=Path(td)/"distribution.db"
    repo=DistributionRepository(db)
    d1=repo.begin_download(artifact_name="CyberDefenderPackage.zip",version="0.8.5")
    repo.complete_download(d1,bytes_sent=123)
    d2=repo.begin_download(artifact_name="CyberDefenderPackage.zip",version="0.8.5")
    repo.fail_download(d2)
    repo.register_endpoint(endpoint_id="ep-1",hostname="host-a",runtime_version="2.4",health_state="HEALTHY",service_state="RUNNING")
    repo.register_endpoint(endpoint_id="ep-2",hostname="host-b",runtime_version="2.4",health_state="DEGRADED",service_state="RUNNING")
    s=repo.summary(online_after_seconds=90)
    assert s["downloads_total"]==2 and s["downloads_completed"]==1 and s["downloads_failed"]==1
    assert s["installed"]==2 and s["online"]==2 and s["degraded"]==1
    assert s["exact_download_events"] is True and s["people_identity_counted"] is False
    repo.close()
    view=FleetReadModel(db).snapshot()
    assert view["summary"]["downloads_completed"]==1
    assert len(view["endpoints"])==2
print("PASS | exact download event counts are persisted")
print("PASS | install/health/service status is queryable")
print("PASS | Owner fleet model is read-only")
print("RESULT: PASS")
