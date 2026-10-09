from __future__ import annotations
import tempfile, threading, urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
import control_plane.distribution_server as srv
from dashboard_owner.fleet_read_model import FleetReadModel
from agent.fleet.client import FleetTelemetryClient

with tempfile.TemporaryDirectory(prefix="cd_dist_http_") as td:
    root=Path(td); artifact=root/"CyberDefenderPackage.zip"; artifact.write_bytes(b"cyberdefender-test-artifact"*1024)
    token=root/"fleet_token.txt"; token.write_text("test-token-0123456789-abcdef-0123456789",encoding="ascii")
    db=root/"distribution.db"
    srv.ARTIFACT=artifact; srv.TOKEN_FILE=token; srv.DB=db
    httpd=ThreadingHTTPServer(("127.0.0.1",0),srv.Handler); port=httpd.server_address[1]
    thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/download/cyberdefender?version=0.8.5",timeout=3) as r:
            body=r.read(); download_id=r.headers.get("X-CyberDefender-Download-ID")
        assert body==artifact.read_bytes() and download_id
        endpoint_id_file=root/"endpoint_id.txt"; endpoint_id_file.write_text("ep-http",encoding="ascii")
        client=FleetTelemetryClient(f"http://127.0.0.1:{port}", token, endpoint_id_file)
        assert client.register(runtime_version="2.4",health_state="HEALTHY",service_state="RUNNING")
        assert client.heartbeat(runtime_version="2.4",health_state="HEALTHY",service_state="RUNNING",resource_state="NORMAL")
    finally:
        httpd.shutdown(); httpd.server_close(); thread.join(timeout=2)
    view=FleetReadModel(db).snapshot()
    assert view["summary"]["downloads_completed"]==1
    assert view["summary"]["installed"]==1 and view["summary"]["online"]==1
    assert view["endpoints"][0]["service_state"]=="RUNNING"
print("PASS | real HTTP file transfer increments exact download count")
print("PASS | authenticated endpoint enrollment is recorded")
print("PASS | authenticated heartbeat drives live fleet status")
print("RESULT: PASS")
