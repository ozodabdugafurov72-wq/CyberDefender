from pathlib import Path
root=Path(__file__).resolve().parent.parent
html=(root/"dashboard_owner"/"static"/"index.html").read_text(encoding="utf-8")
js=(root/"dashboard_owner"/"static"/"owner.js").read_text(encoding="utf-8")
for token in ("Fleet & Distribution","fleetDownloads","fleetInstalled","fleetOnline","fleetOffline","exact completed transfers"):
    assert token in html, token
for token in ("renderFleet","downloads_completed","service_state","runtime_version"):
    assert token in js, token
assert "guessed count of people" in html
print("PASS | Owner UI has Fleet & Distribution section")
print("PASS | exact download events are distinguished from people identity")
print("PASS | endpoint install/health/service/version status is rendered")
print("RESULT: PASS")
