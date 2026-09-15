from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "dashboard_owner" / "static" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "dashboard_owner" / "static" / "owner.js").read_text(encoding="utf-8")
CSS = (ROOT / "dashboard_owner" / "static" / "owner.css").read_text(encoding="utf-8")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS | {message}")


def main() -> None:
    check('id="incidentSearch"' in HTML and 'id="incidentSeverity"' in HTML and 'id="incidentClass"' in HTML, "Incident history search/filter controls are present")
    check('id="opsDrawer"' in HTML and 'id="drawerBody"' in HTML, "Incident/endpoint/demo drill-down drawer is present")
    check('data-action="demo-critical-threat"' in HTML, "Safe critical-threat simulation is reachable from the UI")
    check('data-action="endpoint-investigation"' in HTML, "Endpoint detail investigation is reachable from the UI")
    check('Privileged Action · PROTECTED' in HTML and 'REAL-WORLD EFFECT: BLOCKED' in HTML, "UI keeps privileged real-world actions protected")
    check('/owner/api/incidents' in JS and '/owner/api/endpoint' in JS, "UI uses local read-only incident and endpoint APIs")
    check('/owner/api/demo/critical-threat' in JS, "UI uses the synthetic critical-threat API")
    check('eval(' not in JS and 'new Function' not in JS, "Demo UI contains no dynamic code evaluation")
    check('http://' not in JS and 'https://' not in JS, "Demo UI makes no external network requests")
    check('.ops-drawer' in CSS and '.timeline-row' in CSS, "Demo Operations drawer and evidence timeline styling are packaged")
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
