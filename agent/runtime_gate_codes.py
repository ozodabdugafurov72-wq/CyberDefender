from __future__ import annotations


HEALTH_COMPONENTS = frozenset({
    "RUNTIME",
    "KEY_MANAGER",
    "RUNTIME_PIPELINE",
    "ADMISSION_GATEWAY",
    "SPOOL",
    "PIPELINE",
})
RUNTIME_GATE_CODES = frozenset({
    "BOOTSTRAP_UNCLASSIFIED",
    "CONFIG_REJECTED",
    "KEY_PROVISION_FAIL",
    "KEY_NOT_ACTIVE",
    "KEY_NOT_READY",
    *("HEALTH:" + component for component in HEALTH_COMPONENTS),
})


def normalize_gate_code(value: object) -> str:
    return value if isinstance(value, str) and value in RUNTIME_GATE_CODES else "BOOTSTRAP_UNCLASSIFIED"


def health_gate_code(component: str) -> str:
    return normalize_gate_code("HEALTH:" + str(component).strip().upper())


def failing_component(code: str) -> str | None:
    normalized = normalize_gate_code(code)
    if normalized.startswith("HEALTH:"):
        return normalized.split(":", 1)[1].lower()
    if normalized.startswith("KEY_"):
        return "key_manager"
    return None
