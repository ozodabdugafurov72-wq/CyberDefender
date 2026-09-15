import json
from pathlib import Path


class ConfigError(Exception):
    pass


def load_config():
    config_path = (
        Path(__file__).resolve().parent.parent
        / "config"
        / "config.json"
    )

    if not config_path.exists():
        raise ConfigError(
            f"Config fayli topilmadi: {config_path}"
        )

    try:
        with config_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            config = json.load(file)

    except json.JSONDecodeError as error:
        raise ConfigError(
            f"Config JSON noto'g'ri: {error}"
        )

    # Asosiy parametrlar
    required_keys = {
        "mode",
        "enabled",
        "safety",
        "detection"
    }

    missing_keys = (
        required_keys - config.keys()
    )

    if missing_keys:
        raise ConfigError(
            "Config'da kerakli parametrlar "
            f"yo'q: {missing_keys}"
        )

    # Mode tekshiruvi
    if config["mode"] not in {
        "OBSERVE",
        "CONTAIN",
        "RECOVERY"
    }:
        raise ConfigError(
            f"Noto'g'ri mode: "
            f"{config['mode']}"
        )

    # Safety tekshiruvi
    safety_keys = {
        "fail_safe",
        "allow_system_changes",
        "allow_firewall_changes",
        "allow_registry_changes",
        "allow_service_changes"
    }

    missing_safety = (
        safety_keys
        - config["safety"].keys()
    )

    if missing_safety:
        raise ConfigError(
            "Safety config'da parametrlar "
            f"yo'q: {missing_safety}"
        )

    # Detection parametrlarini tekshirish
    detection_keys = {
        "memory_warning",
        "memory_critical",
        "cpu_warning",
        "cpu_critical",
        "process_warning",
        "process_critical",
        "available_memory_warning",
        "available_memory_critical"
    }

    missing_detection = (
        detection_keys
        - config["detection"].keys()
    )

    if missing_detection:
        raise ConfigError(
            "Detection config'da parametrlar "
            f"yo'q: {missing_detection}"
        )

    return config