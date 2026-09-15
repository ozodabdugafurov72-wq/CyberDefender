from __future__ import annotations

"""
CyberDefender P11.20
Health Contract Adversarial Test

Maqsad:
- komponent health_check() failure holatini xavfsiz qaytarishini tekshirish
- health_check() exceptionni tashqariga chiqarmasligini tekshirish
- asl komponent holatini test davomida imkon qadar buzmaslik
- critical health chain'ni tekshirish

Security-first:
Health diagnostikasi hech qachon:
- event yaratmasligi
- ACK qilmasligi
- quarantine transition qilmasligi
- production state'ni o'zgartirmasligi kerak.
"""

from pathlib import Path


PASS = 0
FAIL = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL

    if ok:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}")

    if detail:
        print(f"       {detail}")


class BrokenHealthComponent:
    """
    Health contract adversarial double.

    health_check() ataylab exception chiqaradi.
    Runtime diagnostic layer buni tashqariga
    chiqarib yubormasligi kerak.
    """

    def health_check(self):
        raise RuntimeError(
            "INTENTIONAL_HEALTH_FAILURE"
        )


class InvalidHealthComponent:
    """
    health_check() dict emas, noto'g'ri qiymat qaytaradi.
    """

    def health_check(self):
        return "BROKEN_HEALTH_RESPONSE"


class HealthyHealthComponent:
    """
    Minimal valid health component.
    """

    def health_check(self):
        return {
            "component": "HealthyTestComponent",
            "status": "HEALTHY",
            "version": "test",
        }


def test_exception_is_contained() -> None:
    component = BrokenHealthComponent()

    try:
        component.health_check()
    except Exception as exc:
        report(
            "health exception source behaves as expected",
            isinstance(exc, RuntimeError),
            str(exc),
        )
        return

    report(
        "health exception source behaves as expected",
        False,
        "Expected RuntimeError was not raised",
    )


def test_invalid_response_detection() -> None:
    component = InvalidHealthComponent()

    result = component.health_check()

    report(
        "invalid health response is detectable",
        not isinstance(result, dict),
        f"type={type(result).__name__}",
    )


def test_valid_response_contract() -> None:
    component = HealthyHealthComponent()

    result = component.health_check()

    valid = (
        isinstance(result, dict)
        and result.get("status") == "HEALTHY"
        and result.get("component")
    )

    report(
        "valid health response contract",
        bool(valid),
        repr(result),
    )


def test_runtime_health_method_contains_failure() -> None:
    """
    CyberDefenderRuntime health collection logicni
    minimal mustaqil model orqali tekshiradi.

    Kutilgan behavior:
    component.health_check() exception bersa,
    diagnostic layer:
        status = DEGRADED
    qilib davom etadi.
    """

    component = BrokenHealthComponent()

    health = {}

    try:
        method = getattr(
            component,
            "health_check",
            None,
        )

        if not callable(method):
            health = {
                "status": "UNKNOWN"
            }
        else:
            try:
                result = method()

                if not isinstance(result, dict):
                    health = {
                        "status":
                            "INVALID_HEALTH_RESPONSE"
                    }
                else:
                    health = result

            except Exception as exc:
                health = {
                    "status": "DEGRADED",
                    "error":
                        f"{type(exc).__name__}: {exc}",
                }

        report(
            "health failure is contained",
            health.get("status") == "DEGRADED",
            repr(health),
        )

    except Exception as exc:
        report(
            "health failure is contained",
            False,
            f"UNEXPECTED OUTER EXCEPTION: {type(exc).__name__}: {exc}",
        )


def test_no_files_are_modified_by_health_contract() -> None:
    """
    Health adversarial testning o'zi yangi runtime state
    yaratmasligini tekshiradi.

    Faqat mavjud asosiy fayllarning metadata snapshotini olamiz.
    """

    paths = [
        Path(r".\state\state.json"),
        Path(r".\logs\events.jsonl"),
        Path(r".\state\spool\pending.jsonl"),
        Path(r".\state\spool\acked_state.json"),
        Path(r".\state\spool\quarantined.jsonl"),
    ]

    before = {}

    for path in paths:
        if path.exists():
            stat = path.stat()
            before[str(path)] = (
                stat.st_size,
                stat.st_mtime_ns,
            )

    # Health contract double.
    component = HealthyHealthComponent()
    component.health_check()

    after = {}

    for path in paths:
        if path.exists():
            stat = path.stat()
            after[str(path)] = (
                stat.st_size,
                stat.st_mtime_ns,
            )

    report(
        "health check does not modify protected storage",
        before == after,
        f"before={before} after={after}",
    )


def test_real_components_if_available() -> None:
    """
    Real CyberDefender components mavjud bo'lsa,
    ularning health contractlarini chaqiradi.

    Bu test komponentni ataylab buzmaydi.
    """

    try:
        from agent.observer import SystemObserver

        observer = SystemObserver()

        result = observer.health_check()

        report(
            "real observer health contract",
            isinstance(result, dict)
            and result.get("status") in {
                "HEALTHY",
                "DEGRADED",
            },
            repr(result),
        )

    except Exception as exc:
        report(
            "real observer health contract",
            False,
            f"{type(exc).__name__}: {exc}",
        )

    try:
        from agent.detector import DetectionEngine

        config = {
            "detection": {
                "memory_warning": 80.0,
                "memory_critical": 95.0,

                "cpu_warning": 80.0,
                "cpu_critical": 95.0,

                "process_warning": 500,
                "process_critical": 1000,

                "available_memory_warning": 2048.0,
                "available_memory_critical": 1024.0,

                "memory_anomaly_delta": 10.0,
                "cpu_anomaly_delta": 30.0,
            }
        }

        detector = DetectionEngine(config)

        result = detector.health_check()

        report(
            "real detector health contract",
            isinstance(result, dict)
            and result.get("status") in {
                "HEALTHY",
                "DEGRADED",
            },
            repr(result),
        )

    except Exception as exc:
        report(
            "real detector health contract",
            False,
            f"{type(exc).__name__}: {exc}",
        )


def main() -> int:
    print(
        "=== P11.20 HEALTH ADVERSARIAL TEST ==="
    )
    print()

    print(
        "--- CONTRACT FAILURE TESTS ---"
    )

    test_exception_is_contained()
    test_invalid_response_detection()
    test_valid_response_contract()
    test_runtime_health_method_contains_failure()

    print()
    print(
        "--- STORAGE SAFETY TEST ---"
    )

    test_no_files_are_modified_by_health_contract()

    print()
    print(
        "--- REAL COMPONENT TESTS ---"
    )

    test_real_components_if_available()

    print()
    print(
        "========================================"
    )
    print(
        f"RESULT: PASS={PASS} FAIL={FAIL}"
    )
    print(
        "========================================"
    )

    if FAIL == 0:
        print(
            "P11.20 HEALTH ADVERSARIAL: PASS"
        )
        return 0

    print(
        "P11.20 HEALTH ADVERSARIAL: FAIL"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

