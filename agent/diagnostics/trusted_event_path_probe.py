"""Synthetic trusted-event path probe.

This module is deliberately not imported by the Windows service.  It provides
a bounded, secret-redacted harness for locating a failure between delivery
binding and durable ACK without reading or mutating live state.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


_SAFE_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def _exception_class(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if _SAFE_CLASS.fullmatch(name) else "UNSAFE_EXCEPTION_CLASS"


def _result(marker: str, stage: str, *, exc: BaseException | None = None) -> dict[str, str | bool]:
    out: dict[str, str | bool] = {
        "marker": marker,
        "stage": stage,
        "ack_attempted": marker == "TRUSTED_EVENT_SUCCESS",
    }
    if exc is not None:
        out["exception_class"] = _exception_class(exc)
    return out


def _invoke(
    stage: str,
    callback: Callable[[Any], Any],
    value: Any,
    *,
    failure_marker: str,
    valid: Callable[[Any], bool],
) -> tuple[Any, dict[str, str | bool] | None]:
    try:
        result = callback(value)
    except Exception as exc:  # diagnostic boundary; never expose args/message
        return None, _result(f"{failure_marker}_EXCEPTION", stage, exc=exc)
    if not valid(result):
        return None, _result(failure_marker, stage)
    return result, None


def trace_trusted_event_path(
    event: Any,
    *,
    bind: Callable[[Any], Any],
    bridge: Callable[[Any], Any],
    correlate: Callable[[Any], Any],
    persist: Callable[[Any], Any],
    ack: Callable[[Any], Any],
) -> dict[str, str | bool]:
    """Trace synthetic delivery through persistence and ACK boundaries.

    Callbacks are supplied by an isolated test only.  The return value contains
    fixed marker vocabulary, one sanitized exception class, and no event data.
    """
    trusted, failure = _invoke(
        "delivery_binding", bind, event,
        failure_marker="TRUSTED_EVENT_DELIVERY_BINDING_FAILED",
        valid=lambda value: value is not None and value is not False,
    )
    if failure is not None:
        return failure

    detection, failure = _invoke(
        "bridge", bridge, trusted,
        failure_marker="TRUSTED_EVENT_BRIDGE_FAILED",
        valid=lambda value: isinstance(value, dict),
    )
    if failure is not None:
        return failure

    _, failure = _invoke(
        "correlation", correlate, detection,
        failure_marker="TRUSTED_EVENT_CORRELATION_FAILED",
        valid=lambda value: value is True,
    )
    if failure is not None:
        return failure

    _, failure = _invoke(
        "persistence", persist, detection,
        failure_marker="TRUSTED_EVENT_PERSISTENCE_FAILED",
        valid=lambda value: value is True,
    )
    if failure is not None:
        return failure

    _, failure = _invoke(
        "ack", ack, trusted,
        failure_marker="TRUSTED_EVENT_ACK_FAILED",
        valid=lambda value: value is True,
    )
    if failure is not None:
        return failure
    return _result("TRUSTED_EVENT_SUCCESS", "ack")
