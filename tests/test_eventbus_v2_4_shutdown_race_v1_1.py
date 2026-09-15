"""
CyberDefender EventBus v2.4
Concurrent Shutdown Race Adversarial Test v1.1

This test verifies the hardened lifecycle contract:

    - shutdown transition is serialized with queue admission
    - an already in-flight publish may finish before shutdown returns
    - request_shutdown() must not return while that admission is still in flight
    - after request_shutdown() returns, new publish() calls are rejected
"""

from __future__ import annotations

import threading
import time

from agent.bus.event_bus import EventBus


def main() -> int:
    print("=" * 72)
    print(" CYBERDEFENDER EVENTBUS v2.3 CONCURRENT SHUTDOWN RACE TEST v1.1")
    print(" Lifecycle serialization / admission-vs-shutdown integrity")
    print("=" * 72)

    bus = EventBus(max_size=16, security_reserve=4)

    failures = 0
    passes = 0

    def report(condition: bool, message: str) -> None:
        nonlocal failures, passes
        if condition:
            passes += 1
            print(f"PASS | {message}")
        else:
            failures += 1
            print(f"FAIL | {message}")

    report(bus.VERSION == "2.4", "EventBus version is v2.4")
    report(bus.size() == 0, "Initial queue is empty")
    report(not bus.is_shutdown_requested(), "Shutdown initially not requested")

    put_entered = threading.Event()
    release_put = threading.Event()
    shutdown_entered = threading.Event()
    shutdown_returned = threading.Event()

    original_put = bus._queue.put_nowait

    def blocking_put(event):
        put_entered.set()
        if not release_put.wait(timeout=5.0):
            raise TimeoutError("shutdown-race test hook timed out")
        return original_put(event)

    bus._queue.put_nowait = blocking_put

    publish_result = {"value": None, "exception": None}
    shutdown_result = {"exception": None}

    def publisher() -> None:
        try:
            publish_result["value"] = bus.publish(
                {
                    "event_id": "shutdown-race-001",
                    "severity": "CRITICAL",
                    "type": "ADVERSARIAL_SHUTDOWN_RACE",
                }
            )
        except BaseException as exc:
            publish_result["exception"] = exc

    def shutdown_worker() -> None:
        shutdown_entered.set()
        try:
            bus.request_shutdown()
        except BaseException as exc:
            shutdown_result["exception"] = exc
        finally:
            shutdown_returned.set()

    publisher_thread = threading.Thread(
        target=publisher,
        name="eventbus-shutdown-race-publisher",
    )
    publisher_thread.start()

    report(
        put_entered.wait(timeout=5.0),
        "Publisher reached queue admission point",
    )

    shutdown_thread = threading.Thread(
        target=shutdown_worker,
        name="eventbus-shutdown-race-shutdown",
    )
    shutdown_thread.start()

    report(
        shutdown_entered.wait(timeout=2.0),
        "Shutdown thread entered request_shutdown()",
    )

    # v2.3 contract: shutdown cannot return while the in-flight publish owns
    # the lifecycle admission lock.
    time.sleep(0.10)
    report(
        not shutdown_returned.is_set(),
        "Shutdown does not return while publish admission is in flight",
    )

    release_put.set()

    publisher_thread.join(timeout=5.0)
    shutdown_thread.join(timeout=5.0)

    report(
        not publisher_thread.is_alive(),
        "Publisher terminates after admission release",
    )
    report(
        not shutdown_thread.is_alive(),
        "Shutdown thread terminates after admission release",
    )
    report(
        publish_result["exception"] is None,
        "Publisher raises no unexpected exception",
    )
    report(
        shutdown_result["exception"] is None,
        "Shutdown raises no unexpected exception",
    )
    report(
        publish_result["value"] is True,
        "In-flight publish completes successfully before shutdown returns",
    )
    report(
        shutdown_returned.is_set(),
        "Shutdown returns after in-flight publish completes",
    )
    report(
        bus.is_shutdown_requested(),
        "Shutdown flag is set after request_shutdown() returns",
    )
    report(
        bus.size() == 1,
        "The single in-flight event is admitted exactly once",
    )

    # After shutdown has returned, a new event must never be admitted.
    post_shutdown_results = []
    for index in range(20):
        post_shutdown_results.append(
            bus.publish(
                {
                    "event_id": f"post-shutdown-{index}",
                    "severity": "CRITICAL",
                }
            )
        )

    report(
        not any(post_shutdown_results),
        "No new event is admitted after shutdown returns",
    )
    report(
        bus.size() == 1,
        "Post-shutdown publish attempts do not change queue size",
    )

    # Drain the one event that was legitimately admitted before shutdown
    # completed.
    event = bus.get(timeout=0)
    report(
        isinstance(event, dict)
        and event.get("event_id") == "shutdown-race-001",
        "Only the legitimate in-flight event remains",
    )
    bus.task_done()
    bus.join()

    report(
        bus.size() == 0,
        "Queue drains completely after shutdown",
    )

    health = bus.health_check()
    report(
        health.get("status") == EventBus.SHUTDOWN,
        "Health explicitly reports SHUTDOWN",
    )
    report(
        health.get("shutdown_requested") is True,
        "Health exposes shutdown_requested=True",
    )

    stats = bus.get_stats()
    report(
        stats.get("task_done_errors") == 0,
        "No task_done accounting errors occurred",
    )
    report(
        stats.get("queue_size", -1) <= stats.get("queue_capacity", -1),
        "Final queue remains physically bounded",
    )

    bus._queue.put_nowait = original_put

    print()
    print("=" * 72)
    print(" EVENTBUS v2.3 CONCURRENT SHUTDOWN RACE RESULT")
    print("=" * 72)
    print(f"PASS: {passes}")
    print(f"FAIL: {failures}")
    print(f"Publish result: {publish_result['value']!r}")
    print(f"Queue: {bus.size()}/{stats.get('queue_capacity')}")
    print(f"Shutdown requested: {bus.is_shutdown_requested()}")
    print()

    if failures == 0:
        print("RESULT: PASS — shutdown admission invariant verified")
        return 0

    print("RESULT: FAIL — lifecycle serialization contract is violated")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
