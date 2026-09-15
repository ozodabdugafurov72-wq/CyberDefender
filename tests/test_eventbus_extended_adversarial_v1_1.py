"""
CyberDefender EventBus v2.2 — Extended Adversarial Test v1.1

Scope:
- concurrent publishers
- boundedness under concurrent load
- counter integrity
- malformed/invalid input resilience
- subscriber failure isolation
- shutdown lifecycle
- task_done/join/clear lifecycle
- repeated saturation and recovery
- HIGH/CRITICAL preservation after lower-priority saturation
- priority dispatch / same-priority FIFO
- no unhandled EventBus exceptions

This test does NOT modify production code.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.bus.event_bus import EventBus


PASS = 0
FAIL = 0


def check(label: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS | {label}")
    else:
        FAIL += 1
        print(f"FAIL | {label}")


def event(event_id: str, severity: str = "LOW") -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": "EVENTBUS_EXTENDED_ADVERSARIAL",
        "severity": severity,
        "source": "eventbus_extended_adversarial_v1_0",
    }


def drain(bus: EventBus) -> list[Any]:
    items: list[Any] = []
    while True:
        item = bus.get(timeout=0)
        if item is None:
            break
        items.append(item)
        bus.task_done()
    return items


def main() -> int:
    global PASS, FAIL

    capacity = 40
    reserve = 10

    print("=" * 72)
    print(" CYBERDEFENDER EVENTBUS v2.2 EXTENDED ADVERSARIAL TEST v1.1")
    print(" Concurrency / Shutdown / Malformed Input / Subscriber Failure")
    print(" Starvation / Counters / Recovery / Lifecycle")
    print("=" * 72)

    # ================================================================
    # A. BASELINE
    # ================================================================
    bus = EventBus(max_size=capacity, security_reserve=reserve)

    check("EventBus version is v2.4", bus.get_stats()["version"] == "2.4")
    check("Queue capacity is bounded", bus.get_stats()["queue_capacity"] == capacity)
    check("Security reserve is bounded", bus.get_stats()["security_reserve"] == reserve)
    check("Initial queue is empty", bus.size() == 0)
    check(
        "Initial health is operational",
        bus.health_check()["status"] in {"HEALTHY", "DEGRADED"},
    )

    # ================================================================
    # B. MALFORMED / INVALID INPUT
    #
    # EventBus is not the schema/authentication layer. These cases only
    # verify that malformed inputs cannot crash the process or acquire
    # false CRITICAL/HIGH priority.
    # ================================================================
    malformed = [
        None,
        {},
        object(),
        {"event_id": "bad-1", "severity": None},
        {"event_id": "bad-2", "severity": 999},
        {"event_id": "bad-3", "severity": ""},
        {"event_id": "bad-4", "severity": "UNKNOWN"},
    ]

    malformed_results: list[bool] = []
    malformed_publish_exceptions: list[BaseException] = []

    for item in malformed:
        try:
            # Transport-layer contract: publish() must not raise merely because
            # the object is malformed/untrusted. Schema/auth/replay validation
            # belongs to the higher trusted-event pipeline.
            malformed_results.append(bus.publish(item))
        except BaseException as exc:
            malformed_publish_exceptions.append(exc)

    check(
        "Malformed inputs do not crash EventBus",
        len(malformed_publish_exceptions) == 0,
    )
    check(
        "None is rejected safely",
        malformed_results[0] is False,
    )
    malformed_stats = bus.get_stats()
    check(
        "Malformed input cannot gain CRITICAL/HIGH priority",
        malformed_stats["priority_admissions"]["CRITICAL"] == 0
        and malformed_stats["priority_admissions"]["HIGH"] == 0,
    )
    check("Queue remains bounded after malformed-input probe", bus.size() <= capacity)

    # Remove any admitted LOW-like malformed objects before the next gate.
    bus.clear()
    check("Clear leaves queue empty", bus.is_empty() is True)
    bus.join()
    check("Join completes after clear", True)

    # ================================================================
    # C. CONCURRENT PUBLISHERS
    #
    # 20 threads, mixed priorities. Admission is non-blocking and the
    # queue must never exceed the configured bound.
    # ================================================================
    publisher_threads = 20
    events_per_thread = 100
    attempted = publisher_threads * events_per_thread
    accepted_lock = threading.Lock()
    accepted_ids: list[str] = []
    thread_exceptions: list[BaseException] = []
    concurrent_baseline_published = bus.get_stats()["published"]
    concurrent_baseline_dropped = bus.get_stats()["dropped"]

    start_barrier = threading.Barrier(publisher_threads)

    def publisher(thread_index: int) -> None:
        try:
            start_barrier.wait(timeout=5)
            for i in range(events_per_thread):
                selector = (thread_index + i) % 10
                if selector == 0:
                    severity = "CRITICAL"
                elif selector in {1, 2}:
                    severity = "HIGH"
                elif selector in {3, 4}:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                item = event(f"concurrent-{thread_index}-{i}", severity)
                if bus.publish(item):
                    with accepted_lock:
                        accepted_ids.append(item["event_id"])
        except BaseException as exc:
            with accepted_lock:
                thread_exceptions.append(exc)

    threads = [
        threading.Thread(target=publisher, args=(index,), daemon=True)
        for index in range(publisher_threads)
    ]

    for thread in threads:
        thread.start()

    deadline = time.monotonic() + 10
    for thread in threads:
        remaining = deadline - time.monotonic()
        thread.join(timeout=max(0.0, remaining))

    all_threads_stopped = all(not thread.is_alive() for thread in threads)

    check("All concurrent publisher threads terminate", all_threads_stopped)
    check("No publisher thread raised an exception", len(thread_exceptions) == 0)
    check("Queue never exceeds capacity under concurrency", bus.size() <= capacity)

    concurrent_stats = bus.get_stats()
    concurrent_published_delta = (
        concurrent_stats["published"] - concurrent_baseline_published
    )
    concurrent_dropped_delta = (
        concurrent_stats["dropped"] - concurrent_baseline_dropped
    )
    check(
        "Published counter delta equals admitted concurrent event count",
        concurrent_published_delta == len(accepted_ids),
    )
    check(
        "Published + dropped delta equals all concurrent attempts",
        concurrent_published_delta + concurrent_dropped_delta == attempted,
    )
    check(
        "Queue remains physically bounded",
        concurrent_stats["queue_size"] <= concurrent_stats["queue_capacity"],
    )

    # Drain and verify join/task accounting.
    drained = drain(bus)
    bus.join()
    check("Concurrent queue can be fully drained", len(drained) == len(accepted_ids))
    check("Queue empty after concurrent drain", bus.is_empty() is True)
    check("task_done error counter remains zero", bus.get_stats()["task_done_errors"] == 0)

    # ================================================================
    # D. SUBSCRIBER FAILURE ISOLATION
    # ================================================================
    delivered_good: list[dict[str, Any]] = []

    def broken_subscriber(_: Any) -> None:
        raise RuntimeError("SIMULATED_SUBSCRIBER_FAILURE")

    def healthy_subscriber(item: Any) -> None:
        delivered_good.append(item)

    bus.subscribe(broken_subscriber)
    bus.subscribe(healthy_subscriber)

    for i in range(5):
        check(
            f"Subscriber-failure probe event {i} admitted",
            bus.publish(event(f"subscriber-failure-{i}", "HIGH")) is True,
        )

    dispatched = bus.dispatch_all()
    bus.join()

    failure_stats = bus.get_stats()

    check("Dispatch continues despite broken subscriber", dispatched == 5)
    check(
        "Healthy subscriber still receives events",
        len(delivered_good) == 5,
    )
    check(
        "Subscriber failures are recorded",
        failure_stats["failed_dispatch"] >= 5,
    )
    check(
        "EventBus remains operational after subscriber failure",
        failure_stats["status"] if "status" in failure_stats else bus.health_check()["status"]
        in {"HEALTHY", "DEGRADED"},
    )
    check("Queue empty after subscriber-failure test", bus.is_empty() is True)

    bus.unsubscribe(broken_subscriber)
    bus.unsubscribe(healthy_subscriber)

    # ================================================================
    # E. PRIORITY STARVATION / PRESERVATION
    # ================================================================
    for i in range(capacity - reserve):
        bus.publish(event(f"low-starvation-{i}", "LOW"))

    check(
        "LOW traffic stops at general capacity",
        bus.size() == capacity - reserve,
    )

    # Keep security reserve deliberately occupied.
    for i in range(reserve - 1):
        bus.publish(event(f"high-reserve-{i}", "HIGH"))

    check(
        "Security traffic can occupy protected capacity",
        bus.size() == capacity - 1,
    )

    check(
        "CRITICAL remains admissible with lower-priority saturation",
        bus.publish(event("critical-starvation-test", "CRITICAL")) is True,
    )
    check(
        "Total queue remains exactly bounded",
        bus.size() == capacity,
    )

    priority_received: list[dict[str, Any]] = []
    bus.subscribe(priority_received.append)

    while bus.dispatch_once(timeout=0):
        pass

    bus.join()

    severities = [item["severity"] for item in priority_received]
    check("Priority dispatch does not lose admitted events", len(severities) == capacity)
    check(
        "CRITICAL dispatches before lower priorities",
        severities[0] == "CRITICAL",
    )
    check(
        "HIGH dispatches before LOW",
        all(
            severity in {"CRITICAL", "HIGH"}
            for severity in severities[:reserve]
        ),
    )

    bus.unsubscribe(priority_received.append)

    # ================================================================
    # F. REPEATED SATURATION / RECOVERY
    # ================================================================
    repeated_cycles = 5
    cycle_ok = True

    for cycle in range(repeated_cycles):
        accepted_low = 0
        for i in range(capacity):
            if bus.publish(event(f"cycle-{cycle}-low-{i}", "LOW")):
                accepted_low += 1

        if accepted_low != capacity - reserve:
            cycle_ok = False

        if not bus.publish(event(f"cycle-{cycle}-critical", "CRITICAL")):
            cycle_ok = False

        if not bus.publish(event(f"cycle-{cycle}-high", "HIGH")):
            cycle_ok = False

        if bus.size() > capacity:
            cycle_ok = False

        drain(bus)
        bus.join()

        if not bus.is_empty():
            cycle_ok = False

    check("Repeated saturation/recovery cycles remain bounded", cycle_ok)
    check("Queue empty after repeated saturation", bus.is_empty() is True)
    check("No task_done errors after repeated recovery", bus.get_stats()["task_done_errors"] == 0)

    # ================================================================
    # G. SHUTDOWN LIFECYCLE
    # ================================================================
    pre_shutdown_events = 5
    for i in range(pre_shutdown_events):
        bus.publish(event(f"shutdown-existing-{i}", "HIGH"))

    pre_shutdown_size = bus.size()
    bus.request_shutdown()

    check("Shutdown flag is set", bus.is_shutdown_requested() is True)
    check(
        "Existing queued events survive shutdown request",
        bus.size() == pre_shutdown_size,
    )

    post_shutdown_results = [
        bus.publish(event("shutdown-new-low", "LOW")),
        bus.publish(event("shutdown-new-high", "HIGH")),
        bus.publish(event("shutdown-new-critical", "CRITICAL")),
    ]

    check(
        "New events are rejected after shutdown",
        post_shutdown_results == [False, False, False],
    )
    check(
        "Existing events remain bounded after shutdown",
        bus.size() == pre_shutdown_size,
    )

    drained_after_shutdown = drain(bus)
    bus.join()

    check(
        "Existing shutdown-time queue drains completely",
        len(drained_after_shutdown) == pre_shutdown_size,
    )
    check("Queue empty after shutdown drain", bus.is_empty() is True)
    check(
        "Health explicitly reports shutdown",
        bus.health_check()["status"] == bus.SHUTDOWN,
    )

    # ================================================================
    # H. FINAL CONTRACT
    # ================================================================
    final_stats = bus.get_stats()
    final_health = bus.health_check()

    check("Final queue size is bounded", final_stats["queue_size"] <= capacity)
    check("Final security reserve remains bounded", final_stats["security_reserve"] == reserve)
    check("Final task_done errors are zero", final_stats["task_done_errors"] == 0)
    check("Final health state is explicit", final_health["status"] == bus.SHUTDOWN)
    check(
        "Critical security preservation contract remains explicit",
        final_health["critical_security_preservation"] is True,
    )

    print()
    print("=" * 72)
    print(" EVENTBUS v2.2 EXTENDED ADVERSARIAL RESULT")
    print("=" * 72)
    print(f"PASS: {PASS}")
    print(f"FAIL: {FAIL}")
    print(f"Final queue: {final_health.get('queue_size')}/{final_health.get('queue_capacity')}")
    print(f"Security reserve: {final_health.get('security_reserve')}")
    print(f"Published: {final_stats.get('published')}")
    print(f"Dropped: {final_stats.get('dropped')}")
    print(f"Failed subscriber dispatches: {final_stats.get('failed_dispatch')}")
    print()

    if FAIL == 0:
        print("RESULT: PASS — EventBus v2.2 extended adversarial contract verified")
        return 0

    print("RESULT: FAIL — EventBus v2.2 extended contract violated")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
