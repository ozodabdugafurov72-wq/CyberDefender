from collections import Counter
from agent.bus.event_bus import EventBus

def main():
    print("=" * 76)
    print(" CYBERDEFENDER EVENTBUS v2.4 PRIORITY STARVATION / FAIRNESS TEST v1.0")
    print(" Sustained HIGH/CRITICAL traffic vs bounded LOW/MEDIUM service")
    print("=" * 76)

    bus = EventBus(max_size=64, security_reserve=16)
    passed = failed = 0

    def check(ok, msg):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"PASS | {msg}")
        else:
            failed += 1
            print(f"FAIL | {msg}")

    seen = []
    bus.subscribe(seen.append)
    admitted = Counter()

    for sev, count in (("LOW", 8), ("MEDIUM", 8), ("HIGH", 24), ("CRITICAL", 8)):
        for i in range(count):
            if bus.publish({"event_id": f"{sev}-{i}", "severity": sev}):
                admitted[sev] += 1

    check(bus.size() <= 64, "Queue remains physically bounded")
    check(all(admitted[s] > 0 for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")),
          "All priority classes can be admitted")

    low_round = medium_round = None

    for round_no in range(64):
        bus.publish({"event_id": f"STREAM-H-{round_no}", "severity": "HIGH"})
        bus.publish({"event_id": f"STREAM-C-{round_no}", "severity": "CRITICAL"})
        before = len(seen)
        bus.dispatch_once()
        if len(seen) > before:
            sev = str(seen[-1].get("severity", "LOW")).upper()
            if sev == "LOW" and low_round is None:
                low_round = round_no
            if sev == "MEDIUM" and medium_round is None:
                medium_round = round_no
        if low_round is not None and medium_round is not None:
            break

    check(low_round is not None,
          "LOW receives bounded service under sustained higher-priority traffic")
    check(medium_round is not None,
          "MEDIUM receives bounded service under sustained higher-priority traffic")
    check(low_round is not None and low_round <= 32,
          f"LOW service occurs within bounded window (round {low_round})")
    check(medium_round is not None and medium_round <= 32,
          f"MEDIUM service occurs within bounded window (round {medium_round})")

    bus.dispatch_all()
    stats = bus.get_stats()
    check(bus.size() == 0, "Queue drains completely after fairness probe")
    check(stats.get("task_done_errors", 0) == 0,
          "No task_done accounting errors occurred")

    print()
    print("=" * 76)
    print(" EVENTBUS v2.4 PRIORITY STARVATION / FAIRNESS RESULT")
    print("=" * 76)
    print(f"PASS: {passed}")
    print(f"FAIL: {failed}")
    print(f"LOW first service round: {low_round}")
    print(f"MEDIUM first service round: {medium_round}")
    print(f"Final queue: {bus.size()}/64")
    print()

    if failed == 0:
        print("RESULT: PASS — bounded priority fairness contract verified")
        return 0
    print("RESULT: FAIL — fairness/starvation weakness requires architectural review")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
