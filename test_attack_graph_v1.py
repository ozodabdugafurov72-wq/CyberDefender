from __future__ import annotations

import concurrent.futures
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from agent.attack_graph import AttackGraph
from agent.correlation.graph import ProcessGraph


def check(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"[PASS] {label}")


def main() -> None:
    print("CYBERDEFENDER — ATTACK GRAPH v1 FOCUSED + ADVERSARIAL TEST")
    print("=" * 72)

    g = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=20)
    check(g.health_check()["status"] == "HEALTHY", "Fresh graph HEALTHY")

    check(g.add_node("device:host-a", "DEVICE")["accepted"], "Device node accepted")
    check(g.add_node("process:p1", "PROCESS")["accepted"], "Process node accepted")
    check(g.add_node("ip:10.0.0.5", "IP")["accepted"], "IP node accepted")
    check(g.add_edge("device:host-a", "process:p1", "RUNS")["accepted"], "RUNS edge accepted")
    check(g.add_edge("process:p1", "ip:10.0.0.5", "CONNECTS_TO")["accepted"], "CONNECTS_TO edge accepted")

    duplicate = g.add_edge("device:host-a", "process:p1", "RUNS")
    check(duplicate["reason"] == "EDGE_DUPLICATE_SUPPRESSED", "Duplicate edge suppressed")
    check(g.get_stats()["edges"] == 2, "Duplicate did not grow edge count")

    path = g.find_path("device:host-a", "ip:10.0.0.5")
    check(path["found"], "Shortest path found")
    check(path["path"] == ["device:host-a", "process:p1", "ip:10.0.0.5"], "Path is deterministic")

    check(g.add_node("incident:I-1", "INCIDENT")["accepted"], "Incident node accepted")
    check(g.add_edge("incident:I-1", "process:p1", "OBSERVED_IN")["accepted"], "Incident relationship accepted")

    check(not g.add_edge("missing", "process:p1", "RUNS")["accepted"], "Unknown source rejected")
    check(not g.add_node("bad", "NOT_A_NODE")["accepted"], "Unknown node type rejected")
    check(not g.add_node("", "DEVICE")["accepted"], "Empty node id rejected")
    check(g.health_check()["status"] == "HEALTHY", "Malformed input does not degrade graph health")

    small = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=1)
    for node in ["a", "b", "c"]:
        check(small.add_node(node, "DEVICE")["accepted"], f"Budget graph node {node} accepted")
    check(small.add_edge("a", "b", "RELATED_TO")["accepted"], "Budget edge a->b accepted")
    check(small.add_edge("b", "c", "RELATED_TO")["accepted"], "Budget edge b->c accepted")
    budget = small.find_path("a", "c")
    check(budget["reason"] == "PATH_BUDGET_EXHAUSTED", "Path expansion budget enforced")

    bounded = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=20)
    for i in range(100):
        check(bounded.add_node(f"n{i}", "DEVICE")["accepted"], f"Bounded node {i} accepted") if i in (0, 99) else bounded.add_node(f"n{i}", "DEVICE")
    check(bounded.add_node("overflow", "DEVICE")["reason"] == "NODE_LIMIT", "Node limit enforced")
    check(bounded.get_stats()["nodes"] == 100, "Node count remains bounded")

    process_graph = ProcessGraph(ttl_seconds=60, max_nodes=100)
    process_graph.ingest_snapshot({"processes": [
        {"pid": 1, "ppid": 0, "name": "init", "create_time": 1.0},
        {"pid": 2, "ppid": 1, "name": "child", "create_time": 2.0},
    ]})
    imported = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=20)
    result = imported.ingest_process_graph(process_graph)
    check(result["accepted"], "ProcessGraph ingestion accepted")
    check(imported.get_stats()["nodes"] == 2, "ProcessGraph nodes imported")
    check(imported.get_stats()["edges"] == 1, "ProcessGraph edge imported")
    check(imported.find_path("process:pid:1@created:1.000000", "process:pid:2@created:2.000000")["found"], "Imported process lineage query works")

    # Thread-safety: concurrent updates to the same existing node must not corrupt state.
    concurrent_graph = AttackGraph(max_nodes=100, max_edges=100, ttl_seconds=60, max_path_nodes=20)
    concurrent_graph.add_node("device:x", "DEVICE")
    def update_one(i: int) -> bool:
        return concurrent_graph.add_node("device:x", "DEVICE", attributes={"last_writer": i})["accepted"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(update_one, range(100)))
    check(all(results), "Concurrent node updates accepted")
    check(concurrent_graph.get_stats()["nodes"] == 1, "Concurrent updates preserve one node")
    check(concurrent_graph.health_check()["failed"] == 0, "Concurrent updates leave graph failure-free")

    print("\nFINAL STATS")
    print(g.get_stats())
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
