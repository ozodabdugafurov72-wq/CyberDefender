from __future__ import annotations

"""CyberDefender deterministic Risk Engine v1.

Security boundary:
- analysis only; never authorizes or executes actions
- Risk != Authorization
- consumes bounded trusted AttackGraph/incident state
- deterministic scoring with explicit caps
- malformed external input is rejected without degrading health
- unexpected internal failures are isolated and observable
"""

from collections import defaultdict
from threading import RLock
from typing import Any
import time


class RiskEngineError(Exception):
    """Risk Engine contract violation."""


class RiskEngine:
    VERSION = "1.0"
    DEFAULT_MAX_INCIDENTS = 128
    DEFAULT_MAX_GRAPH_NODES = 10000
    DEFAULT_MAX_GRAPH_EDGES = 25000
    DEFAULT_MAX_DETECTION_TYPES = 32

    SEVERITY_FLOOR = {
        "INFO": 0, "LOW": 20, "MEDIUM": 40,
        "WARNING": 50, "HIGH": 70, "CRITICAL": 90,
    }
    RISK_LEVELS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (10, "LOW"), (0, "INFO"))
    GRAPH_SIGNAL_WEIGHTS = {
        "THREAT_ACTOR": 10, "CREDENTIAL": 8, "TTP": 6,
        "CLOUD_RESOURCE": 6, "IDENTITY": 4, "DEVICE": 2,
        "PROCESS": 2, "FILE": 2, "IP": 1, "DOMAIN": 1, "SESSION": 1,
    }

    def __init__(self, *, max_incidents: int = DEFAULT_MAX_INCIDENTS,
                 max_graph_nodes: int = DEFAULT_MAX_GRAPH_NODES,
                 max_graph_edges: int = DEFAULT_MAX_GRAPH_EDGES,
                 max_detection_types: int = DEFAULT_MAX_DETECTION_TYPES) -> None:
        self._validate_limit("max_incidents", max_incidents, 1)
        self._validate_limit("max_graph_nodes", max_graph_nodes, 1)
        self._validate_limit("max_graph_edges", max_graph_edges, 1)
        self._validate_limit("max_detection_types", max_detection_types, 1)
        self.name = "RiskEngine"
        self.max_incidents = max_incidents
        self.max_graph_nodes = max_graph_nodes
        self.max_graph_edges = max_graph_edges
        self.max_detection_types = max_detection_types
        self._lock = RLock()
        self.assessments_run = 0
        self.incidents_assessed = 0
        self.incidents_rejected = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_error_type: str | None = None
        self.last_error_at: float | None = None
        self.last_result: dict[str, Any] | None = None

    @staticmethod
    def _validate_limit(name: str, value: Any, minimum: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} integer bo'lishi kerak")
        if value < minimum:
            raise ValueError(f"{name} >= {minimum} bo'lishi kerak")

    @staticmethod
    def _clamp_score(value: Any) -> int:
        if isinstance(value, bool):
            return 0
        if isinstance(value, (int, float)):
            return max(0, min(100, int(round(value))))
        return 0

    @classmethod
    def _severity_floor(cls, severity: Any) -> int:
        return cls.SEVERITY_FLOOR.get(severity.strip().upper(), 0) if isinstance(severity, str) else 0

    @classmethod
    def _risk_level(cls, score: int) -> str:
        for minimum, level in cls.RISK_LEVELS:
            if score >= minimum:
                return level
        return "INFO"

    def _record_failure(self, exc: Exception) -> None:
        with self._lock:
            self.failed += 1
            self.last_error = str(exc)
            self.last_error_type = type(exc).__name__
            self.last_error_at = time.time()

    @staticmethod
    def _graph_snapshot(graph: Any) -> dict[str, Any]:
        if isinstance(graph, dict):
            return graph
        snapshot = getattr(graph, "snapshot", None)
        if not callable(snapshot):
            raise RiskEngineError("AttackGraph snapshot mavjud emas")
        result = snapshot()
        if not isinstance(result, dict):
            raise RiskEngineError("AttackGraph snapshot dict bo'lishi kerak")
        return result

    def _normalize_graph(self, graph: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        snapshot = self._graph_snapshot(graph)
        nodes, edges = snapshot.get("nodes", []), snapshot.get("edges", [])
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise RiskEngineError("AttackGraph nodes/edges list bo'lishi kerak")
        if len(nodes) > self.max_graph_nodes or len(edges) > self.max_graph_edges:
            raise RiskEngineError("AttackGraph resource budget exceeded")
        normalized_nodes: list[dict[str, Any]] = []
        node_ids: set[str] = set()
        for node in nodes:
            if not isinstance(node, dict):
                continue
            node_id, node_type = node.get("node_id"), node.get("node_type")
            if not isinstance(node_id, str) or not node_id.strip() or not isinstance(node_type, str) or not node_type.strip():
                continue
            node_id = node_id.strip()
            if node_id in node_ids:
                continue
            node_ids.add(node_id)
            normalized_nodes.append({"node_id": node_id, "node_type": node_type.strip().upper(),
                                    "attributes": node.get("attributes") if isinstance(node.get("attributes"), dict) else {}})
        normalized_edges: list[dict[str, Any]] = []
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            source, target, edge_type = edge.get("source_id"), edge.get("target_id"), edge.get("edge_type")
            if not all(isinstance(v, str) and v.strip() for v in (source, target, edge_type)):
                continue
            if source not in node_ids or target not in node_ids:
                continue
            normalized_edges.append({"source_id": source, "target_id": target, "edge_type": edge_type.strip().upper()})
        return normalized_nodes, normalized_edges

    def _graph_context(self, incident_id: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> tuple[int, dict[str, int], int]:
        incident_node = f"incident:{incident_id}"
        adjacent_ids: set[str] = set()
        adjacent_edge_types: set[str] = set()
        for edge in edges:
            if edge["source_id"] == incident_node:
                adjacent_ids.add(edge["target_id"])
                adjacent_edge_types.add(edge["edge_type"])
            elif edge["target_id"] == incident_node:
                adjacent_ids.add(edge["source_id"])
                adjacent_edge_types.add(edge["edge_type"])
        by_id = {node["node_id"]: node for node in nodes}
        type_counts: dict[str, int] = defaultdict(int)
        score = 0
        for node_id in sorted(adjacent_ids):
            node = by_id.get(node_id)
            if node is None:
                continue
            node_type = node["node_type"]
            type_counts[node_type] += 1
            score += self.GRAPH_SIGNAL_WEIGHTS.get(node_type, 0)
        score += min(len(adjacent_edge_types), 3)
        return min(score, 25), dict(type_counts), len(adjacent_edge_types)

    def assess_incident(self, incident: dict[str, Any], *, graph_nodes: list[dict[str, Any]], graph_edges: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(incident, dict):
            raise RiskEngineError("incident dict bo'lishi kerak")
        incident_id = incident.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise RiskEngineError("incident_id kerak")
        base = max(self._clamp_score(incident.get("risk_score")), self._severity_floor(incident.get("severity")))
        event_count = incident.get("event_count", 0)
        event_count = event_count if isinstance(event_count, int) and event_count >= 0 else 0
        signal_bonus = min(max(event_count - 1, 0) * 3, 9)
        detections = incident.get("detections", [])
        detections = detections if isinstance(detections, list) else []
        types: set[str] = set()
        for detection in detections[:self.max_detection_types]:
            if isinstance(detection, dict) and isinstance(detection.get("type"), str) and detection["type"].strip():
                types.add(detection["type"].strip())
        diversity_bonus = min(max(len(types) - 1, 0) * 2, 6)
        graph_bonus, graph_types, graph_edge_types = self._graph_context(incident_id.strip(), graph_nodes, graph_edges)
        score = min(100, base + signal_bonus + diversity_bonus + graph_bonus)
        return {
            "incident_id": incident_id.strip(), "risk_score": score, "risk_level": self._risk_level(score),
            "confidence": min(95, 50 + min(len(types), 5) * 5 + min(graph_edge_types, 3) * 5),
            "base_score": base, "signal_bonus": signal_bonus, "diversity_bonus": diversity_bonus,
            "graph_bonus": graph_bonus, "event_count": event_count, "detection_types": sorted(types),
            "graph_context": graph_types, "graph_edge_types": graph_edge_types,
            "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
        }

    def assess(self, graph: Any, incidents: list[dict[str, Any]]) -> dict[str, Any]:
        """Produce a bounded deterministic risk snapshot. No authorization is performed."""
        try:
            nodes, edges = self._normalize_graph(graph)
            if not isinstance(incidents, list):
                raise RiskEngineError("incidents list bo'lishi kerak")
            assessments: list[dict[str, Any]] = []
            rejected = 0
            for incident in incidents[:self.max_incidents]:
                try:
                    assessments.append(self.assess_incident(incident, graph_nodes=nodes, graph_edges=edges))
                except RiskEngineError:
                    rejected += 1
                    with self._lock:
                        self.incidents_rejected += 1
            assessments.sort(key=lambda item: (-item["risk_score"], item["incident_id"]))
            highest = assessments[0]["risk_score"] if assessments else 0
            result = {
                "component": self.name, "version": self.VERSION, "overall_risk_score": highest,
                "overall_risk_level": self._risk_level(highest), "incidents_assessed": len(assessments),
                "incidents_rejected": rejected, "graph_nodes_considered": len(nodes),
                "graph_edges_considered": len(edges), "assessments": assessments,
                "authorization": "NOT_GRANTED", "action": "OBSERVE_ONLY",
            }
            with self._lock:
                self.assessments_run += 1
                self.incidents_assessed += len(assessments)
                self.last_result = result
            return result
        except RiskEngineError as exc:
            with self._lock:
                self.invalid_operations += 1
            return {"component": self.name, "version": self.VERSION, "accepted": False, "reason": "INVALID_INPUT", "error": type(exc).__name__}
        except Exception as exc:
            self._record_failure(exc)
            return {"component": self.name, "version": self.VERSION, "accepted": False, "reason": "ENGINE_ERROR", "error": type(exc).__name__}

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            return {"component": self.name, "version": self.VERSION, "status": "HEALTHY" if self.failed == 0 else "DEGRADED",
                    "assessments_run": self.assessments_run, "incidents_assessed": self.incidents_assessed,
                    "incidents_rejected": self.incidents_rejected, "invalid_operations": self.invalid_operations,
                    "failed": self.failed, "last_error": self.last_error}

    def get_stats(self) -> dict[str, Any]:
        return self.health_check()
