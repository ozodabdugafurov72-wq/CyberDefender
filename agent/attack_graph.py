from __future__ import annotations

"""CyberDefender bounded Attack Graph v1.

Security properties:
- observe/analysis only; never performs remediation or OS actions
- bounded nodes, edges and path-search work
- deterministic shortest-path traversal
- cycle safe
- duplicate suppression
- strict input validation
- thread-safe mutation/query operations
- fail-closed on malformed graph operations
"""

from collections import OrderedDict, deque
from threading import RLock
from typing import Any
import time


class AttackGraphError(Exception):
    """Base error for Attack Graph contract violations."""


class AttackGraph:
    VERSION = "1.0"

    DEFAULT_MAX_NODES = 10000
    DEFAULT_MAX_EDGES = 25000
    DEFAULT_TTL_SECONDS = 3600
    DEFAULT_MAX_PATH_NODES = 256

    MIN_MAX_NODES = 100
    MIN_MAX_EDGES = 100
    MIN_TTL_SECONDS = 60
    MIN_PATH_NODES = 1

    NODE_TYPES = frozenset(
        {
            "USER",
            "IDENTITY",
            "DEVICE",
            "PROCESS",
            "FILE",
            "IP",
            "DOMAIN",
            "SESSION",
            "CREDENTIAL",
            "CLOUD_RESOURCE",
            "INCIDENT",
            "THREAT_ACTOR",
            "TTP",
        }
    )

    EDGE_TYPES = frozenset(
        {
            "USES",
            "AUTHENTICATES",
            "OWNS",
            "RUNS",
            "SPAWNS",
            "ACCESSES",
            "CONNECTS_TO",
            "RESOLVES_TO",
            "ASSOCIATED_WITH",
            "OBSERVED_IN",
            "INDICATES",
            "TARGETS",
            "USES_TTP",
            "RELATED_TO",
        }
    )

    def __init__(
        self,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_path_nodes: int = DEFAULT_MAX_PATH_NODES,
    ) -> None:
        self._validate_positive_int("max_nodes", max_nodes, self.MIN_MAX_NODES)
        self._validate_positive_int("max_edges", max_edges, self.MIN_MAX_EDGES)
        self._validate_positive_int("ttl_seconds", ttl_seconds, self.MIN_TTL_SECONDS)
        self._validate_positive_int("max_path_nodes", max_path_nodes, self.MIN_PATH_NODES)

        self.name = "AttackGraph"
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.ttl_seconds = ttl_seconds
        self.max_path_nodes = max_path_nodes

        self._nodes: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._adjacency: dict[str, set[tuple[str, str]]] = {}
        self._lock = RLock()

        self.nodes_created = 0
        self.nodes_updated = 0
        self.nodes_rejected = 0
        self.edges_created = 0
        self.edges_updated = 0
        self.edges_rejected = 0
        self.duplicates_suppressed = 0
        self.expired_nodes = 0
        self.expired_edges = 0
        self.path_queries = 0
        self.path_successes = 0
        self.path_budget_exhausted = 0
        self.invalid_operations = 0
        self.failed = 0
        self.last_error: str | None = None
        self.last_error_type: str | None = None
        self.last_error_at: float | None = None

    @staticmethod
    def _validate_positive_int(name: str, value: Any, minimum: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} integer bo'lishi kerak")
        if value < minimum:
            raise ValueError(f"{name} >= {minimum} bo'lishi kerak")

    @staticmethod
    def _validate_id(value: Any, field: str) -> str:
        if not isinstance(value, str):
            raise AttackGraphError(f"{field} string bo'lishi kerak")
        value = value.strip()
        if not value:
            raise AttackGraphError(f"{field} bo'sh bo'lishi mumkin emas")
        if len(value) > 512:
            raise AttackGraphError(f"{field} juda uzun")
        return value

    @staticmethod
    def _validate_type(value: Any, allowed: frozenset[str], field: str) -> str:
        if not isinstance(value, str):
            raise AttackGraphError(f"{field} string bo'lishi kerak")
        value = value.strip().upper()
        if value not in allowed:
            raise AttackGraphError(f"unsupported {field}: {value}")
        return value

    def _record_error(self, exc: Exception) -> None:
        self.failed += 1
        self.last_error = str(exc)
        self.last_error_type = type(exc).__name__
        self.last_error_at = time.time()

    def _expire_locked(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        cutoff = now - self.ttl_seconds

        expired_nodes = [
            node_id
            for node_id, node in self._nodes.items()
            if node["last_seen_monotonic"] < cutoff
        ]
        for node_id in expired_nodes:
            self._remove_node_locked(node_id)
            self.expired_nodes += 1

        expired_edges = [
            key
            for key, edge in self._edges.items()
            if edge["last_seen_monotonic"] < cutoff
        ]
        for key in expired_edges:
            self._remove_edge_locked(key)
            self.expired_edges += 1

    def _remove_edge_locked(self, key: tuple[str, str, str]) -> None:
        edge = self._edges.pop(key, None)
        if edge is None:
            return
        src, dst, edge_type = key
        bucket = self._adjacency.get(src)
        if bucket is not None:
            bucket.discard((dst, edge_type))
            if not bucket:
                self._adjacency.pop(src, None)

    def _remove_node_locked(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)
        incident = [
            key
            for key in self._edges
            if key[0] == node_id or key[1] == node_id
        ]
        for key in incident:
            self._remove_edge_locked(key)

    def add_node(
        self,
        node_id: str,
        node_type: str,
        *,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create or update one graph node. Returns a copy of the node."""
        try:
            node_id = self._validate_id(node_id, "node_id")
            node_type = self._validate_type(node_type, self.NODE_TYPES, "node_type")
            if attributes is not None and not isinstance(attributes, dict):
                raise AttackGraphError("attributes dict bo'lishi kerak")

            now_wall = time.time()
            now_mono = time.monotonic()
            with self._lock:
                self._expire_locked(now_mono)
                existing = self._nodes.get(node_id)
                if existing is None:
                    if len(self._nodes) >= self.max_nodes:
                        self.nodes_rejected += 1
                        return {"accepted": False, "reason": "NODE_LIMIT"}
                    node = {
                        "node_id": node_id,
                        "node_type": node_type,
                        "attributes": dict(attributes or {}),
                        "first_seen": now_wall,
                        "last_seen": now_wall,
                        "last_seen_monotonic": now_mono,
                    }
                    self._nodes[node_id] = node
                    self.nodes_created += 1
                else:
                    if existing["node_type"] != node_type:
                        self.nodes_rejected += 1
                        return {"accepted": False, "reason": "NODE_TYPE_CONFLICT"}
                    if attributes:
                        existing["attributes"].update(attributes)
                    existing["last_seen"] = now_wall
                    existing["last_seen_monotonic"] = now_mono
                    self._nodes.move_to_end(node_id)
                    self.nodes_updated += 1
                return {"accepted": True, "reason": "NODE_ACCEPTED", "node": dict(self._nodes[node_id])}
        except AttackGraphError as exc:
            self.invalid_operations += 1
            self.nodes_rejected += 1
            return {"accepted": False, "reason": "INVALID_NODE", "error": type(exc).__name__}
        except Exception as exc:
            self._record_error(exc)
            return {"accepted": False, "reason": "NODE_ERROR", "error": type(exc).__name__}

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        *,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create or update one directed relationship."""
        try:
            source_id = self._validate_id(source_id, "source_id")
            target_id = self._validate_id(target_id, "target_id")
            edge_type = self._validate_type(edge_type, self.EDGE_TYPES, "edge_type")
            if attributes is not None and not isinstance(attributes, dict):
                raise AttackGraphError("attributes dict bo'lishi kerak")

            with self._lock:
                self._expire_locked()
                if source_id not in self._nodes or target_id not in self._nodes:
                    self.edges_rejected += 1
                    return {"accepted": False, "reason": "UNKNOWN_NODE"}

                now_wall = time.time()
                now_mono = time.monotonic()
                key = (source_id, target_id, edge_type)
                existing = self._edges.get(key)
                if existing is not None:
                    if attributes:
                        existing["attributes"].update(attributes)
                    existing["last_seen"] = now_wall
                    existing["last_seen_monotonic"] = now_mono
                    self.edges_updated += 1
                    self.duplicates_suppressed += 1
                    return {"accepted": True, "reason": "EDGE_DUPLICATE_SUPPRESSED", "edge": dict(existing)}

                if len(self._edges) >= self.max_edges:
                    self.edges_rejected += 1
                    return {"accepted": False, "reason": "EDGE_LIMIT"}

                edge = {
                    "source_id": source_id,
                    "target_id": target_id,
                    "edge_type": edge_type,
                    "attributes": dict(attributes or {}),
                    "first_seen": now_wall,
                    "last_seen": now_wall,
                    "last_seen_monotonic": now_mono,
                }
                self._edges[key] = edge
                self._adjacency.setdefault(source_id, set()).add((target_id, edge_type))
                self.edges_created += 1
                return {"accepted": True, "reason": "EDGE_ACCEPTED", "edge": dict(edge)}
        except AttackGraphError as exc:
            self.invalid_operations += 1
            self.edges_rejected += 1
            return {"accepted": False, "reason": "INVALID_EDGE", "error": type(exc).__name__}
        except Exception as exc:
            self._record_error(exc)
            return {"accepted": False, "reason": "EDGE_ERROR", "error": type(exc).__name__}

    def ingest_process_graph(self, process_graph: Any) -> dict[str, int | bool | str]:
        """Import the public ProcessGraph representation without coupling to its internals."""
        try:
            nodes = getattr(process_graph, "nodes", None)
            edges = getattr(process_graph, "edges", None)
            if not isinstance(nodes, dict) or not isinstance(edges, set):
                return {"accepted": False, "reason": "INVALID_PROCESS_GRAPH"}

            added_nodes = 0
            added_edges = 0
            rejected = 0
            for identity, node in nodes.items():
                if not isinstance(node, dict):
                    rejected += 1
                    continue
                result = self.add_node(
                    f"process:{identity}",
                    "PROCESS",
                    attributes={
                        "pid": node.get("pid"),
                        "ppid": node.get("ppid"),
                        "name": node.get("name"),
                        "exe": node.get("exe"),
                        "username": node.get("username"),
                        "state": node.get("state"),
                    },
                )
                if result.get("accepted"):
                    added_nodes += 1
                else:
                    rejected += 1

            for parent, child in edges:
                parent_id = f"process:{parent}"
                child_id = f"process:{child}"
                if parent_id not in self._nodes or child_id not in self._nodes:
                    rejected += 1
                    continue
                result = self.add_edge(parent_id, child_id, "SPAWNS")
                if result.get("accepted") and result.get("reason") == "EDGE_ACCEPTED":
                    added_edges += 1

            return {
                "accepted": True,
                "reason": "PROCESS_GRAPH_INGESTED",
                "nodes_added": added_nodes,
                "edges_added": added_edges,
                "rejected": rejected,
            }
        except Exception as exc:
            self.invalid_operations += 1
            self._record_error(exc)
            return {"accepted": False, "reason": "PROCESS_GRAPH_ERROR"}

    def ingest_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Add a bounded incident node and optional links to known entities."""
        try:
            if not isinstance(incident, dict):
                raise AttackGraphError("incident dict bo'lishi kerak")
            incident_id = self._validate_id(incident.get("incident_id"), "incident_id")
            node_result = self.add_node(
                f"incident:{incident_id}",
                "INCIDENT",
                attributes={
                    "risk_score": incident.get("risk_score"),
                    "severity": incident.get("severity"),
                    "correlation_key": incident.get("correlation_key"),
                },
            )
            if not node_result.get("accepted"):
                return node_result

            linked = 0
            correlation_key = incident.get("correlation_key")
            if isinstance(correlation_key, str) and correlation_key.strip():
                target = f"process:{correlation_key.strip()}"
                with self._lock:
                    known = target in self._nodes
                if known:
                    edge_result = self.add_edge(
                        f"incident:{incident_id}",
                        target,
                        "OBSERVED_IN",
                    )
                    if edge_result.get("accepted"):
                        linked = 1
            return {
                "accepted": True,
                "reason": "INCIDENT_INGESTED",
                "linked": linked,
            }
        except AttackGraphError as exc:
            self.invalid_operations += 1
            return {"accepted": False, "reason": "INVALID_INCIDENT", "error": type(exc).__name__}
        except Exception as exc:
            self._record_error(exc)
            return {"accepted": False, "reason": "INCIDENT_ERROR", "error": type(exc).__name__}

    def find_path(self, source_id: str, target_id: str) -> dict[str, Any]:
        """Find a deterministic shortest directed path under a hard node-expansion budget."""
        source_id = self._validate_id(source_id, "source_id")
        target_id = self._validate_id(target_id, "target_id")
        with self._lock:
            self.path_queries += 1
            self._expire_locked()
            if source_id not in self._nodes or target_id not in self._nodes:
                return {"found": False, "reason": "UNKNOWN_NODE", "path": [], "expanded": 0}
            if source_id == target_id:
                self.path_successes += 1
                return {"found": True, "reason": "SOURCE_EQUALS_TARGET", "path": [source_id], "expanded": 0}

            queue = deque([source_id])
            parent: dict[str, str | None] = {source_id: None}
            expanded = 0
            found = False

            while queue:
                current = queue.popleft()
                expanded += 1
                if expanded > self.max_path_nodes:
                    self.path_budget_exhausted += 1
                    return {"found": False, "reason": "PATH_BUDGET_EXHAUSTED", "path": [], "expanded": expanded}

                neighbors = sorted(self._adjacency.get(current, set()), key=lambda item: (item[0], item[1]))
                for neighbor, _edge_type in neighbors:
                    if neighbor in parent:
                        continue
                    parent[neighbor] = current
                    if neighbor == target_id:
                        found = True
                        queue.clear()
                        break
                    queue.append(neighbor)
                if found:
                    break

            if not found:
                return {"found": False, "reason": "NO_PATH", "path": [], "expanded": expanded}

            path: list[str] = []
            cursor: str | None = target_id
            while cursor is not None:
                path.append(cursor)
                cursor = parent[cursor]
            path.reverse()
            self.path_successes += 1
            return {"found": True, "reason": "PATH_FOUND", "path": path, "expanded": expanded}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._expire_locked()
            nodes = [dict(node) for node in self._nodes.values()]
            edges = [dict(edge) for edge in self._edges.values()]
            return {
                "component": self.name,
                "version": self.VERSION,
                "nodes": nodes,
                "edges": edges,
            }

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            self._expire_locked()
            status = "HEALTHY" if self.failed == 0 else "DEGRADED"
            return {
                "component": self.name,
                "version": self.VERSION,
                "status": status,
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "path_queries": self.path_queries,
                "path_successes": self.path_successes,
                "path_budget_exhausted": self.path_budget_exhausted,
                "failed": self.failed,
                "invalid_operations": self.invalid_operations,
                "last_error": self.last_error,
            }

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            self._expire_locked()
            return {
                "component": self.name,
                "version": self.VERSION,
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "nodes_created": self.nodes_created,
                "nodes_updated": self.nodes_updated,
                "nodes_rejected": self.nodes_rejected,
                "edges_created": self.edges_created,
                "edges_updated": self.edges_updated,
                "edges_rejected": self.edges_rejected,
                "duplicates_suppressed": self.duplicates_suppressed,
                "expired_nodes": self.expired_nodes,
                "expired_edges": self.expired_edges,
                "path_queries": self.path_queries,
                "path_successes": self.path_successes,
                "path_budget_exhausted": self.path_budget_exhausted,
                "invalid_operations": self.invalid_operations,
                "failed": self.failed,
            }
