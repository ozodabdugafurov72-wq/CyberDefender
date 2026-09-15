from __future__ import annotations

import time
from collections import OrderedDict
from threading import RLock
from typing import Any


class ProcessGraph:
    """
    CyberDefender Process Graph v1.6

    OBSERVE-only process correlation graph.

    Features:
        - PID + create_time identity
        - Parent / child graph
        - PID reuse detection
        - Process lifecycle tracking
        - Exit detection
        - Edge lifecycle management
        - TTL expiration
        - Node limit / eviction
        - Cycle detection
        - Thread-safe access
        - Monotonic TTL timing
        - Health / error telemetry
        - Anomaly generation

    NEVER:
        - kills processes
        - modifies firewall
        - modifies registry
        - deletes files
        - disconnects network
        - performs remediation
    """

    VERSION = "1.6"

    DEFAULT_TTL_SECONDS = 900
    DEFAULT_MAX_NODES = 5000

    MIN_TTL_SECONDS = 60
    MIN_MAX_NODES = 100

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_nodes: int = DEFAULT_MAX_NODES,
    ):
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
        ):
            raise TypeError(
                "ttl_seconds integer bo'lishi kerak"
            )

        if (
            isinstance(max_nodes, bool)
            or not isinstance(max_nodes, int)
        ):
            raise TypeError(
                "max_nodes integer bo'lishi kerak"
            )

        if ttl_seconds < self.MIN_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds >= "
                f"{self.MIN_TTL_SECONDS} bo'lishi kerak"
            )

        if max_nodes < self.MIN_MAX_NODES:
            raise ValueError(
                f"max_nodes >= "
                f"{self.MIN_MAX_NODES} bo'lishi kerak"
            )

        self.name = "ProcessGraph"

        self.ttl_seconds = ttl_seconds
        self.max_nodes = max_nodes

        # identity -> node
        self.nodes: OrderedDict[
            str,
            dict[str, Any],
        ] = OrderedDict()

        # (parent_identity, child_identity)
        self.edges: set[
            tuple[str, str]
        ] = set()

        # PID -> latest known identity
        self._pid_index: dict[
            int,
            str,
        ] = {}

        self._lock = RLock()

        # -----------------------------------------------------
        # METRICS
        # -----------------------------------------------------

        self.snapshots_processed = 0

        self.nodes_created = 0
        self.nodes_updated = 0
        self.nodes_expired = 0
        self.nodes_evicted = 0

        self.invalid_processes = 0
        self.pid_reuse_detected = 0

        self.processes_seen = 0
        self.processes_exited = 0

        self.edges_created = 0
        self.edges_updated = 0
        self.edges_removed = 0

        self.cycles_detected = 0
        self.anomalies_detected = 0

        self.failed = 0

        self.last_error = None
        self.last_error_type = None
        self.last_error_at = None

        self._last_snapshot_monotonic = None

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(self) -> dict:
        with self._lock:
            return {
                "component": self.name,
                "status": "HEALTHY",
                "version": self.VERSION,
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "failed": self.failed,
            }

    # =========================================================
    # ERROR TELEMETRY
    # =========================================================

    def _record_error(
        self,
        exc: Exception,
    ) -> None:
        self.failed += 1
        self.last_error = str(exc)
        self.last_error_type = type(exc).__name__
        self.last_error_at = time.time()

    # =========================================================
    # PROCESS IDENTITY
    # =========================================================

    @staticmethod
    def _normalize_create_time(
        value: Any,
    ) -> float | None:

        if value is None:
            return None

        try:
            value = float(value)

            if value != value:
                return None

            return value

        except (TypeError, ValueError):
            return None

    @staticmethod
    def _process_identity(
        pid: int,
        create_time: float | None,
    ) -> str:

        if create_time is None:
            return (
                f"pid:{pid}"
                "@created:unknown"
            )

        return (
            f"pid:{pid}"
            f"@created:{create_time:.6f}"
        )

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _normalize_process(
        self,
        process: Any,
    ) -> dict[str, Any] | None:

        if not isinstance(process, dict):
            self.invalid_processes += 1
            return None

        pid = process.get("pid")

        if pid is None:
            self.invalid_processes += 1
            return None

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            self.invalid_processes += 1
            return None

        if pid < 0:
            self.invalid_processes += 1
            return None

        ppid = process.get("ppid")

        if ppid is not None:
            try:
                ppid = int(ppid)

                if ppid < 0:
                    ppid = None

            except (TypeError, ValueError):
                ppid = None

        create_time = (
            self._normalize_create_time(
                process.get("create_time")
            )
        )

        now_wall = time.time()
        now_mono = time.monotonic()

        identity = self._process_identity(
            pid,
            create_time,
        )

        return {
            "identity": identity,
            "pid": pid,
            "ppid": ppid,
            "name": process.get("name"),
            "exe": process.get("exe"),
            "username": process.get("username"),
            "cmdline": process.get("cmdline"),
            "create_time": create_time,
            "cpu_percent": process.get(
                "cpu_percent",
                0.0,
            ),
            "memory_percent": process.get(
                "memory_percent",
                0.0,
            ),
            "first_seen": now_wall,
            "last_seen": now_wall,
            "_last_seen_monotonic": now_mono,
            "state": "RUNNING",
        }

    # =========================================================
    # SNAPSHOT COVERAGE
    # =========================================================

    @staticmethod
    def _snapshot_coverage(
        snapshot: dict[str, Any],
        observed_pids: set[int],
    ) -> dict[str, Any]:
        """
        Normalize lifecycle coverage semantics.

        Missing-process inference is safe only when snapshot coverage
        is understood:

        - complete snapshot: every missing RUNNING identity may exit;
        - valid partial snapshot: only explicitly skipped PIDs are
          protected from absence-based exit;
        - invalid/ambiguous coverage metadata: fail closed and suppress
          all absence-based exits for that snapshot.

        Positive evidence (observed process / PID reuse) is handled
        independently by normal ingestion.
        """

        partial_raw = snapshot.get("partial", False)
        skipped_raw = snapshot.get("skipped", 0)

        if type(partial_raw) is not bool:
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "PARTIAL_FLAG_INVALID",
            }

        if type(skipped_raw) is not int or skipped_raw < 0:
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "SKIPPED_COUNT_INVALID",
            }

        partial = partial_raw
        skipped = skipped_raw

        if not partial:
            if skipped != 0:
                return {
                    "mode": "PARTIAL_FAIL_CLOSED",
                    "valid": False,
                    "skipped_pids": set(),
                    "reason": "COMPLETE_WITH_NONZERO_SKIPPED",
                }

            return {
                "mode": "COMPLETE",
                "valid": True,
                "skipped_pids": set(),
                "reason": "COMPLETE_NEGATIVE_INFERENCE_ALLOWED",
            }

        diagnostics = snapshot.get("skipped_processes")

        if not isinstance(diagnostics, list):
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "SKIP_LIST_INVALID",
            }

        skipped_pids: set[int] = set()

        for item in diagnostics:
            if not isinstance(item, dict):
                return {
                    "mode": "PARTIAL_FAIL_CLOSED",
                    "valid": False,
                    "skipped_pids": set(),
                    "reason": "SKIP_ENTRY_INVALID",
                }

            pid = item.get("pid")
            reason = item.get("reason")

            if type(pid) is not int or pid < 0:
                return {
                    "mode": "PARTIAL_FAIL_CLOSED",
                    "valid": False,
                    "skipped_pids": set(),
                    "reason": "SKIP_PID_INVALID",
                }

            if not isinstance(reason, str) or not reason.strip():
                return {
                    "mode": "PARTIAL_FAIL_CLOSED",
                    "valid": False,
                    "skipped_pids": set(),
                    "reason": "SKIP_REASON_INVALID",
                }

            if pid in skipped_pids:
                return {
                    "mode": "PARTIAL_FAIL_CLOSED",
                    "valid": False,
                    "skipped_pids": set(),
                    "reason": "SKIP_PID_DUPLICATE",
                }

            skipped_pids.add(pid)

        if len(skipped_pids) != skipped:
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "SKIPPED_COUNT_MISMATCH",
            }

        if skipped == 0:
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "PARTIAL_WITHOUT_SKIPS",
            }

        if skipped_pids & observed_pids:
            return {
                "mode": "PARTIAL_FAIL_CLOSED",
                "valid": False,
                "skipped_pids": set(),
                "reason": "SKIPPED_PID_ALSO_OBSERVED",
            }

        return {
            "mode": "PARTIAL_EXPLICIT_COVERAGE",
            "valid": True,
            "skipped_pids": skipped_pids,
            "reason": "PARTIAL_SKIP_SCOPE_APPLIED",
        }

    # =========================================================
    # SNAPSHOT INGEST
    # =========================================================

    def ingest_snapshot(
        self,
        snapshot: Any,
    ) -> dict:

        with self._lock:

            try:
                if not isinstance(snapshot, dict):
                    return {
                        "accepted": False,
                        "reason": "INVALID_SNAPSHOT",
                    }

                processes = snapshot.get(
                    "processes",
                    [],
                )

                if not isinstance(
                    processes,
                    list,
                ):
                    return {
                        "accepted": False,
                        "reason": "INVALID_PROCESSES",
                    }

                now_mono = time.monotonic()

                current_identities: set[str] = set()

                created: list[str] = []
                updated: list[str] = []
                exited: list[str] = []
                pid_reuse: list[dict] = []
                anomalies: list[dict] = []

                valid_count = 0
                observed_pids: set[int] = set()

                # -------------------------------------------------
                # PROCESS INGESTION
                # -------------------------------------------------

                for raw_process in processes:

                    process = self._normalize_process(
                        raw_process
                    )

                    if process is None:
                        continue

                    valid_count += 1
                    self.processes_seen += 1

                    pid = process["pid"]
                    identity = process["identity"]

                    observed_pids.add(pid)

                    current_identities.add(
                        identity
                    )

                    previous_identity = (
                        self._pid_index.get(pid)
                    )

                    # -------------------------------------------------
                    # PID REUSE
                    # -------------------------------------------------

                    if (
                        previous_identity is not None
                        and previous_identity != identity
                    ):
                        self.pid_reuse_detected += 1

                        pid_reuse.append(
                            {
                                "pid": pid,
                                "old_identity":
                                    previous_identity,
                                "new_identity":
                                    identity,
                            }
                        )

                        old_node = self.nodes.get(
                            previous_identity
                        )

                        if old_node is not None:

                            if (
                                old_node.get("state")
                                != "EXITED"
                            ):
                                old_node["state"] = (
                                    "EXITED"
                                )

                                self.processes_exited += 1

                                exited.append(
                                    previous_identity
                                )

                            self._remove_edges_for_identity(
                                previous_identity
                            )

                            self.nodes.pop(
                                previous_identity,
                                None,
                            )

                    self._pid_index[pid] = identity

                    # -------------------------------------------------
                    # CREATE / UPDATE
                    # -------------------------------------------------

                    existing = self.nodes.get(
                        identity
                    )

                    if existing is None:

                        self.nodes[identity] = (
                            process
                        )

                        self.nodes_created += 1

                        created.append(
                            identity
                        )

                    else:

                        first_seen = existing.get(
                            "first_seen",
                            process["first_seen"],
                        )

                        existing.update(
                            process
                        )

                        existing["first_seen"] = (
                            first_seen
                        )

                        existing["state"] = (
                            "RUNNING"
                        )

                        self.nodes.move_to_end(
                            identity
                        )

                        self.nodes_updated += 1

                        updated.append(
                            identity
                        )

                # -------------------------------------------------
                # EXIT DETECTION
                # -------------------------------------------------

                known_running = {
                    identity
                    for identity, node
                    in self.nodes.items()
                    if (
                        node.get("state")
                        == "RUNNING"
                    )
                }

                missing = (
                    known_running
                    - current_identities
                )

                coverage = self._snapshot_coverage(
                    snapshot,
                    observed_pids,
                )

                suppressed_missing: list[str] = []

                if coverage["mode"] == "COMPLETE":
                    exit_candidates = set(missing)

                elif (
                    coverage["mode"]
                    == "PARTIAL_EXPLICIT_COVERAGE"
                ):
                    skipped_pids = coverage[
                        "skipped_pids"
                    ]

                    exit_candidates = set()

                    for identity in missing:
                        node = self.nodes.get(identity)

                        if node is None:
                            continue

                        if node.get("pid") in skipped_pids:
                            suppressed_missing.append(
                                identity
                            )
                        else:
                            exit_candidates.add(
                                identity
                            )

                else:
                    # Invalid / ambiguous coverage metadata must not
                    # create lifecycle exits from absence alone.
                    exit_candidates = set()
                    suppressed_missing = list(missing)

                for identity in exit_candidates:

                    node = self.nodes.get(
                        identity
                    )

                    if node is None:
                        continue

                    node["state"] = "EXITED"

                    self.processes_exited += 1

                    exited.append(identity)

                    # An exited process must not remain
                    # connected to the active graph.
                    self._remove_edges_for_identity(
                        identity
                    )

                # -------------------------------------------------
                # EDGE RECONCILIATION
                # -------------------------------------------------

                for identity in current_identities:

                    node = self.nodes.get(
                        identity
                    )

                    if node is None:
                        continue

                    if node.get("state") != "RUNNING":
                        continue

                    # IMPORTANT:
                    # Remove all previous incoming edges.
                    #
                    # This fixes:
                    # A -> B
                    # then
                    # C -> B
                    #
                    # Old A -> B must not remain.

                    old_incoming = {
                        edge
                        for edge in self.edges
                        if edge[1] == identity
                    }

                    if old_incoming:
                        self.edges.difference_update(
                            old_incoming
                        )

                        self.edges_removed += len(
                            old_incoming
                        )

                    ppid = node.get("ppid")

                    if ppid is None:
                        continue

                    parent_identity = (
                        self._pid_index.get(ppid)
                    )

                    if parent_identity is None:
                        continue

                    parent_node = self.nodes.get(
                        parent_identity
                    )

                    if parent_node is None:
                        continue

                    if (
                        parent_node.get("state")
                        != "RUNNING"
                    ):
                        continue

                    if parent_identity == identity:

                        self.cycles_detected += 1
                        self.anomalies_detected += 1

                        anomalies.append(
                            {
                                "type":
                                    "SELF_PARENT",
                                "identity":
                                    identity,
                            }
                        )

                        continue

                    edge = (
                        parent_identity,
                        identity,
                    )

                    if edge in self.edges:
                        self.edges_updated += 1

                    else:
                        self.edges.add(edge)
                        self.edges_created += 1

                # -------------------------------------------------
                # CYCLE DETECTION
                # -------------------------------------------------

                cycles = self._detect_cycles()

                if cycles:

                    self.cycles_detected += len(
                        cycles
                    )

                    self.anomalies_detected += len(
                        cycles
                    )

                    for cycle in cycles:
                        anomalies.append(
                            {
                                "type":
                                    "PROCESS_GRAPH_CYCLE",
                                "cycle":
                                    cycle,
                            }
                        )

                # -------------------------------------------------
                # TTL
                # -------------------------------------------------

                self._expire_old_nodes(
                    now_mono
                )

                # -------------------------------------------------
                # NODE LIMIT
                # -------------------------------------------------

                evicted = (
                    self._enforce_node_limit()
                )

                # -------------------------------------------------
                # SNAPSHOT METADATA
                # -------------------------------------------------

                self.snapshots_processed += 1

                self._last_snapshot_monotonic = (
                    now_mono
                )

                return {
                    "accepted": True,
                    "processes_received":
                        len(processes),
                    "processes_valid":
                        valid_count,
                    "created":
                        created,
                    "updated":
                        updated,
                    "exited":
                        exited,
                    "pid_reuse":
                        pid_reuse,
                    "anomalies":
                        anomalies,
                    "evicted":
                        evicted,
                    "coverage_mode":
                        coverage["mode"],
                    "coverage_reason":
                        coverage["reason"],
                    "coverage_metadata_valid":
                        coverage["valid"],
                    "exit_suppressed":
                        suppressed_missing,
                    "node_count":
                        len(self.nodes),
                    "edge_count":
                        len(self.edges),
                }

            except Exception as exc:

                self._record_error(exc)

                return {
                    "accepted": False,
                    "reason":
                        "PROCESSING_ERROR",
                    "error":
                        str(exc),
                }

    # =========================================================
    # EDGE MANAGEMENT
    # =========================================================

    def _remove_edges_for_identity(
        self,
        identity: str,
    ) -> None:

        removed = {
            edge
            for edge in self.edges
            if (
                edge[0] == identity
                or edge[1] == identity
            )
        }

        if not removed:
            return

        self.edges.difference_update(
            removed
        )

        self.edges_removed += len(
            removed
        )

    # =========================================================
    # TTL
    # =========================================================

    def _expire_old_nodes(
        self,
        now_monotonic: float | None = None,
    ) -> None:

        if now_monotonic is None:
            now_monotonic = time.monotonic()

        expired = []

        for identity, node in list(
            self.nodes.items()
        ):

            last_seen = node.get(
                "_last_seen_monotonic"
            )

            if last_seen is None:
                continue

            if (
                now_monotonic - last_seen
                > self.ttl_seconds
            ):
                expired.append(
                    identity
                )

        for identity in expired:

            self.nodes.pop(
                identity,
                None,
            )

            self._remove_edges_for_identity(
                identity
            )

            self.nodes_expired += 1

            for pid, current_identity in list(
                self._pid_index.items()
            ):

                if current_identity == identity:
                    self._pid_index.pop(
                        pid,
                        None,
                    )

    # =========================================================
    # NODE LIMIT
    # =========================================================

    def _enforce_node_limit(
        self,
    ) -> list[str]:

        evicted = []

        while len(self.nodes) > self.max_nodes:

            identity, _ = (
                self.nodes.popitem(
                    last=False
                )
            )

            self._remove_edges_for_identity(
                identity
            )

            for pid, current_identity in list(
                self._pid_index.items()
            ):

                if current_identity == identity:
                    self._pid_index.pop(
                        pid,
                        None,
                    )

            self.nodes_evicted += 1

            evicted.append(
                identity
            )

        return evicted

    # =========================================================
    # CYCLE DETECTION
    # =========================================================

    def _detect_cycles(
        self,
    ) -> list[list[str]]:

        adjacency: dict[
            str,
            list[str],
        ] = {}

        for parent, child in self.edges:
            adjacency.setdefault(
                parent,
                [],
            ).append(child)

        visited: set[str] = set()
        active: set[str] = set()
        stack: list[str] = []

        cycles: list[list[str]] = []

        def visit(
            node: str,
        ) -> None:

            if node in active:

                if node in stack:
                    index = stack.index(
                        node
                    )

                    cycle = (
                        stack[index:]
                        + [node]
                    )

                    if cycle not in cycles:
                        cycles.append(
                            cycle
                        )

                return

            if node in visited:
                return

            visited.add(node)
            active.add(node)
            stack.append(node)

            for child in adjacency.get(
                node,
                [],
            ):
                visit(child)

            stack.pop()
            active.remove(node)

        for node in adjacency:
            if node not in visited:
                visit(node)

        return cycles

    # =========================================================
    # NODE ACCESS
    # =========================================================

    def get_node(
        self,
        pid: int,
    ) -> dict | None:

        with self._lock:

            try:
                pid = int(pid)
            except (
                TypeError,
                ValueError,
            ):
                return None

            identity = self._pid_index.get(
                pid
            )

            if identity is None:
                return None

            node = self.nodes.get(
                identity
            )

            if node is None:
                return None

            result = dict(node)

            result.pop(
                "_last_seen_monotonic",
                None,
            )

            return result

    # =========================================================
    # CHILDREN
    # =========================================================

    def get_children(
        self,
        pid: int,
    ) -> list[dict]:

        with self._lock:

            try:
                pid = int(pid)
            except (
                TypeError,
                ValueError,
            ):
                return []

            parent_identity = (
                self._pid_index.get(pid)
            )

            if parent_identity is None:
                return []

            parent_node = self.nodes.get(
                parent_identity
            )

            if (
                parent_node is None
                or parent_node.get("state")
                != "RUNNING"
            ):
                return []

            children = []

            for parent, child in self.edges:

                if parent != parent_identity:
                    continue

                node = self.nodes.get(
                    child
                )

                if node is None:
                    continue

                if node.get("state") != "RUNNING":
                    continue

                result = dict(node)

                result.pop(
                    "_last_seen_monotonic",
                    None,
                )

                children.append(
                    result
                )

            return children

    # =========================================================
    # PARENT
    # =========================================================

    def get_parent(
        self,
        pid: int,
    ) -> dict | None:

        with self._lock:

            node = self.get_node(pid)

            if node is None:
                return None

            if node.get("state") != "RUNNING":
                return None

            ppid = node.get("ppid")

            if ppid is None:
                return None

            parent = self.get_node(ppid)

            if parent is None:
                return None

            if parent.get("state") != "RUNNING":
                return None

            return parent

    # =========================================================
    # PROCESS TREE
    # =========================================================

    def get_process_tree(
        self,
        pid: int,
        max_depth: int = 32,
    ) -> dict | None:

        with self._lock:

            try:
                pid = int(pid)
            except (
                TypeError,
                ValueError,
            ):
                return None

            if max_depth <= 0:
                max_depth = 1

            root = self.get_node(pid)

            if root is None:
                return None

            def build(
                current_pid: int,
                depth: int,
                visited: set[int],
            ) -> dict | None:

                node = self.get_node(
                    current_pid
                )

                if node is None:
                    return None

                if current_pid in visited:

                    node["children"] = []
                    node["cycle_detected"] = True

                    return node

                current_visited = set(
                    visited
                )

                current_visited.add(
                    current_pid
                )

                node["children"] = []

                if depth >= max_depth:

                    node["tree_truncated"] = True

                    return node

                for child in self.get_children(
                    current_pid
                ):

                    child_pid = child.get(
                        "pid"
                    )

                    if child_pid is None:
                        continue

                    child_tree = build(
                        child_pid,
                        depth + 1,
                        current_visited,
                    )

                    if child_tree:
                        node["children"].append(
                            child_tree
                        )

                return node

            return build(
                pid,
                0,
                set(),
            )

    # =========================================================
    # ANOMALIES
    # =========================================================

    def get_anomalies(
        self,
    ) -> list[dict]:

        with self._lock:

            anomalies = []

            cycles = self._detect_cycles()

            for cycle in cycles:

                anomalies.append(
                    {
                        "type":
                            "PROCESS_GRAPH_CYCLE",
                        "severity":
                            "HIGH",
                        "cycle":
                            cycle,
                    }
                )

            for identity, node in self.nodes.items():

                if node.get("state") != "RUNNING":
                    continue

                pid = node.get("pid")
                ppid = node.get("ppid")

                if pid == ppid:

                    anomalies.append(
                        {
                            "type":
                                "SELF_PARENT",
                            "severity":
                                "HIGH",
                            "identity":
                                identity,
                        }
                    )

            return anomalies

    # =========================================================
    # STATS
    # =========================================================

    def get_stats(
        self,
    ) -> dict:

        with self._lock:

            return {
                "graph":
                    self.name,
                "version":
                    self.VERSION,
                "nodes":
                    len(self.nodes),
                "edges":
                    len(self.edges),
                "snapshots_processed":
                    self.snapshots_processed,
                "nodes_created":
                    self.nodes_created,
                "nodes_updated":
                    self.nodes_updated,
                "nodes_expired":
                    self.nodes_expired,
                "nodes_evicted":
                    self.nodes_evicted,
                "invalid_processes":
                    self.invalid_processes,
                "pid_reuse_detected":
                    self.pid_reuse_detected,
                "processes_seen":
                    self.processes_seen,
                "processes_exited":
                    self.processes_exited,
                "edges_created":
                    self.edges_created,
                "edges_updated":
                    self.edges_updated,
                "edges_removed":
                    self.edges_removed,
                "cycles_detected":
                    self.cycles_detected,
                "anomalies_detected":
                    self.anomalies_detected,
                "failed":
                    self.failed,
                "ttl_seconds":
                    self.ttl_seconds,
                "max_nodes":
                    self.max_nodes,
                "last_error":
                    self.last_error,
                "last_error_type":
                    self.last_error_type,
                "last_error_at":
                    self.last_error_at,
            }

    # =========================================================
    # CLEAR
    # =========================================================

    def clear(
        self,
    ) -> None:

        with self._lock:

            self.nodes.clear()
            self.edges.clear()
            self._pid_index.clear()

            self._last_snapshot_monotonic = None