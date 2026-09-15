from __future__ import annotations

import base64
import os
import tempfile
from collections import Counter
from pathlib import Path
from types import MethodType

from agent.config import load_config
from agent.crypto.key_manager import KeyManager
from agent.safety import SafetyCore
from agent.event import SecurityEvent
from agent.main import CyberDefenderRuntime


class TraversalProbe:
    def __init__(self) -> None:
        self.calls = Counter()
        self.security_event_ids: list[str] = []
        self.bridge_event_ids: list[str] = []
        self.correlation_event_ids: list[str] = []
        self.incident_counts: list[int] = []
        self.dashboard_calls = 0

    def mark(self, name: str) -> None:
        self.calls[name] += 1


def wrap_instance_method(obj, name: str, probe: TraversalProbe, label: str, extra=None):
    original = getattr(obj, name)

    def wrapper(self, *args, **kwargs):
        probe.mark(label)
        result = original(*args, **kwargs)
        if extra is not None:
            extra(args, kwargs, result)
        return result

    setattr(obj, name, MethodType(wrapper, obj))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cyberdefender_traversal_") as state_dir:
        os.environ["CYBERDEFENDER_STATE_DIR"] = state_dir
        storage_key = os.urandom(32)
        os.environ["CYBERDEFENDER_STORAGE_KEY_B64"] = base64.b64encode(storage_key).decode()

        # Production contract: runtime must not start without an ACTIVE
        # signing key.  Provision one explicitly before bootstrap so this
        # traversal test exercises the same fail-closed startup boundary.
        bootstrap_key_manager = KeyManager(
            Path(state_dir) / "keys",
            storage_key,
        )
        if bootstrap_key_manager.is_ready():
            raise AssertionError("Fresh KeyManager unexpectedly READY")
        if not bootstrap_key_manager.generate_key():
            raise AssertionError("Test key provisioning failed")
        if not bootstrap_key_manager.is_ready():
            raise AssertionError("Provisioned KeyManager not READY")

        config = load_config()
        runtime = CyberDefenderRuntime(SafetyCore(), config)
        probe = TraversalProbe()

        if runtime.key_manager is None or not runtime.key_manager.is_ready():
            raise AssertionError("Runtime KeyManager unavailable/not READY")

        # Keep the real DetectionEngine, but force one deterministic memory
        # warning so a normal workstation snapshot always exercises the
        # SecurityEvent path without modifying the production config file.
        runtime.detector.memory_warning = 0.0
        runtime.detector.memory_critical = 1000.0
        runtime.detector.cpu_warning = 1000.0
        runtime.detector.cpu_critical = 1001.0
        runtime.detector.process_warning = 100000
        runtime.detector.process_critical = 100001
        runtime.detector.available_memory_warning = -1.0
        runtime.detector.available_memory_critical = -2.0

        # ProcessSensor -> ProcessGraph
        wrap_instance_method(
            runtime.process_sensor,
            "collect",
            probe,
            "process_sensor.collect",
        )
        wrap_instance_method(
            runtime.process_graph,
            "ingest_snapshot",
            probe,
            "process_graph.ingest_snapshot",
        )

        # Observer -> Detection -> Rule
        wrap_instance_method(runtime, "observe", probe, "observer")
        wrap_instance_method(runtime, "detect", probe, "detection")
        wrap_instance_method(runtime, "rule_detect", probe, "rule_detection")
        wrap_instance_method(runtime, "process_detection", probe, "security_event_builder")

        # SecurityEvent -> RuntimeSecurityPipeline -> Durable Pipeline -> EventBus
        wrap_instance_method(runtime.runtime_pipeline, "ingest", probe, "runtime_pipeline.ingest")

        # P0.4 production runtime intentionally migrates CryptoReplay admission
        # to DurableEventPipeline.ingest_detailed() so persisted delivery
        # deferral is not collapsed into False.  Legacy stacks still use
        # ingest().  Instrument whichever contract the runtime actually owns.
        if bool(getattr(runtime.admission_gateway, "use_detailed_transport", False)):
            wrap_instance_method(
                runtime.pipeline,
                "ingest_detailed",
                probe,
                "durable_pipeline.ingest",
            )
        else:
            wrap_instance_method(
                runtime.pipeline,
                "ingest",
                probe,
                "durable_pipeline.ingest",
            )

        def count_security_publish(args, kwargs, result):
            event = args[0] if args else kwargs.get("event")
            if isinstance(event, SecurityEvent):
                probe.mark("event_bus.publish.security_event")

        wrap_instance_method(runtime.event_bus, "publish", probe, "event_bus.publish", count_security_publish)

        # Trusted EventBus consumer is already registered by main.py.
        # Add a read-only audit subscriber after it to observe actual dispatch.
        def audit_subscriber(event):
            if isinstance(event, SecurityEvent):
                probe.mark("trusted_consumer.dispatch")
                probe.security_event_ids.append(event.event_id)

        runtime.event_bus.subscribe(audit_subscriber)

        # SecurityEventBridge -> CorrelationEngine
        original_bridge = runtime.event_bridge.to_detection

        def bridge_wrapper(event):
            result = original_bridge(event)
            if isinstance(event, SecurityEvent):
                probe.mark("security_event_bridge")
                probe.bridge_event_ids.append(event.event_id)
            return result

        runtime.event_bridge.to_detection = bridge_wrapper

        original_handle = runtime.correlation_adapter.handle_event

        def correlation_wrapper(event):
            result = original_handle(event)
            if isinstance(event, dict) and event.get("event_type") == "DETECTION":
                probe.mark("correlation_adapter")
                event_id = event.get("event_id")
                if isinstance(event_id, str):
                    probe.correlation_event_ids.append(event_id)
            return result

        runtime.correlation_adapter.handle_event = correlation_wrapper

        # Incident materialization/read path.
        original_incidents = runtime.correlation_engine.get_recent_incidents

        def incidents_wrapper(*args, **kwargs):
            result = original_incidents(*args, **kwargs)
            probe.mark("incident.read")
            probe.incident_counts.append(len(result) if isinstance(result, list) else -1)
            return result

        runtime.correlation_engine.get_recent_incidents = incidents_wrapper

        # Dashboard is deliberately observed only; it remains outside the
        # security decision path.
        original_dashboard = runtime.publish_dashboard_state

        def dashboard_wrapper(self, *args, **kwargs):
            probe.dashboard_calls += 1
            return original_dashboard(*args, **kwargs)

        runtime.publish_dashboard_state = MethodType(dashboard_wrapper, runtime)

        per_cycle = []

        for cycle in (1, 2):
            before = probe.calls.copy()
            before_ids = len(probe.security_event_ids)
            before_bridge = len(probe.bridge_event_ids)
            before_corr = len(probe.correlation_event_ids)
            before_admitted = runtime.events_admitted
            before_acked = runtime.events_acked

            runtime.run_cycle()

            delta = probe.calls - before
            ids = probe.security_event_ids[before_ids:]
            bridge_ids = probe.bridge_event_ids[before_bridge:]
            corr_ids = probe.correlation_event_ids[before_corr:]

            if delta["process_sensor.collect"] != 1:
                raise AssertionError(f"cycle {cycle}: ProcessSensor count={delta['process_sensor.collect']}")
            if delta["process_graph.ingest_snapshot"] != 1:
                raise AssertionError(f"cycle {cycle}: ProcessGraph count={delta['process_graph.ingest_snapshot']}")
            if delta["observer"] != 1:
                raise AssertionError(f"cycle {cycle}: Observer count={delta['observer']}")
            if delta["detection"] != 1:
                raise AssertionError(f"cycle {cycle}: Detection count={delta['detection']}")
            if delta["rule_detection"] != 1:
                raise AssertionError(f"cycle {cycle}: RuleDetection count={delta['rule_detection']}")
            if delta["security_event_builder"] < 1:
                raise AssertionError(f"cycle {cycle}: no SecurityEvent built")
            if delta["runtime_pipeline.ingest"] < 1:
                raise AssertionError(f"cycle {cycle}: no RuntimeSecurityPipeline traversal")
            if delta["durable_pipeline.ingest"] < 1:
                raise AssertionError(f"cycle {cycle}: no DurableEventPipeline traversal")
            if delta["event_bus.publish.security_event"] < 1:
                raise AssertionError(f"cycle {cycle}: no SecurityEvent EventBus publication")
            if delta["trusted_consumer.dispatch"] < 1:
                raise AssertionError(f"cycle {cycle}: no trusted SecurityEvent dispatch")
            if delta["security_event_bridge"] < 1:
                raise AssertionError(f"cycle {cycle}: no SecurityEventBridge traversal")
            if delta["correlation_adapter"] < 1:
                raise AssertionError(f"cycle {cycle}: no Correlation traversal")
            if delta["incident.read"] < 1:
                raise AssertionError(f"cycle {cycle}: incident path not reached")
            if runtime.events_admitted <= before_admitted:
                raise AssertionError(f"cycle {cycle}: admitted counter did not increase")
            if runtime.events_acked <= before_acked:
                raise AssertionError(f"cycle {cycle}: ACK counter did not increase")
            if not ids:
                raise AssertionError(f"cycle {cycle}: no trusted SecurityEvent id observed")
            if len(ids) != len(set(ids)):
                raise AssertionError(f"cycle {cycle}: duplicate SecurityEvent dispatch inside cycle: {ids}")
            if set(bridge_ids) != set(ids):
                raise AssertionError(
                    f"cycle {cycle}: bridge IDs differ from dispatched IDs: dispatch={ids} bridge={bridge_ids}"
                )
            if set(corr_ids) != set(ids):
                raise AssertionError(
                    f"cycle {cycle}: correlation IDs differ from dispatched IDs: dispatch={ids} corr={corr_ids}"
                )

            per_cycle.append({
                "cycle": cycle,
                "security_events": len(ids),
                "admitted_delta": runtime.events_admitted - before_admitted,
                "acked_delta": runtime.events_acked - before_acked,
                "process_nodes": runtime.last_process_graph_result.get("node_count", 0),
                "incident_count": probe.incident_counts[-1] if probe.incident_counts else 0,
            })

        # Cross-cycle uniqueness: different cycle-generated events must not
        # collapse into duplicate delivery.
        if len(probe.security_event_ids) != len(set(probe.security_event_ids)):
            raise AssertionError(
                f"cross-cycle duplicate SecurityEvent IDs: {probe.security_event_ids}"
            )

        if runtime.cycle_count != 2:
            raise AssertionError(f"cycle_count={runtime.cycle_count}, expected 2")

        if runtime.component_failures != 0:
            raise AssertionError(f"component_failures={runtime.component_failures}")

        health = runtime.health_snapshot()
        runtime_status = health.get("runtime", {}).get("status")
        if runtime_status != "HEALTHY":
            raise AssertionError(f"runtime health={runtime_status!r}")

        dashboard_path = runtime.dashboard_publisher.state_file
        if not isinstance(dashboard_path, Path) or not dashboard_path.exists():
            raise AssertionError(
                f"dashboard state file was not published: {dashboard_path!r}"
            )
        if runtime.dashboard_publisher.publish_count < 2:
            raise AssertionError(
                f"dashboard publish_count={runtime.dashboard_publisher.publish_count}"
            )

        print("\nFULL RUNTIME TRAVERSAL v1")
        print("=" * 72)
        for row in per_cycle:
            print(
                f"Cycle {row['cycle']}: "
                f"SecurityEvents={row['security_events']} "
                f"Admitted+={row['admitted_delta']} "
                f"ACKed+={row['acked_delta']} "
                f"GraphNodes={row['process_nodes']} "
                f"Incidents={row['incident_count']}"
            )

        print("\nSTAGE COUNTS")
        for key in (
            "process_sensor.collect",
            "process_graph.ingest_snapshot",
            "observer",
            "detection",
            "rule_detection",
            "security_event_builder",
            "runtime_pipeline.ingest",
            "durable_pipeline.ingest",
            "event_bus.publish.security_event",
            "trusted_consumer.dispatch",
            "security_event_bridge",
            "correlation_adapter",
            "incident.read",
        ):
            print(f"{key}: {probe.calls[key]}")

        print(f"Dashboard publications observed: {probe.dashboard_calls}")
        print(f"Unique trusted SecurityEvents: {len(set(probe.security_event_ids))}")
        print(f"Runtime health: {runtime_status}")
        print(f"Component failures: {runtime.component_failures}")
        print("\nRESULT: PASS")
        runtime.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
