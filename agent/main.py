from __future__ import annotations
from agent.core.resource_guard import ResourceGuard
from agent.core.resource_adapter import ResourceGuardAdapter
from agent.core.resource_safety_plane import ResourceSafetyPlane
from agent.core.event_bus_resource_safety_gate import EventBusResourceSafetyGate
from agent.core.event_rate_limiter import EventRateLimiter
from agent.core.backpressure_controller import BackpressureController
from agent.core.evidence_retention import EvidenceRetentionPolicy
from agent.dashboard.runtime_state import (
    RuntimeStatePublisher,
)
from agent.data.sqlite_repository import (
    SQLiteDataRepository,
)


import base64
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any


# ============================================================
# DIRECT SCRIPT BOOTSTRAP
# ============================================================
#
# Allows both:
#
#     python -m agent.main
#
# and:
#
#     python .\agent\main.py
#
# to resolve the "agent" package correctly.
#
# No security decision is made here.
# ============================================================

if __package__ in {None, ""}:
    _THIS_FILE = Path(__file__).resolve()
    _PROJECT_ROOT = _THIS_FILE.parent.parent

    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(
            0,
            str(_PROJECT_ROOT),
        )


# ============================================================
# PROJECT IMPORTS
# ============================================================

from agent.config import (
    ConfigError,
    load_config,
)

from agent.safety import (
    SafetyCore,
)

from agent.observer import (
    SystemObserver,
)

from agent.sensors.process import (
    ProcessSensor,
)

from agent.network import (
    AsyncPassiveNetworkInventory,
    PassiveNetworkInventory,
    load_trust_registry,
)

from agent.sensors.process_display import (
    build_process_inventory,
)

from agent.sensors.rust_process_shadow import (
    RustProcessShadowProbe,
    compare_shadow_to_authoritative,
)

from agent.sensors.process_authority import (
    ProcessSensorAuthorityController,
    ProcessSensorMode,
)

from agent.sensors.rust_process_canary import (
    RustProcessCanary,
    RustProcessCanaryError,
)

from agent.sensors.process_runtime_config import (
    ProcessSensorRuntimeConfigError,
    load_process_sensor_runtime_config,
)

from agent.correlation.graph import (
    ProcessGraph,
)

from agent.attack_graph import (
    AttackGraph,
)

from agent.risk_engine import (
    RiskEngine,
)

from agent.policy_engine import (
    PolicyEngine,
)

from agent.independent_verifier import (
    IndependentVerifier,
)

from agent.safety_authorization_gate import (
    SafetyAuthorizationGate,
)

from agent.action_gateway import (
    ActionGateway,
)

from agent.blast_radius_guard import (
    BlastRadiusGuard,
)

from agent.post_action_verifier import (
    PostActionVerifier,
)

from agent.recovery_planner import (
    RecoveryPlanner,
)

from agent.detector import (
    DetectionEngine,
)

from agent.detection.rule_adapter import (
    RuleAdapter,
)

from agent.event import (
    SecurityEvent,
)

from agent.logger import (
    EventLogger,
)

from agent.state import (
    EventState,
)

from agent.bus.event_bus import (
    EventBus,
)

from agent.correlation.engine import (
    CorrelationEngine,
)

from agent.correlation.adapter import (
    CorrelationAdapter,
)

from agent.crypto.key_manager import (
    KeyManager,
)

from agent.crypto.replay_guard import (
    ReplayGuard,
)

from agent.core.crypto_replay_admission_gateway import (
    CryptoReplayAdmissionGateway,
)

from agent.core.durable_event_pipeline import (
    DurableEventPipeline,
)

from agent.storage.durable_spool import (
    DurableEventSpool,
)

from agent.core.runtime_security_pipeline import (
    RuntimeSecurityPipeline,
    RuntimePipelineResult,
)

from agent.core.event_bridge import (
    SecurityEventBridge,
)


# ============================================================
# VERSION
# ============================================================

VERSION = "2.4"
RESPONSE_SAFETY_CONTRACT_VERSION = "P0.5-1"

DEFAULT_LOOP_INTERVAL = 5.0
DEFAULT_BUS_CAPACITY = 1000
DEFAULT_REPLAY_MAX_ENTRIES = 100_000
DEFAULT_EVENT_LOG_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_EVENT_LOG_BACKUP_COUNT = 6


# ============================================================
# ERRORS
# ============================================================

class RuntimeBootstrapError(RuntimeError):
    """
    CyberDefender runtime bootstrap failure.

    Bootstrap failure must never result in unsafe
    autonomous system modification.
    """

    pass


# ============================================================
# CYBERDEFENDER RUNTIME
# ============================================================

class CyberDefenderRuntime:
    """
    CyberDefender P11.20 Hardened Runtime Orchestrator.

    High-level flow:

        Bootstrap
            |
            v
        Safety Core
            |
            v
        Observer
            |
            v
        Detection
            |
            v
        SecurityEvent
            |
            v
        Runtime Security Pipeline
            |
            +--> Crypto Trust
            |
            +--> Replay Protection
            |
            +--> Durable Storage
            |
            v
        EventBus
            |
            +--> Correlation
            |
            +--> Incident

    Security invariant:

        FAILURE
           |
           v
        ISOLATE
           |
           v
        FAIL CLOSED
           |
           v
        PRESERVE STATE
           |
           v
        RECOVER SAFELY

    Current runtime mode:

        OBSERVE only

    No autonomous destructive system modification is
    performed by this runtime.
    """

    VERSION = VERSION

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(
        self,
        safety: SafetyCore,
        config: dict[str, Any],
        *, allow_optional_sensors: bool = True,
    ):
        if safety is None:
            raise ValueError(
                "safety kerak"
            )

        if not isinstance(
            config,
            dict,
        ):
            raise TypeError(
                "config dict bo'lishi kerak"
            )

        self.safety = safety
        self.config = config
        self.allow_optional_sensors = bool(allow_optional_sensors)
        self.child_cleanup_verified = True

        # ----------------------------------------------------
        # Lifecycle
        # ----------------------------------------------------

        self.running = False
        self.degraded = False
        self.shutdown_requested = False

        self.cycle_count = 0
        self.cycle_failures = 0
        self.component_failures = 0

        # ----------------------------------------------------
        # Event counters
        # ----------------------------------------------------

        self.events_created = 0
        self.events_admitted = 0
        self.events_rejected = 0
        self.events_acked = 0
        self.events_published = 0
        self.events_persisted_deferred = 0

        self.recovery_published = 0

        # ----------------------------------------------------
        # Failure counters
        # ----------------------------------------------------

        self.observer_failures = 0
        self.detector_failures = 0
        self.rule_failures = 0
        self.admission_failures = 0
        self.dispatch_failures = 0
        self.correlation_failures = 0
        self.state_failures = 0
        self.logger_failures = 0
        self.recovery_failures = 0
        self.resource_snapshot_failures = 0
        self.data_repository_failures = 0
        self.data_repository_syncs = 0

            # --------------------------------------------------
        # Last runtime state
        # --------------------------------------------------

        self.started_at = time.time()
        self.started_monotonic = time.monotonic()

        self.last_cycle_started = None
        self.last_cycle_completed = None
        self.last_cycle_duration = 0.0

        self.last_observation: dict[str, Any] | None = None

        # Passive network inventory is observational only. It never probes hosts,
        # grants authorization, mutates firewall state, or executes dashboard actions.
        self.last_network_inventory: dict[str, Any] | None = None
        self.network_inventory_failures = 0
        self.network_inventory_sample_every_cycles = 5
        self.network_inventory_deadline_seconds = 5

        self.last_process_graph_result: dict[str, Any] | None = None
        # Bounded, display-only inventory derived from the authoritative
        # Python ProcessSensor snapshot. It is never an authority input.
        self.last_process_inventory: list[dict[str, Any]] = []
        self.process_sensor_failures = 0
        self.process_graph_failures = 0

        # Process sensor authority is explicit and independently observable.
        # Current release remains Python-authoritative; Rust primary is
        # compile-locked even if an operator requests that mode.
        self.process_sensor_mode = ProcessSensorMode.PYTHON_ONLY
        self.process_authority_config_error: str | None = None
        self.last_process_authority_decision: dict[str, Any] | None = None

        # Rust Process Sensor remains non-authoritative in this release.
        self.rust_process_shadow_enabled = False
        self.rust_process_shadow_failures = 0
        self.last_rust_process_shadow_result: dict[str, Any] | None = None
        self.last_rust_process_shadow_error: str | None = None
        self.rust_process_sensor_sha256: str | None = None
        self.rust_process_sensor_binary_trusted = False

        # Persistent Rust v0.5.1 canary is a separate, explicitly
        # non-authoritative observability plane.  It can never enter
        # ProcessGraph/EventBus/Policy/SafetyCore/action paths in this release.
        self.process_sensor_runtime_config: dict[str, Any] | None = None
        self.rust_process_canary_enabled = False
        self.rust_process_canary: RustProcessCanary | None = None
        self.rust_process_canary_failures = 0
        self.rust_process_canary_cycle_counter = 0
        self.rust_process_canary_sample_every_cycles = 2
        self.last_rust_process_canary_result: dict[str, Any] | None = None
        self.last_rust_process_canary_error: str | None = None

        self.last_attack_graph_result: dict[str, Any] | None = None
        self.attack_graph_failures = 0
        self.last_risk_result: dict[str, Any] | None = None
        self.last_policy_result: dict[str, Any] | None = None
        self.risk_engine_failures = 0
        self.policy_engine_failures = 0
        self.independent_verifier_failures = 0
        self.last_verification_result: dict[str, Any] | None = None
        self.authorization_gate_failures = 0
        self.last_authorization_result: dict[str, Any] | None = None
        self.action_gateway_failures = 0
        self.last_action_result: dict[str, Any] | None = None
        self.blast_radius_failures = 0
        self.last_blast_radius_result: dict[str, Any] | None = None
        self.post_action_verifier_failures = 0
        self.last_post_action_verification_result: dict[str, Any] | None = None
        self.response_recovery_failures = 0
        self.last_response_recovery_result: dict[str, Any] | None = None
        self.last_response_lifecycle_result: dict[str, Any] | None = None

        self.last_admission_reason = None
        self.last_admission_stage = None
        self.last_transport_disposition = None
        self.last_resource_result: dict[str, Any] | None = None
        self.last_data_repository_result: dict[str, Any] | None = None

        self.last_error = None

        # ----------------------------------------------------
        # Components
        # ----------------------------------------------------

        self.event_bus: EventBus | None = None

        self.resource_guard: ResourceGuard | None = None

        self.resource_adapter: ResourceGuardAdapter | None = None

        self.event_rate_limiter: EventRateLimiter | None = None

        self.backpressure_controller: BackpressureController | None = None

        self.evidence_retention: EvidenceRetentionPolicy | None = None

        self.resource_safety_plane: ResourceSafetyPlane | None = None

        self.resource_delivery_gate: EventBusResourceSafetyGate | None = None

        self.dashboard_publisher: RuntimeStatePublisher | None = None

        self.data_repository: SQLiteDataRepository | None = None

        self.spool: DurableEventSpool | None = None

        self.pipeline: DurableEventPipeline | None = None

        self.key_manager: KeyManager | None = None

        self.replay_guard: ReplayGuard | None = None

        self.admission_gateway: (
            CryptoReplayAdmissionGateway | None
        ) = None

        self.runtime_pipeline: (
            RuntimeSecurityPipeline | None
        ) = None

        self.correlation_engine: (
            CorrelationEngine | None
        ) = None

        self.correlation_adapter: (
            CorrelationAdapter | None
        ) = None

        self.event_bridge: (
            SecurityEventBridge | None
        ) = None

        self.observer: (
            SystemObserver | None
        ) = None

        self.network_inventory: (
            AsyncPassiveNetworkInventory | None
        ) = None

        self.detector: (
            DetectionEngine | None
        ) = None

        self.rule_adapter: (
            RuleAdapter | None
        ) = None

        self.state_manager: (
            EventState | None
        ) = None

        self.logger: (
            EventLogger | None
        ) = None

        self.process_sensor: ProcessSensor | None = None

        self.process_graph: ProcessGraph | None = None

        self.process_authority_controller: (
            ProcessSensorAuthorityController | None
        ) = None

        self.rust_process_shadow: RustProcessShadowProbe | None = None

        self.attack_graph: AttackGraph | None = None

        self.risk_engine: RiskEngine | None = None

        self.policy_engine: PolicyEngine | None = None

        self.independent_verifier: IndependentVerifier | None = None
        self.authorization_gate: SafetyAuthorizationGate | None = None
        self.action_gateway: ActionGateway | None = None
        self.blast_radius_guard: BlastRadiusGuard | None = None
        self.post_action_verifier: PostActionVerifier | None = None
        self.recovery_planner: RecoveryPlanner | None = None

        # ----------------------------------------------------
        # Bootstrap
        # ----------------------------------------------------

        try:
            self._initialize()
        except Exception:
            # Bootstrap may have already opened non-authoritative resources
            # (notably the SQLite read-model) before a later fail-closed
            # security boundary rejects startup.  Release those handles
            # deterministically so Windows does not retain locked state files.
            self.close()
            raise

    # ========================================================
    # PROJECT ROOT
    # ========================================================

    @staticmethod
    def _project_root() -> Path:
        return (
            Path(__file__)
            .resolve()
            .parent
            .parent
        )

    # ========================================================
    # STATE ROOT
    # ========================================================

    def _state_root(self) -> Path:
        configured = os.getenv(
            "CYBERDEFENDER_STATE_DIR"
        )

        if configured:
            return (
                Path(configured)
                .expanduser()
                .resolve()
            )

        return (
            self._project_root()
            / "state"
        )

    # ========================================================
    # LOG ROOT
    # ========================================================

    def _log_root(self, state_root: Path) -> Path:
        """Resolve runtime-owned log storage without cross-instance leakage."""
        configured = os.getenv("CYBERDEFENDER_LOG_DIR")
        if configured:
            return Path(configured).expanduser().resolve()

        if os.getenv("CYBERDEFENDER_STATE_DIR"):
            return state_root / "logs"

        return self._project_root() / "logs"

    # ========================================================
    # ENVIRONMENT HELPERS
    # ========================================================

    @staticmethod
    def _positive_float(
        value: str | None,
        default: float,
    ) -> float:

        if value is None:
            return default

        try:
            parsed = float(value)
        except (
            TypeError,
            ValueError,
        ):
            return default

        if parsed <= 0:
            return default

        return parsed

    @staticmethod
    def _positive_int(
        value: str | None,
        default: int,
    ) -> int:

        if value is None:
            return default

        try:
            parsed = int(value)
        except (
            TypeError,
            ValueError,
        ):
            return default

        if parsed <= 0:
            return default

        return parsed

    @staticmethod
    def _nonnegative_int(
        value: str | None,
        default: int,
    ) -> int:
        if value is None:
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        if parsed < 0:
            return default
        return parsed

    # ========================================================
    # BOOLEAN ENVIRONMENT FLAG
    # ========================================================

    @staticmethod
    def _env_enabled(name: str) -> bool:
        return (
            str(os.getenv(name) or "")
            .strip()
            .lower()
            in {"1", "true", "yes", "on"}
        )

    # ========================================================
    # PROCESS SENSOR AUTHORITY CONFIGURATION
    # ========================================================

    def _initialize_process_sensor_authority(self) -> None:
        """Initialize the fail-closed process-sensor authority plane.

        Configuration precedence:
            1. explicit environment mode (development/operator override);
            2. machine-local validated ProgramData config;
            3. legacy RUST_PROCESS_SHADOW flag;
            4. PYTHON_ONLY safe baseline.

        The machine-local config can enable only an already compile-locked
        mode.  Rust primary remains impossible in this release.
        """
        machine_config: dict[str, Any] | None = None
        machine_config_error: str | None = None
        try:
            machine_config = load_process_sensor_runtime_config(
                self._state_root()
            )
        except ProcessSensorRuntimeConfigError as exc:
            machine_config_error = str(exc)[:256]

        self.process_sensor_runtime_config = machine_config

        configured = str(
            os.getenv("CYBERDEFENDER_PROCESS_SENSOR_MODE") or ""
        ).strip()

        if configured:
            requested_mode = configured
        elif machine_config_error is not None:
            # Malformed machine configuration must never broaden authority.
            requested_mode = ProcessSensorMode.PYTHON_ONLY
        elif isinstance(machine_config, dict):
            requested_mode = str(
                machine_config.get("mode") or ProcessSensorMode.PYTHON_ONLY
            )
        elif self._env_enabled("CYBERDEFENDER_RUST_PROCESS_SHADOW"):
            requested_mode = ProcessSensorMode.RUST_SHADOW
        else:
            requested_mode = ProcessSensorMode.PYTHON_ONLY

        python_failure_threshold = min(
            self._positive_int(
                os.getenv("CYBERDEFENDER_PROCESS_PYTHON_FAILURE_THRESHOLD"),
                2,
            ),
            10,
        )
        python_recovery_threshold = min(
            self._positive_int(
                os.getenv("CYBERDEFENDER_PROCESS_PYTHON_RECOVERY_THRESHOLD"),
                2,
            ),
            10,
        )
        rust_healthy_threshold = min(
            self._positive_int(
                os.getenv("CYBERDEFENDER_PROCESS_RUST_HEALTHY_THRESHOLD"),
                2,
            ),
            10,
        )
        max_alignment_age = min(
            self._positive_float(
                os.getenv("CYBERDEFENDER_PROCESS_ALIGNMENT_MAX_AGE_SECONDS"),
                30.0,
            ),
            300.0,
        )

        controller = ProcessSensorAuthorityController(
            mode=requested_mode,
            primary_unlock_token=os.getenv(
                "CYBERDEFENDER_RUST_PRIMARY_UNLOCK"
            ),
            python_failure_threshold=python_failure_threshold,
            python_recovery_threshold=python_recovery_threshold,
            rust_healthy_threshold=rust_healthy_threshold,
            max_alignment_age_seconds=max_alignment_age,
            # Security release lock: configuration alone cannot activate Rust
            # primary authority.
            compiled_primary_enabled=False,
        )

        if machine_config_error is not None:
            controller.config_error = machine_config_error
            controller.last_error = machine_config_error

        self.process_authority_controller = controller
        self.process_sensor_mode = controller.mode
        self.process_authority_config_error = controller.config_error

        # Keep legacy v0.4 shadow and new v0.5.1 persistent canary distinct.
        # Only one non-authoritative native collection mode is active.
        self.rust_process_shadow_enabled = controller.mode in {
            ProcessSensorMode.RUST_SHADOW,
            ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
        }
        self.rust_process_canary_enabled = (
            controller.mode == ProcessSensorMode.RUST_CANARY
        )

    # ========================================================
    # RUST PROCESS SENSOR SHADOW / CANARY PROBE
    # ========================================================

    def _initialize_rust_process_shadow(self) -> None:
        """Initialize optional non-authoritative Rust probe.

        The binary is hash-pinned before it is ever executed. A mismatch
        is isolated from the Python-authoritative runtime and cannot silently
        broaden process-sensor authority.
        """
        controller = self.process_authority_controller

        if controller is None:
            self.rust_process_shadow_enabled = False
            self.rust_process_shadow = None
            return

        self.rust_process_shadow_enabled = controller.mode in {
            ProcessSensorMode.RUST_SHADOW,
            ProcessSensorMode.RUST_PRIMARY_WITH_FALLBACK,
        }

        if not self.rust_process_shadow_enabled:
            self.rust_process_shadow = None
            return

        executable = str(
            os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_EXE") or ""
        ).strip()

        if not executable:
            self.rust_process_shadow_failures += 1
            self.last_rust_process_shadow_error = "EXECUTABLE_NOT_CONFIGURED"
            self.rust_process_shadow = None
            return

        path = Path(executable).expanduser().resolve()

        try:
            digest = controller.sha256_file(path)
        except Exception as exc:
            self.rust_process_shadow_failures += 1
            self.last_rust_process_shadow_error = (
                f"BINARY_HASH_ERROR:{type(exc).__name__}"
            )[:512]
            self.rust_process_shadow = None
            return

        self.rust_process_sensor_sha256 = digest
        self.rust_process_sensor_binary_trusted = (
            controller.rust_binary_trusted(digest)
        )

        if not self.rust_process_sensor_binary_trusted:
            self.rust_process_shadow_failures += 1
            self.last_rust_process_shadow_error = "BINARY_HASH_MISMATCH"
            self.rust_process_shadow = None
            return

        timeout = self._positive_float(
            os.getenv("CYBERDEFENDER_RUST_PROCESS_SENSOR_TIMEOUT"),
            5.0,
        )
        timeout = min(timeout, 30.0)

        try:
            self.rust_process_shadow = RustProcessShadowProbe(
                path,
                timeout=timeout,
            )
            self.last_rust_process_shadow_error = None
        except Exception as exc:
            self.rust_process_shadow_failures += 1
            self.last_rust_process_shadow_error = (
                f"{type(exc).__name__}:{exc}"
            )[:512]
            self.rust_process_shadow = None

    # ========================================================
    # LOOP CONFIGURATION
    # ========================================================

    def _loop_interval(self) -> float:
        return self._positive_float(
            os.getenv(
                "CYBERDEFENDER_LOOP_INTERVAL"
            ),
            DEFAULT_LOOP_INTERVAL,
        )

    # ========================================================

    def _bus_capacity(self) -> int:
        return self._positive_int(
            os.getenv(
                "CYBERDEFENDER_BUS_CAPACITY"
            ),
            DEFAULT_BUS_CAPACITY,
        )

    # ========================================================

    def _replay_capacity(self) -> int:
        return self._positive_int(
            os.getenv(
                "CYBERDEFENDER_REPLAY_MAX_ENTRIES"
            ),
            DEFAULT_REPLAY_MAX_ENTRIES,
        )

    # ========================================================
    # LOCAL SECURITY LOG RETENTION
    # ========================================================

    def _event_log_max_bytes(self) -> int:
        return self._positive_int(
            os.getenv(
                "CYBERDEFENDER_EVENT_LOG_MAX_BYTES"
            ),
            DEFAULT_EVENT_LOG_MAX_BYTES,
        )

    def _event_log_backup_count(self) -> int:
        raw = os.getenv(
            "CYBERDEFENDER_EVENT_LOG_BACKUP_COUNT"
        )
        if raw is None:
            return DEFAULT_EVENT_LOG_BACKUP_COUNT
        try:
            parsed = int(raw)
        except (TypeError, ValueError):
            return DEFAULT_EVENT_LOG_BACKUP_COUNT
        if parsed < 0:
            return DEFAULT_EVENT_LOG_BACKUP_COUNT
        return parsed

    # ========================================================
    # STRUCTURED DATA READ MODEL
    # ========================================================

    def _data_db_path(self, state_root: Path) -> Path:
        configured = os.getenv("CYBERDEFENDER_DATA_DB")
        if configured:
            return Path(configured).expanduser().resolve()

        return state_root / "data" / "cyberdefender.db"

    @staticmethod
    def _local_endpoint_id() -> str:
        configured = str(os.getenv("CYBERDEFENDER_ENDPOINT_ID") or "").strip()
        if configured:
            return configured[:255]

        hostname = str(socket.gethostname() or "agent-local").strip()
        return (hostname or "agent-local")[:255]

    # ========================================================
    # STORAGE KEY
    # ========================================================

    def _load_storage_key(self) -> bytes:
        """
        Storage key environment orqali olinadi.

        Required:

            CYBERDEFENDER_STORAGE_KEY_B64

        Minimum:

            32 bytes

        Production architecture:

            TPM / HSM / OS protected secret store

        Environment variable is acceptable for development,
        but should not be considered the final production
        secret-management architecture.
        """

        encoded = os.getenv(
            "CYBERDEFENDER_STORAGE_KEY_B64"
        )

        if not encoded:
            raise RuntimeBootstrapError(
                "CYBERDEFENDER_STORAGE_KEY_B64 "
                "o'rnatilmagan."
            )

        try:

            key = base64.b64decode(
                encoded,
                validate=True,
            )

        except Exception as exc:

            raise RuntimeBootstrapError(
                "Storage key invalid Base64."
            ) from exc

        if len(key) < 32:

            raise RuntimeBootstrapError(
                "Storage key kamida 32 byte "
                "bo'lishi kerak."
            )

        return key

    # ========================================================
    # RUST v0.5.1 PERSISTENT CANARY
    # ========================================================

    def _initialize_rust_process_canary(self) -> None:
        """Initialize persistent Rust v0.5.1 canary without authority.

        Failure is isolated: Python remains the sole ProcessGraph source and
        the security runtime does not degrade solely because canary telemetry
        is unavailable.
        """
        if not self.rust_process_canary_enabled:
            self.rust_process_canary = None
            return

        config = self.process_sensor_runtime_config
        rust_config = (
            config.get("rust_v05", {})
            if isinstance(config, dict)
            else {}
        )
        canary_config = (
            config.get("canary", {})
            if isinstance(config, dict)
            else {}
        )
        if not isinstance(rust_config, dict):
            rust_config = {}
        if not isinstance(canary_config, dict):
            canary_config = {}

        executable = str(
            os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_EXE")
            or rust_config.get("executable")
            or ""
        ).strip()
        expected_sha256 = str(
            os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_SHA256")
            or rust_config.get("sha256")
            or ""
        ).strip().lower()

        self.rust_process_canary_sample_every_cycles = min(
            self._positive_int(
                os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_EVERY_CYCLES"),
                int(canary_config.get("sample_every_cycles", 2) or 2),
            ),
            60,
        )

        if not executable or not expected_sha256:
            self.rust_process_canary_failures += 1
            self.last_rust_process_canary_error = (
                "RUST_CANARY_CONFIGURATION_MISSING"
            )
            self.rust_process_canary = None
            return

        try:
            self.rust_process_canary = RustProcessCanary(
                executable,
                expected_sha256,
                timeout=self._positive_float(
                    os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_TIMEOUT"),
                    float(canary_config.get("timeout_seconds", 5.0) or 5.0),
                ),
                max_restarts=min(
                    self._nonnegative_int(
                        os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_MAX_RESTARTS"),
                        int(canary_config.get("max_restarts", 2)),
                    ),
                    10,
                ),
                restart_window_seconds=self._positive_float(
                    os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_RESTART_WINDOW_SECONDS"),
                    float(canary_config.get("restart_window_seconds", 60.0) or 60.0),
                ),
                min_field_coverage=self._positive_float(
                    os.getenv("CYBERDEFENDER_RUST_PROCESS_CANARY_MIN_COVERAGE"),
                    float(canary_config.get("min_field_coverage", 0.98) or 0.98),
                ),
            )
            self.last_rust_process_canary_error = None
        except Exception as exc:
            self.rust_process_canary = None
            self.rust_process_canary_failures += 1
            self.last_rust_process_canary_error = (
                "RUST_CANARY_INIT_FAILED"
            )[:512]

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def _initialize(self) -> None:

        state_root = self._state_root()
        log_root = self._log_root(state_root)

        try:

            state_root.mkdir(
                parents=True,
                exist_ok=True,
            )
            log_root.mkdir(
                parents=True,
                exist_ok=True,
            )

        except Exception as exc:

            raise RuntimeBootstrapError(
                "State directory yaratilmadi."
            ) from exc

        # ----------------------------------------------------
        # DASHBOARD STATE BRIDGE
        # ----------------------------------------------------

        self.dashboard_publisher = (
            RuntimeStatePublisher(
                state_root
            )
        )

        # ----------------------------------------------------
        # PASSIVE NETWORK INVENTORY v0.1.4
        # ----------------------------------------------------
        # Collection runs on exactly one bounded background worker. The core
        # security cycle never waits for Windows network telemetry. Failures,
        # deadline overruns and stale data remain observable while the last good
        # snapshot is preserved. The plane remains read-only/non-authoritative.
        try:
            registry_path = state_root / "network_trust.json"
            # v0.1.5: trust evidence is reloadable and fail-safe. The network
            # plane remains non-authoritative; malformed evidence collapses to
            # UNKNOWN instead of preserving stale AUTHORIZED labels.
            # Do not parse optional trust evidence in the authoritative runtime
            # bootstrap path. The collector performs bounded fail-safe reloads so
            # malformed trust JSON degrades to UNKNOWN without disabling network
            # observation.
            network_collector = PassiveNetworkInventory(
                trust_registry={},
                trust_registry_path=registry_path,
                max_devices=min(
                    self._positive_int(
                        os.getenv("CYBERDEFENDER_NETWORK_MAX_DEVICES"),
                        256,
                    ),
                    2048,
                ),
                max_connections=min(
                    self._positive_int(
                        os.getenv("CYBERDEFENDER_NETWORK_MAX_CONNECTIONS"),
                        256,
                    ),
                    4096,
                ),
            )
            self.network_inventory_sample_every_cycles = min(
                self._positive_int(
                    os.getenv("CYBERDEFENDER_NETWORK_SAMPLE_EVERY_CYCLES"),
                    5,
                ),
                120,
            )
            self.network_inventory_deadline_seconds = min(
                self._positive_int(
                    os.getenv("CYBERDEFENDER_NETWORK_DEADLINE_SECONDS"),
                    5,
                ),
                60,
            )
            self.network_inventory = AsyncPassiveNetworkInventory(
                network_collector,
                deadline_seconds=self.network_inventory_deadline_seconds,
            )
        except Exception as exc:
            self.network_inventory = None
            self.network_inventory_failures += 1
            self.last_error = f"network_inventory_bootstrap:{type(exc).__name__}"

        # ----------------------------------------------------
        # STRUCTURED DATA READ MODEL (P0.7)
        # ----------------------------------------------------
        # SQLite is intentionally non-authoritative.  Failure here must not
        # bypass or disable cryptographic admission, replay protection, the
        # durable spool, append-oriented audit evidence, Policy or Safety.

        try:
            self.data_repository = SQLiteDataRepository(
                self._data_db_path(state_root),
                max_incidents=self._positive_int(
                    os.getenv("CYBERDEFENDER_SQL_MAX_INCIDENTS"),
                    SQLiteDataRepository.DEFAULT_MAX_INCIDENTS,
                ),
                max_decisions=self._positive_int(
                    os.getenv("CYBERDEFENDER_SQL_MAX_DECISIONS"),
                    SQLiteDataRepository.DEFAULT_MAX_DECISIONS,
                ),
            )
        except Exception as exc:
            self.data_repository = None
            self.data_repository_failures += 1
            self.component_failures += 1
            self.last_error = f"data_repository_bootstrap:{type(exc).__name__}"

        # ----------------------------------------------------
        # CRYPTO FOUNDATION
        # ----------------------------------------------------

        storage_key = (
            self._load_storage_key()
        )

        key_root = (
            state_root / "keys"
        )

        spool_root = (
            state_root / "spool"
        )

        self.key_manager = KeyManager(
            key_root,
            storage_key,
        )

        if not self.key_manager.is_ready():

            # Controlled first-install bootstrap only.  A brand-new state
            # directory with an explicitly supplied storage key may create
            # its first ACTIVE signing key.  Existing authenticated state
            # with no ACTIVE key (for example after revocation) must never
            # be silently re-keyed and remains fail-closed.
            if getattr(
                self.key_manager,
                "is_fresh_unprovisioned",
                lambda: False,
            )():
                generated_key_id = (
                    self.key_manager.generate_key()
                )

                if (
                    generated_key_id
                    and self.key_manager.is_ready()
                ):
                    pass
                else:
                    raise RuntimeBootstrapError(
                        "KeyManager initial key provisioning "
                        "muvaffaqiyatsiz."
                    )

            elif getattr(
                self.key_manager,
                "is_unprovisioned",
                lambda: False,
            )():
                raise RuntimeBootstrapError(
                    "KeyManager ACTIVE key mavjud emas. "
                    "Controlled key provisioning talab qilinadi."
                )

            else:
                raise RuntimeBootstrapError(
                    "KeyManager READY emas."
                )

        # ----------------------------------------------------
        # EVENT BUS
        # ----------------------------------------------------

        self.event_bus = EventBus(
            self._bus_capacity()
        )


        # ----------------------------------------------------
        # RESOURCE GUARD
        # ----------------------------------------------------

        self.resource_guard = ResourceGuard()

        # ----------------------------------------------------
        # DURABLE SPOOL (BOUNDED PRODUCTION STORAGE)
        # ----------------------------------------------------

        self.spool = DurableEventSpool(
            spool_root
        )

        # ----------------------------------------------------
        # RESOURCE SAFETY PLANE
        # ----------------------------------------------------
        # P0.4 production wiring:
        #   - one authoritative ResourceGuard sample per cycle
        #   - bounded EventRateLimiter / BackpressureController
        #   - production DurableEventSpool is the capacity source
        #   - no direct OS action

        self.event_rate_limiter = EventRateLimiter()
        self.backpressure_controller = BackpressureController()
        self.evidence_retention = EvidenceRetentionPolicy()

        self.resource_safety_plane = ResourceSafetyPlane(
            resource_guard=self.resource_guard,
            event_rate_limiter=self.event_rate_limiter,
            backpressure_controller=self.backpressure_controller,
            evidence_retention=self.evidence_retention,
            bounded_spool=self.spool,
        )

        self.resource_delivery_gate = EventBusResourceSafetyGate(
            event_bus=self.event_bus,
            safety_plane=self.resource_safety_plane,
            require_committed_snapshot=True,
            enforce_cycle_binding=True,
        )

        # Resource status is a single internal telemetry event per cycle.
        # The adapter receives an already-evaluated result and therefore never
        # resamples ResourceGuard or advances hysteresis.
        self.resource_adapter = ResourceGuardAdapter(
            resource_guard=self.resource_guard,
            event_bus=self.event_bus,
        )

        # ----------------------------------------------------
        # DURABLE PIPELINE
        # ----------------------------------------------------
        # SecurityEvents are persisted first, then delivery is governed by
        # the resource-aware gate.  PERSISTED_DEFERRED remains pending and is
        # not misclassified as a durable rejection.

        self.pipeline = DurableEventPipeline(
            self.spool,
            self.event_bus,
            delivery_gateway=self.resource_delivery_gate,
            require_admission=True,
        )

        # ----------------------------------------------------
        # REPLAY PROTECTION
        # ----------------------------------------------------

        self.replay_guard = ReplayGuard(
            max_entries=(
                self._replay_capacity()
            )
        )

        # ----------------------------------------------------
        # CRYPTO + REPLAY ADMISSION
        # ----------------------------------------------------

        self.admission_gateway = (
            CryptoReplayAdmissionGateway(
                self.key_manager,
                self.replay_guard,
                self.pipeline,
                use_detailed_transport=True,
            )
        )

        self.pipeline.bind_admission_verifier(self.admission_gateway.verify_admission_receipt)

        # ----------------------------------------------------
        # RUNTIME SECURITY PIPELINE
        # ----------------------------------------------------

        self.runtime_pipeline = (
            RuntimeSecurityPipeline(
                self.admission_gateway
            )
        )

        # ----------------------------------------------------
        # CORRELATION
        # ----------------------------------------------------

        self.correlation_engine = (
            CorrelationEngine()
        )

        self.correlation_adapter = (
            CorrelationAdapter(
                engine=self.correlation_engine,
                event_bus=self.event_bus,
            )
        )

        # ----------------------------------------------------
        # EVENT BRIDGE
        # ----------------------------------------------------

        self.event_bridge = (
            SecurityEventBridge(
                output_callback=(
                    self._handle_detection
                )
            )
        )

        # ----------------------------------------------------
        # TRUSTED EVENT CONSUMER
        # ----------------------------------------------------

        if self.event_bus is None:
            raise RuntimeBootstrapError(
                "EventBus initialization failed."
            )

        self.event_bus.subscribe(
            self._handle_trusted_event
        )

        # ----------------------------------------------------
        # OBSERVER
        # ----------------------------------------------------

        self.observer = (
            SystemObserver()
        )

        # ----------------------------------------------------
        # PROCESS TELEMETRY -> PROCESS GRAPH
        # ----------------------------------------------------
        # Direct sensor -> graph path.
        # ProcessSensorAdapter is intentionally NOT used here:
        # its raw dictionary event path must not bypass the
        # canonical SecurityEvent admission boundary.
        self.process_sensor = ProcessSensor()
        self.process_graph = ProcessGraph()

        # Authority policy is initialized before the optional Rust probe.
        # Current release keeps Python authoritative and compile-locks Rust
        # primary mode. Shadow/canary evidence remains non-authoritative.
        self._initialize_process_sensor_authority()
        if not self.allow_optional_sensors:
            self.rust_process_shadow_enabled = False
            self.rust_process_canary_enabled = False
        self._initialize_rust_process_shadow()
        self._initialize_rust_process_canary()

        # ----------------------------------------------------
        # ATTACK GRAPH
        # ----------------------------------------------------
        # Analysis-only graph. It consumes trusted local ProcessGraph
        # state and correlation incidents. It has no remediation authority.
        self.attack_graph = AttackGraph()

        # ----------------------------------------------------
        # RISK ENGINE
        # ----------------------------------------------------
        # Deterministic analysis only. Risk never grants authority.
        self.risk_engine = RiskEngine()

        # ----------------------------------------------------
        # POLICY ENGINE
        # ----------------------------------------------------
        # Deterministic governance only. Policy never authorizes
        # or executes privileged actions. Independent verification
        # and SafetyCore remain mandatory future gates.
        self.policy_engine = PolicyEngine()

        # ----------------------------------------------------
        # INDEPENDENT VERIFIER
        # ----------------------------------------------------
        # Pre-authorization verification boundary. It independently
        # checks Risk/Policy consistency and SafetyCore state. It
        # cannot authorize or execute any action. Full post-action
        # verification remains a future executor/verifier boundary.
        self.independent_verifier = IndependentVerifier()

        # ----------------------------------------------------
        # SAFETY CORE AUTHORIZATION GATE + ACTION GATEWAY
        # ----------------------------------------------------
        # v1 is DRY_RUN only. No real-world privileged action is executable.
        self.authorization_gate = SafetyAuthorizationGate()
        self.action_gateway = ActionGateway(self.authorization_gate)

        # ----------------------------------------------------
        # RESPONSE SAFETY FOUNDATION
        # ----------------------------------------------------
        # P0.5 establishes bounded blast-radius, independent
        # post-response verification, and recovery planning.
        # These components do not enable a real OS executor.
        self.blast_radius_guard = BlastRadiusGuard()
        self.post_action_verifier = PostActionVerifier()
        self.recovery_planner = RecoveryPlanner()

        # ----------------------------------------------------
        # DETECTOR
        # ----------------------------------------------------

        self.detector = (
            DetectionEngine(
                self.config
            )
        )

        # ----------------------------------------------------
        # RULE ENGINE
        # ----------------------------------------------------

        self.rule_adapter = (
            RuleAdapter(
                self.config
            )
        )

        # ----------------------------------------------------
        # STATE
        # ----------------------------------------------------

        self.state_manager = (
            EventState(
                state_root / "state.json"
            )
        )

        # ----------------------------------------------------
        # LOGGER
        # ----------------------------------------------------

        self.logger = (
            EventLogger(
                log_root / "events.jsonl",
                max_bytes=self._event_log_max_bytes(),
                backup_count=self._event_log_backup_count(),
            )
        )

    # ========================================================
    # TRUSTED EVENT CONSUMER
    # ========================================================

    def _handle_trusted_event(
        self,
        event: Any,
    ) -> None:
        """
        EventBus'dan faqat trusted/admitted event kelishi
        kerak.

        Processing muvaffaqiyatli tugamaguncha ACK berilmaydi.

        Agar processing failure bo'lsa:

            no ACK
               |
               v
            event remains pending
               |
               v
            recovery
        """

        if not isinstance(
            event,
            SecurityEvent,
        ):
            return

        pipeline = self.pipeline

        bridge = self.event_bridge

        correlation_adapter = (
            self.correlation_adapter
        )

        if (
            pipeline is None
            or bridge is None
            or correlation_adapter is None
        ):
            return

        try:

            # Only pipeline-issued, one-use delivery bindings reach the bridge.
            # A fresh canonical copy removes unsigned extra Python attributes.
            event = pipeline.claim_trusted_delivery(event)
            if not isinstance(event, SecurityEvent):
                raise RuntimeBootstrapError("trusted admission binding missing or invalid")

            # ------------------------------------------------
            # Detection bridge
            # ------------------------------------------------

            detection = bridge.to_detection(
                event
            )

            # ------------------------------------------------
            # Correlation
            # ------------------------------------------------

            if not isinstance(
                detection,
                dict,
            ):
                raise RuntimeBootstrapError(
                    "SecurityEventBridge returned invalid detection."
                )

            if correlation_adapter.handle_event(detection) is not True:
                raise RuntimeBootstrapError("correlation consumption failed")

            # ------------------------------------------------
            # ACK ONLY AFTER SUCCESS
            # ------------------------------------------------

            if pipeline.ack(event.event_id) is not True:
                raise RuntimeBootstrapError("durable ACK failed")
            self.events_acked += 1

        except Exception as exc:

            self.component_failures += 1

            self.last_error = (
                f"trusted_event:"
                f"{type(exc).__name__}"
            )

            if isinstance(event, SecurityEvent):
                report_failure = getattr(pipeline, "consumer_failed", None)
                if callable(report_failure):
                    report_failure(event.event_id)

            # ------------------------------------------------
            # IMPORTANT:
            #
            # NO ACK.
            #
            # Event remains durable/pending.
            # Recovery can retry it.
            # ------------------------------------------------

            return

    # ========================================================
    # EVENT BRIDGE CALLBACK
    # ========================================================

    def _handle_detection(
        self,
        detection: dict[str, Any],
    ) -> None:
        """
        SecurityEventBridge callback.

        Current P11.20 runtime does not perform autonomous
        destructive response here.

        Detection is intentionally kept isolated from
        system-modification logic.

        Future layers:

            PolicyEngine
            RiskEngine
            IndependentVerifier
            ResponseController

        will consume this boundary.
        """

        if not isinstance(
            detection,
            dict,
        ):
            return

        # Intentionally observe-only for now.
        return

    # ========================================================
    # AUTHORITATIVE RESOURCE SAFETY CYCLE
    # ========================================================

    def update_resource_safety_cycle(
        self,
    ) -> dict[str, Any] | None:
        """Commit exactly one ResourceGuard result for this runtime cycle.

        Security properties:
            - Event volume never calls ResourceGuard.check().
            - Gate is bound to the current cycle before sampling.
            - If sampling fails, the previous cycle snapshot cannot be reused.
            - HIGH/CRITICAL delivery remains protected by the gate contract.
        """

        guard = self.resource_guard
        plane = self.resource_safety_plane
        gate = self.resource_delivery_gate
        adapter = self.resource_adapter

        if guard is None or plane is None or gate is None:
            self.component_failures += 1
            self.resource_snapshot_failures += 1
            self.degraded = True
            self.last_error = "resource_safety:unavailable"
            return None

        if not gate.bind_cycle(self.cycle_count):
            self.component_failures += 1
            self.resource_snapshot_failures += 1
            self.degraded = True
            self.last_error = "resource_safety:cycle_bind_rejected"
            return None

        try:
            result = guard.check()
        except Exception as exc:
            self.component_failures += 1
            self.resource_snapshot_failures += 1
            self.degraded = True
            self.last_error = f"resource_guard:{type(exc).__name__}"
            print(
                "ResourceGuard failure contained; current-cycle "
                "snapshot unavailable, delivery gate remains fail-safe."
            )
            return None

        if not isinstance(result, dict):
            self.component_failures += 1
            self.resource_snapshot_failures += 1
            self.degraded = True
            self.last_error = "resource_guard:invalid_result"
            return None

        if not plane.commit_resource_snapshot(
            result,
            cycle_id=self.cycle_count,
        ):
            self.component_failures += 1
            self.resource_snapshot_failures += 1
            self.degraded = True
            self.last_error = "resource_safety:snapshot_commit_rejected"
            return None

        self.last_resource_result = result

        resource_state = result.get(
            "state",
            ResourceGuard.NORMAL,
        )
        resource = result.get(
            "resource",
            {},
        )
        if not isinstance(resource, dict):
            resource = {}

        print()
        print("Resource Guard:")
        print(f"State: {resource_state}")
        print(f"CPU: {resource.get('cpu_percent')}%")
        print(f"Memory: {resource.get('memory_percent')}%")
        print(
            "Available memory: "
            f"{resource.get('memory_available_mb')} MB"
        )

        # Observability only.  Failure to publish this one telemetry item must
        # not disable the security pipeline or trigger a second resource sample.
        if adapter is not None:
            try:
                if not adapter.publish_result(result):
                    self.component_failures += 1
                    print(
                        "Resource telemetry publish failed; "
                        "security pipeline preserved."
                    )
            except Exception as exc:
                self.component_failures += 1
                self.last_error = (
                    f"resource_adapter:{type(exc).__name__}"
                )

        return result

    # ========================================================
    # PENDING RECOVERY
    # ========================================================

    def recover_pending(self) -> int:

        pipeline = self.pipeline

        if pipeline is None:
            return 0

        try:

            published = (
                pipeline.publish_pending()
            )

            if not isinstance(
                published,
                int,
            ):
                published = 0

            if published > 0:

                self.recovery_published += (
                    published
                )

            return published

        except Exception as exc:

            self.component_failures += 1
            self.recovery_failures += 1

            self.last_error = (
                f"recovery:"
                f"{type(exc).__name__}"
            )

            self.degraded = True

            return 0

    # ========================================================
    # OBSERVATION
    # ========================================================

    def observe(
        self,
    ) -> dict[str, Any] | None:

        observer = self.observer

        if observer is None:
            self.observer_failures += 1
            self.component_failures += 1
            return None

        try:

            snapshot = (
                observer.get_system_snapshot()
            )

            if not isinstance(
                snapshot,
                dict,
            ):
                self.observer_failures += 1
                self.component_failures += 1
                return None

            self.last_observation = snapshot

            return snapshot

        except Exception as exc:

            self.observer_failures += 1
            self.component_failures += 1

            self.last_error = (
                f"observer:"
                f"{type(exc).__name__}"
            )

            return None

    # ========================================================
    # PROCESS GRAPH
    # ========================================================

    def update_process_graph(
        self,
    ) -> dict[str, Any] | None:
        sensor = getattr(self, "process_sensor", None)
        graph = getattr(self, "process_graph", None)

        if sensor is None or graph is None:
            self.component_failures += 1
            self.process_graph_failures += 1
            self.degraded = True
            return None

        try:
            snapshot = sensor.collect()
            result = graph.ingest_snapshot(snapshot)

            if not isinstance(result, dict) or not result.get("accepted"):
                self.process_graph_failures += 1
                self.component_failures += 1
                self.degraded = True
                self.last_error = "process_graph:ingest_rejected"
                return result if isinstance(result, dict) else None

            self.last_process_graph_result = result
            self.last_process_inventory = build_process_inventory(
                snapshot,
                limit=18,
            )

            # Rust evidence is collected only after authoritative Python
            # ProcessGraph ingestion succeeds. The authority controller may
            # compute readiness/canary telemetry, but this release cannot
            # switch graph ownership to Rust.
            if self.rust_process_canary_enabled:
                self._update_rust_process_canary(snapshot)
            elif self.rust_process_shadow_enabled:
                self._update_rust_process_shadow(snapshot)
            else:
                controller = self.process_authority_controller
                if controller is not None:
                    decision = controller.decide(
                        python_snapshot=snapshot,
                    )
                    self.last_process_authority_decision = (
                        decision.to_dict()
                    )

            return result

        except Exception as exc:
            controller = self.process_authority_controller
            if controller is not None:
                try:
                    decision = controller.decide(
                        python_snapshot=None,
                    )
                    self.last_process_authority_decision = (
                        decision.to_dict()
                    )
                except Exception:
                    pass

            self.process_sensor_failures += 1
            self.process_graph_failures += 1
            self.component_failures += 1
            self.degraded = True
            self.last_error = f"process_graph:{type(exc).__name__}"
            return None

    # ========================================================
    # RUST v0.5.1 NON-AUTHORITATIVE CANARY EVIDENCE
    # ========================================================

    def _update_rust_process_canary(
        self,
        authoritative_snapshot: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Sample the persistent Rust canary after Python graph acceptance.

        The return value is observability only.  It is never passed to
        ProcessGraph, EventBus, correlation, Policy, authorization, SafetyCore
        or response actions.
        """
        controller = self.process_authority_controller
        if controller is not None:
            try:
                decision = controller.decide(
                    python_snapshot=authoritative_snapshot,
                )
                self.last_process_authority_decision = decision.to_dict()
            except Exception:
                pass

        if not self.rust_process_canary_enabled:
            return None

        self.rust_process_canary_cycle_counter += 1
        cadence = max(1, int(self.rust_process_canary_sample_every_cycles))
        if (self.rust_process_canary_cycle_counter - 1) % cadence != 0:
            return self.last_rust_process_canary_result

        canary = self.rust_process_canary
        if canary is None:
            return None

        try:
            result = canary.sample(authoritative_snapshot)
            self.last_rust_process_canary_result = result
            self.last_rust_process_canary_error = None
            return result
        except RustProcessCanaryError as exc:
            self.rust_process_canary_failures += 1
            self.last_rust_process_canary_error = "RUST_CANARY_SAMPLE_FAILED"
            return None
        except Exception as exc:
            self.rust_process_canary_failures += 1
            self.last_rust_process_canary_error = (
                f"RUST_CANARY:{type(exc).__name__}"
            )[:512]
            return None

    # ========================================================
    # RUST PROCESS SENSOR SHADOW / CANARY EVIDENCE
    # ========================================================

    def _update_rust_process_shadow(
        self,
        authoritative_snapshot: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Collect non-authoritative Rust evidence and authority telemetry.

        Security invariant for this release: no Rust return value from this
        method is admitted to ProcessGraph, EventBus, correlation, Policy,
        authorization, SafetyCore, or response actions.
        """
        if not self.rust_process_shadow_enabled:
            return None

        probe = self.rust_process_shadow
        controller = self.process_authority_controller

        if probe is None:
            if controller is not None:
                decision = controller.decide(
                    python_snapshot=authoritative_snapshot,
                )
                self.last_process_authority_decision = decision.to_dict()
            return None

        try:
            rust_snapshot = probe.probe()
            comparison = compare_shadow_to_authoritative(
                authoritative_snapshot,
                rust_snapshot,
            )
            self.last_rust_process_shadow_result = comparison
            self.last_rust_process_shadow_error = None

            if controller is not None:
                evidence = controller.assess_rust_evidence(
                    rust_snapshot=rust_snapshot,
                    comparison=comparison,
                    probe_health=probe.health_check(),
                    binary_sha256=self.rust_process_sensor_sha256,
                    transport_validated=True,
                )
                decision = controller.decide(
                    python_snapshot=authoritative_snapshot,
                    rust_snapshot=rust_snapshot,
                    rust_evidence=evidence,
                )
                self.last_process_authority_decision = decision.to_dict()

            return comparison
        except Exception as exc:
            self.rust_process_shadow_failures += 1
            self.last_rust_process_shadow_error = (
                f"{type(exc).__name__}:{exc}"
            )[:512]

            if controller is not None:
                try:
                    decision = controller.decide(
                        python_snapshot=authoritative_snapshot,
                    )
                    self.last_process_authority_decision = (
                        decision.to_dict()
                    )
                except Exception:
                    pass

            return None

    # ========================================================
    # ATTACK GRAPH
    # ========================================================

    def update_attack_graph(
        self,
        process_graph_result: dict[str, Any] | None = None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """
        Update the bounded, analysis-only AttackGraph from trusted
        local ProcessGraph state and correlation incidents.

        Security boundary:
        - never receives raw unadmitted telemetry;
        - never authorizes or performs OS actions;
        - bounded graph rejects remain contained;
        - unexpected internal failures are recorded locally.
        """
        graph = getattr(self, "attack_graph", None)
        process_graph = getattr(self, "process_graph", None)

        if graph is None or process_graph is None:
            self.attack_graph_failures += 1
            self.component_failures += 1
            self.last_error = "attack_graph:unavailable"
            return None

        try:
            process_result = graph.ingest_process_graph(process_graph)

            incident_results: list[dict[str, Any]] = []
            if incidents is None:
                engine = getattr(self, "correlation_engine", None)
                incidents = []
                if engine is not None:
                    recent = engine.get_recent_incidents(limit=20)
                    if isinstance(recent, list):
                        incidents = recent

            for incident in incidents:
                if isinstance(incident, dict):
                    incident_results.append(
                        graph.ingest_incident(incident)
                    )

            result = {
                "accepted": bool(process_result.get("accepted")),
                "process_graph": process_result,
                "incidents_processed": len(incident_results),
                "incidents_accepted": sum(
                    1 for item in incident_results
                    if item.get("accepted")
                ),
                "graph_health": graph.health_check(),
            }
            self.last_attack_graph_result = result
            return result

        except Exception as exc:
            self.attack_graph_failures += 1
            self.component_failures += 1
            self.last_error = f"attack_graph:{type(exc).__name__}"
            return None

    # ========================================================
    # RISK ENGINE
    # ========================================================

    def update_risk(self) -> dict[str, Any] | None:
        """Assess current trusted incidents against the bounded AttackGraph."""
        engine = getattr(self, "risk_engine", None)
        graph = getattr(self, "attack_graph", None)
        correlation = getattr(self, "correlation_engine", None)

        if engine is None or graph is None or correlation is None:
            self.risk_engine_failures += 1
            self.component_failures += 1
            self.last_error = "risk_engine:unavailable"
            return None

        try:
            incidents = correlation.get_recent_incidents(limit=20)
            if not isinstance(incidents, list):
                incidents = []

            result = engine.assess(graph, incidents)
            if not isinstance(result, dict) or result.get("accepted", True) is False:
                self.risk_engine_failures += 1
                self.component_failures += 1
                self.last_error = "risk_engine:assessment_rejected"
                return result if isinstance(result, dict) else None

            self.last_risk_result = result
            return result

        except Exception as exc:
            self.risk_engine_failures += 1
            self.component_failures += 1
            self.last_error = f"risk_engine:{type(exc).__name__}"
            return None

    # ========================================================
    # POLICY ENGINE
    # ========================================================

    def update_policy(self) -> dict[str, Any] | None:
        """Evaluate RiskEngine output against deterministic policy. No authorization."""
        engine = getattr(self, "policy_engine", None)
        risk_result = getattr(self, "last_risk_result", None)
        safety = getattr(self, "safety", None)

        if engine is None or not isinstance(risk_result, dict):
            self.policy_engine_failures += 1
            self.component_failures += 1
            self.last_error = "policy_engine:unavailable"
            return None

        try:
            result = engine.evaluate(risk_result, safety=safety)
            if not isinstance(result, dict) or result.get("accepted", True) is False:
                self.policy_engine_failures += 1
                self.component_failures += 1
                self.last_error = "policy_engine:evaluation_rejected"
                return result if isinstance(result, dict) else None

            self.last_policy_result = result
            return result

        except Exception as exc:
            self.policy_engine_failures += 1
            self.component_failures += 1
            self.last_error = f"policy_engine:{type(exc).__name__}"
            return None

    # ========================================================
    # INDEPENDENT VERIFICATION
    # ========================================================

    def update_verification(self) -> dict[str, Any] | None:
        """Independently verify the current Risk/Policy decision. Never authorizes."""
        verifier = getattr(self, "independent_verifier", None)
        risk_result = getattr(self, "last_risk_result", None)
        policy_result = getattr(self, "last_policy_result", None)
        safety = getattr(self, "safety", None)

        if verifier is None or not isinstance(risk_result, dict) or not isinstance(policy_result, dict):
            self.independent_verifier_failures += 1
            self.component_failures += 1
            self.last_error = "independent_verifier:unavailable"
            return None

        try:
            result = verifier.verify(risk_result, policy_result, safety=safety)
            if not isinstance(result, dict) or result.get("accepted") is not True or result.get("verified") is not True:
                # Verification failure is fail-closed. It must not authorize anything.
                self.independent_verifier_failures += 1
                self.component_failures += 1
                self.last_error = "independent_verifier:verification_rejected"
                return result if isinstance(result, dict) else None

            self.last_verification_result = result
            return result

        except Exception as exc:
            self.independent_verifier_failures += 1
            self.component_failures += 1
            self.last_error = f"independent_verifier:{type(exc).__name__}"
            return None

    # ========================================================
    # SAFETY CORE AUTHORIZATION GATE (DRY-RUN)
    # ========================================================

    def authorize_dry_run(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        gate = getattr(self, "authorization_gate", None)
        policy = getattr(self, "last_policy_result", None)
        verification = getattr(self, "last_verification_result", None)
        safety = getattr(self, "safety", None)

        if gate is None or not isinstance(policy, dict) or not isinstance(verification, dict):
            self.authorization_gate_failures += 1
            self.component_failures += 1
            self.last_error = "authorization_gate:unavailable"
            return None
        try:
            result = gate.authorize_dry_run(
                request,
                policy_result=policy,
                verification_result=verification,
                safety=safety,
            )
            if not isinstance(result, dict) or result.get("accepted") is not True:
                self.authorization_gate_failures += 1
            self.last_authorization_result = result
            return result
        except Exception as exc:
            self.authorization_gate_failures += 1
            self.component_failures += 1
            self.last_error = f"authorization_gate:{type(exc).__name__}"
            return None

    def execute_dry_run(
        self,
        authorization: dict[str, Any],
        *,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        gateway = getattr(self, "action_gateway", None)
        if gateway is None:
            self.action_gateway_failures += 1
            self.component_failures += 1
            self.last_error = "action_gateway:unavailable"
            return None
        try:
            result = gateway.execute_dry_run(authorization, request=request)
            if not isinstance(result, dict) or result.get("accepted") is not True:
                self.action_gateway_failures += 1
            self.last_action_result = result
            return result
        except Exception as exc:
            self.action_gateway_failures += 1
            self.component_failures += 1
            self.last_error = f"action_gateway:{type(exc).__name__}"
            return None

    # ========================================================
    # RESPONSE SAFETY FOUNDATION (P0.5)
    # ========================================================

    def evaluate_blast_radius(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        guard = getattr(self, "blast_radius_guard", None)
        if guard is None:
            self.blast_radius_failures += 1
            self.component_failures += 1
            self.last_error = "blast_radius_guard:unavailable"
            return None
        try:
            result = guard.evaluate(request)
            self.last_blast_radius_result = result
            return result if isinstance(result, dict) else None
        except Exception as exc:
            self.blast_radius_failures += 1
            self.component_failures += 1
            self.last_error = f"blast_radius_guard:{type(exc).__name__}"
            return None

    def verify_response_outcome(
        self,
        action_result: dict[str, Any],
        *,
        request: dict[str, Any],
        authorization: dict[str, Any],
    ) -> dict[str, Any] | None:
        verifier = getattr(self, "post_action_verifier", None)
        if verifier is None:
            self.post_action_verifier_failures += 1
            self.component_failures += 1
            self.last_error = "post_action_verifier:unavailable"
            return None
        try:
            result = verifier.verify(
                action_result,
                request=request,
                authorization=authorization,
            )
            if not isinstance(result, dict):
                self.post_action_verifier_failures += 1
                self.component_failures += 1
                self.last_error = "post_action_verifier:invalid_result"
                return None
            self.last_post_action_verification_result = result
            return result
        except Exception as exc:
            self.post_action_verifier_failures += 1
            self.component_failures += 1
            self.last_error = f"post_action_verifier:{type(exc).__name__}"
            return None

    def plan_response_recovery(
        self,
        verification_result: dict[str, Any],
        *,
        request: dict[str, Any] | None = None,
        action_result: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        planner = getattr(self, "recovery_planner", None)
        if planner is None:
            self.response_recovery_failures += 1
            self.component_failures += 1
            self.last_error = "recovery_planner:unavailable"
            return None
        try:
            result = planner.plan(
                verification_result,
                request=request,
                action_result=action_result,
            )
            if not isinstance(result, dict):
                self.response_recovery_failures += 1
                self.component_failures += 1
                self.last_error = "recovery_planner:invalid_result"
                return None
            self.last_response_recovery_result = result
            return result
        except Exception as exc:
            self.response_recovery_failures += 1
            self.component_failures += 1
            self.last_error = f"recovery_planner:{type(exc).__name__}"
            return None

    def run_response_dry_run(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the complete P0.5 response lifecycle with zero real-world effect.

        This method is explicit and is NOT invoked automatically by run_cycle().
        Real privileged execution remains unavailable.
        """
        blast = self.evaluate_blast_radius(request)
        if not isinstance(blast, dict) or blast.get("accepted") is not True or blast.get("allowed") is not True:
            result = {
                "component": "ResponseSafetyLifecycle",
                "version": RESPONSE_SAFETY_CONTRACT_VERSION,
                "accepted": False,
                "stage": "BLAST_RADIUS",
                "blast_radius": blast or {},
                "authorization": "NOT_GRANTED",
                "executed": False,
                "real_world_effect": False,
                "fail_closed": True,
            }
            self.last_response_lifecycle_result = result
            return result

        authorization = self.authorize_dry_run(request)
        if not isinstance(authorization, dict) or authorization.get("accepted") is not True:
            result = {
                "component": "ResponseSafetyLifecycle",
                "version": RESPONSE_SAFETY_CONTRACT_VERSION,
                "accepted": False,
                "stage": "AUTHORIZATION",
                "blast_radius": blast,
                "authorization_result": authorization or {},
                "authorization": "NOT_GRANTED",
                "executed": False,
                "real_world_effect": False,
                "fail_closed": True,
            }
            self.last_response_lifecycle_result = result
            return result

        action_result = self.execute_dry_run(authorization, request=request)
        if not isinstance(action_result, dict):
            synthetic = {
                "accepted": False,
                "executed": False,
                "simulated": False,
                "real_world_effect": None,
            }
            post = self.verify_response_outcome(
                synthetic,
                request=request,
                authorization=authorization,
            )
        else:
            post = self.verify_response_outcome(
                action_result,
                request=request,
                authorization=authorization,
            )

        if not isinstance(post, dict):
            post = {
                "accepted": False,
                "verified": False,
                "recovery_required": True,
                "real_world_effect_observed": None,
                "fail_closed": True,
            }

        recovery = self.plan_response_recovery(
            post,
            request=request,
            action_result=action_result if isinstance(action_result, dict) else None,
        )

        success = (
            isinstance(action_result, dict)
            and action_result.get("accepted") is True
            and post.get("accepted") is True
            and post.get("verified") is True
            and post.get("real_world_effect_observed") is False
            and isinstance(recovery, dict)
            and recovery.get("recovery_required") is False
        )
        observed_effect = post.get("real_world_effect_observed")
        result = {
            "component": "ResponseSafetyLifecycle",
            "version": RESPONSE_SAFETY_CONTRACT_VERSION,
            "accepted": bool(success),
            "stage": "COMPLETE" if success else "FAIL_CLOSED",
            "blast_radius": blast,
            "authorization_result": authorization,
            "action_result": action_result or {},
            "post_action_verification": post,
            "recovery": recovery or {},
            "authorization": "NOT_GRANTED",
            "executed": bool(
                isinstance(action_result, dict)
                and action_result.get("executed") is True
            ),
            "real_world_effect": observed_effect,
            "real_world_effect_authorized": False,
            "fail_closed": True,
        }
        self.last_response_lifecycle_result = result
        return result

    # ========================================================
    # DETECTION
    # ========================================================

    def detect(
        self,
        snapshot: dict[str, Any],
    ) -> list[dict[str, Any]]:

        detector = self.detector

        if detector is None:
            self.detector_failures += 1
            self.component_failures += 1
            return []

        if not isinstance(
            snapshot,
            dict,
        ):
            return []

        try:

            result = detector.analyze(
                snapshot
            )

            if not isinstance(
                result,
                list,
            ):
                self.detector_failures += 1
                self.component_failures += 1
                return []

            return result

        except Exception as exc:

            self.detector_failures += 1
            self.component_failures += 1

            self.last_error = (
                f"detector:"
                f"{type(exc).__name__}"
            )

            return []

    # ========================================================
    # RULE DETECTION
    # ========================================================

    def rule_detect(
        self,
        snapshot: dict[str, Any],
    ) -> list[dict[str, Any]]:

        adapter = self.rule_adapter

        if adapter is None:
            self.rule_failures += 1
            self.component_failures += 1
            return []

        if not isinstance(
            snapshot,
            dict,
        ):
            return []

        try:

            result = adapter.analyze(
                snapshot
            )

            if not isinstance(
                result,
                list,
            ):
                self.rule_failures += 1
                self.component_failures += 1
                return []

            return result

        except Exception as exc:

            self.rule_failures += 1
            self.component_failures += 1

            self.last_error = (
                f"rule:"
                f"{type(exc).__name__}"
            )

            return []

    # ========================================================
    # SECURITY EVENT BUILDER
    # ========================================================

    @staticmethod
    def _build_event(
        detection: dict[str, Any],
        source: str,
    ) -> SecurityEvent:
        """
        Convert detector output into SecurityEvent.

        Invalid detector output is rejected before admission.
        """

        if not isinstance(
            detection,
            dict,
        ):
            raise TypeError(
                "detection dict bo'lishi kerak"
            )

        required = (
            "type",
            "severity",
            "value",
            "message",
        )

        for field in required:

            if field not in detection:
                raise ValueError(
                    f"detection field missing: "
                    f"{field}"
                )

        return SecurityEvent(
            event_type=str(
                detection["type"]
            ),
            severity=str(
                detection["severity"]
            ),
            value=detection["value"],
            source=source,
            message=str(
                detection["message"]
            ),
        )

    # ========================================================
    # TRUSTED ADMISSION
    # ========================================================

    def admit_event(
        self,
        event: SecurityEvent,
    ) -> RuntimePipelineResult:
        """
        SINGLE runtime admission boundary.

        SecurityEvent
             |
             v
        RuntimeSecurityPipeline
             |
             +--> Crypto
             |
             +--> Replay
             |
             +--> Durable
             |
             +--> Bus
             |
             v
        RuntimePipelineResult

        Important:

        We preserve the detailed result rather than
        collapsing everything into True/False.

        This makes runtime diagnostics and future policy
        decisions much safer.
        """

        runtime_pipeline = (
            self.runtime_pipeline
        )

        event_id = getattr(
            event,
            "event_id",
            None,
        )

        if runtime_pipeline is None:

            self.events_rejected += 1
            self.admission_failures += 1

            self.last_admission_reason = (
                "RUNTIME_PIPELINE_UNAVAILABLE"
            )

            self.last_admission_stage = (
                "ADMISSION"
            )

            print(
                "  admission_reason="
                "RUNTIME_PIPELINE_UNAVAILABLE"
            )

            print(
                "  admission_stage="
                "ADMISSION"
            )

            print(
                "  admission_accepted=False"
            )

            return RuntimePipelineResult(
                accepted=False,
                reason=(
                    "RUNTIME_PIPELINE_UNAVAILABLE"
                ),
                event_id=event_id,
                stage="ADMISSION",
            )

        # ----------------------------------------------------
        # Validate event before entering security boundary
        # ----------------------------------------------------

        if not isinstance(
            event,
            SecurityEvent,
        ):

            self.events_rejected += 1

            return RuntimePipelineResult(
                accepted=False,
                reason="INVALID_SECURITY_EVENT",
                event_id=event_id,
                stage="INPUT_VALIDATION",
            )

        self.events_created += 1

        try:

            result = (
                runtime_pipeline.ingest(
                    event
                )
            )

        except Exception as exc:

            self.events_rejected += 1
            self.admission_failures += 1

            self.last_error = (
                f"admission:"
                f"{type(exc).__name__}"
            )

            print(
                "  admission_exception="
                f"{type(exc).__name__}: {exc}"
            )

            return RuntimePipelineResult(
                accepted=False,
                reason="ADMISSION_EXCEPTION",
                event_id=event_id,
                stage="ADMISSION",
            )

        # ----------------------------------------------------
        # Defensive result validation
        # ----------------------------------------------------

        if not isinstance(
            result,
            RuntimePipelineResult,
        ):

            self.events_rejected += 1
            self.admission_failures += 1

            self.last_error = (
                "RuntimePipeline returned "
                "invalid result object"
            )

            return RuntimePipelineResult(
                accepted=False,
                reason="INVALID_ADMISSION_RESULT",
                event_id=event_id,
                stage="ADMISSION",
            )

        # ----------------------------------------------------
        # Diagnostics
        # ----------------------------------------------------

        reason = getattr(
            result,
            "reason",
            "UNKNOWN",
        )

        stage = getattr(
            result,
            "stage",
            "UNKNOWN",
        )

        accepted = bool(
            getattr(
                result,
                "accepted",
                False,
            )
        )

        disposition = getattr(
            result,
            "disposition",
            None,
        )
        durable = bool(getattr(result, "durable", False))
        published = bool(getattr(result, "published", False))

        self.last_admission_reason = reason
        self.last_admission_stage = stage
        self.last_transport_disposition = disposition

        print(
            "  admission_reason="
            f"{reason}"
        )

        print(
            "  admission_stage="
            f"{stage}"
        )

        print(
            "  admission_accepted="
            f"{accepted}"
        )

        if disposition is not None:
            print(
                "  transport_disposition="
                f"{disposition}"
            )
            print(
                "  transport_durable="
                f"{durable}"
            )
            print(
                "  transport_published="
                f"{published}"
            )

        # ----------------------------------------------------
        # Final decision
        # ----------------------------------------------------

        if accepted:

            self.events_admitted += 1

            if disposition == "PERSISTED_DEFERRED":
                self.events_persisted_deferred += 1

            if published:
                self.events_published += 1

            return result

        self.events_rejected += 1

        return result

    # ========================================================
    # STATE
    # ========================================================

    def update_state(
        self,
        event: SecurityEvent,
    ) -> None:

        manager = self.state_manager

        if manager is None:
            return

        try:

            manager.update(
                event
            )

        except Exception as exc:

            self.state_failures += 1
            self.component_failures += 1
            self.degraded = True

            self.last_error = (
                f"state:"
                f"{type(exc).__name__}"
            )

    # ========================================================
    # LOGGER
    # ========================================================

    def log_event(
        self,
        event: SecurityEvent,
    ) -> None:

        logger = self.logger

        if logger is None:
            return

        try:

            logger.log(
                event
            )

        except Exception as exc:

            self.logger_failures += 1
            self.component_failures += 1
            self.degraded = True

            self.last_error = (
                f"logger:"
                f"{type(exc).__name__}"
            )

    # ========================================================
    # PROCESS ONE DETECTION
    # ========================================================

    def process_detection(
        self,
        detection: dict[str, Any],
        source: str,
        current_event_types: set[str],
    ) -> None:
        """
        Converts detection -> SecurityEvent -> Admission.

        IMPORTANT:

        State/logging happen only after successful
        SecurityEvent construction.

        Trusted downstream receives events only after
        RuntimeSecurityPipeline admission.
        """

        try:

            event = self._build_event(
                detection,
                source,
            )

        except (
            KeyError,
            TypeError,
            ValueError,
        ) as exc:

            self.component_failures += 1

            self.last_error = (
                f"event_builder:"
                f"{type(exc).__name__}"
            )

            return

        current_event_types.add(
            event.event_type
        )

        # ----------------------------------------------------
        # Admission FIRST
        # ----------------------------------------------------

        result = (
            self.admit_event(
                event
            )
        )

        print(
            "  admission="
            f"{'ACCEPTED' if result.accepted else 'REJECTED'}"
        )

        # ----------------------------------------------------
        # Only accepted events enter trusted local state
        # ----------------------------------------------------

        if not result.accepted:
            return

        self.update_state(
            event
        )

        self.log_event(
            event
        )

    # ========================================================
    # ONE RUNTIME CYCLE
    # ========================================================

    def run_cycle(self) -> None:
        """
        One isolated runtime cycle.

        Order:

            0. Authoritative Resource Safety Snapshot
            1. Recovery
            2. Observation
            3. Detection
            4. Rule Detection
            5. Admission
            6. Recovery State Admission
            7. EventBus Dispatch
            8. Incidents / Decision Layers
            9. Health

        Each stage is isolated as much as possible.
        """

        self.cycle_count += 1

        cycle_started = time.monotonic()

        self.last_cycle_started = (
            time.time()
        )

        current_event_types: set[str] = set()

        try:

            # =================================================
            # AUTHORITATIVE RESOURCE SAFETY SNAPSHOT
            # =================================================
            # This sample precedes recovery so pending delivery is governed by
            # current-cycle pressure, not by a stale previous-cycle snapshot.

            self.update_resource_safety_cycle()

            # =================================================
            # RECOVERY FIRST (AFTER SAFETY SNAPSHOT)
            # =================================================

            self.recover_pending()

            # =================================================
            # OBSERVE
            # =================================================

            snapshot = self.observe()

            if snapshot is None:

                self.degraded = True

                return

            # =================================================
            # PROCESS GRAPH OBSERVATION
            # =================================================

            process_graph_result = self.update_process_graph()

            if process_graph_result is None:
                print()
                print("Process Graph: DEGRADED")
            else:
                print()
                print("Process Graph:")
                print(
                    f"Processes valid: {process_graph_result.get('processes_valid', 0)}"
                )
                print(
                    f"Nodes: {process_graph_result.get('node_count', 0)} | "
                    f"Edges: {process_graph_result.get('edge_count', 0)}"
                )
                print(
                    f"Created: {len(process_graph_result.get('created', []))} | "
                    f"Updated: {len(process_graph_result.get('updated', []))} | "
                    f"Exited: {len(process_graph_result.get('exited', []))}"
                )
                print(
                    f"PID reuse: {len(process_graph_result.get('pid_reuse', []))} | "
                    f"Anomalies: {len(process_graph_result.get('anomalies', []))}"
                )

            print()
            print(
                "System Observer:"
            )

            print(
                f"CPU usage: "
                f"{snapshot.get('cpu_percent')}%"
            )

            print(
                f"Memory usage: "
                f"{snapshot.get('memory_percent')}%"
            )

            print(
                f"Available memory: "
                f"{snapshot.get('memory_available_mb')} MB"
            )

            print(
                f"Running processes: "
                f"{snapshot.get('process_count')}"
            )

            print(
                f"Network sent: "
                f"{snapshot.get('network_sent_mb')} MB"
            )

            print(
                f"Network received: "
                f"{snapshot.get('network_recv_mb')} MB"
            )

            # =================================================
            # DETECTION
            # =================================================

            detections = self.detect(
                snapshot
            )

            # =================================================
            # RULE DETECTION
            # =================================================

            rule_detections = (
                self.rule_detect(
                    snapshot
                )
            )

            print()
            print(
                "Detection Summary:"
            )

            print(
                f"DetectionEngine: "
                f"{len(detections)}"
            )

            print(
                f"RuleEngine: "
                f"{len(rule_detections)}"
            )

            # =================================================
            # SECURITY EVENTS
            # =================================================

            print()
            print(
                "Trusted Security Events:"
            )

            # -------------------------------------------------
            # Detection Engine
            # -------------------------------------------------

            for detection in detections:

                self.process_detection(
                    detection=detection,
                    source="SystemObserver",
                    current_event_types=(
                        current_event_types
                    ),
                )

            # -------------------------------------------------
            # Rule Engine
            # -------------------------------------------------

            for detection in rule_detections:

                self.process_detection(
                    detection=detection,
                    source="RuleEngine",
                    current_event_types=(
                        current_event_types
                    ),
                )

            # =================================================
            # EVENT STATE RECOVERY -> CANONICAL ADMISSION
            # =================================================
            # Recovery is admitted before dispatch so the lifecycle event
            # traverses EventBus -> trusted consumer -> correlation in the
            # same runtime cycle.

            self.process_recovery(
                snapshot,
                current_event_types,
            )

            # =================================================
            # EVENT BUS DISPATCH
            # =================================================

            event_bus = self.event_bus

            if event_bus is not None:

                try:

                    dispatched = (
                        event_bus.dispatch_all()
                    )

                    print()
                    print(
                        "Trusted events dispatched: "
                        f"{dispatched}"
                    )

                except Exception as exc:

                    self.dispatch_failures += 1
                    self.component_failures += 1

                    self.degraded = True

                    self.last_error = (
                        f"dispatch:"
                        f"{type(exc).__name__}"
                    )

                    print()
                    print(
                        "Trusted events dispatch "
                        "failed; pending events preserved."
                    )

            # =================================================
            # ATTACK GRAPH
            # =================================================

            attack_graph_result = self.update_attack_graph()

            if attack_graph_result is None:
                print()
                print("Attack Graph: DEGRADED / CONTAINED")
            else:
                graph_health = attack_graph_result.get("graph_health", {})
                print()
                print("Attack Graph:")
                print(
                    f"Status: {graph_health.get('status', 'UNKNOWN')} | "
                    f"Nodes: {graph_health.get('nodes', 0)} | "
                    f"Edges: {graph_health.get('edges', 0)}"
                )

            # =================================================
            # RISK ENGINE
            # =================================================

            risk_result = self.update_risk()
            if risk_result is None:
                print()
                print("Risk Engine: DEGRADED / CONTAINED")
            else:
                print()
                print("Risk Engine:")
                print(
                    f"Overall: {risk_result.get('overall_risk_level', 'INFO')} "
                    f"({risk_result.get('overall_risk_score', 0)}/100) | "
                    f"Incidents: {risk_result.get('incidents_assessed', 0)}"
                )

            # =================================================
            # POLICY ENGINE
            # =================================================

            policy_result = self.update_policy()
            if policy_result is None:
                print()
                print("Policy Engine: DEGRADED / CONTAINED")
            else:
                print()
                print("Policy Engine:")
                print(
                    f"Outcome: {policy_result.get('policy_outcome', 'OBSERVE_ONLY')} | "
                    f"Recommendation: {policy_result.get('recommendation', 'OBSERVE')} | "
                    f"Authorization: {policy_result.get('authorization', 'NOT_GRANTED')}"
                )

            # =================================================
            # INDEPENDENT VERIFICATION
            # =================================================

            verification_result = self.update_verification()
            if verification_result is None:
                print()
                print("Independent Verifier: REJECTED / FAIL-CLOSED")
            else:
                print()
                print("Independent Verifier:")
                print(
                    f"Outcome: {verification_result.get('verification_outcome', 'UNKNOWN')} | "
                    f"Verified: {verification_result.get('verified', False)} | "
                    f"Authorization: {verification_result.get('authorization', 'NOT_GRANTED')}"
                )

            # =================================================
            # STRUCTURED DATA READ MODEL
            # =================================================

            data_synced = self.persist_data_read_model(
                observation=snapshot,
            )
            print()
            print(
                "Data Store: "
                + ("SYNCED" if data_synced else "DEGRADED / CORE PRESERVED")
            )

            # =================================================
            # PASSIVE NETWORK INVENTORY (NON-AUTHORITATIVE)
            # =================================================

            self.update_network_inventory()

            # =================================================
            # INCIDENTS
            # =================================================

            self.print_incidents()

            # =================================================
            # HEALTH
            # =================================================

            self.print_health()

            # =================================================
            # DASHBOARD STATE
            # =================================================

            dashboard_published = (
                self.publish_dashboard_state(
                    observation=snapshot,
                )
            )

            if dashboard_published:
                print(
                    "Dashboard state: PUBLISHED"
                )
            else:
                print(
                    "Dashboard state: "
                    "PUBLISH FAILED (runtime preserved)"
                )

        finally:

            elapsed = (
                time.monotonic()
                - cycle_started
            )

            self.last_cycle_duration = (
                elapsed
            )

            self.last_cycle_completed = (
                time.time()
            )

    # ========================================================
    # PASSIVE NETWORK INVENTORY v0.1.4
    # ========================================================

    def update_network_inventory(self) -> dict[str, Any] | None:
        """Schedule passive network telemetry without blocking this cycle.

        One background worker owns collection. Runtime cycles only enqueue a
        bounded/coalesced refresh request and consume the latest completed good
        snapshot. Slow/hung/failing telemetry cannot delay Detection, Policy,
        Safety Core, Independent Verification, EventBus, or dashboard publish.
        """
        worker = self.network_inventory
        if worker is None:
            return self.last_network_inventory

        should_request = (
            self.last_network_inventory is None
            or self.cycle_count % self.network_inventory_sample_every_cycles == 0
        )

        if should_request:
            try:
                worker.request_sample()
            except Exception:
                # Request scheduling itself is non-authoritative and isolated.
                self.network_inventory_failures += 1

        try:
            latest = worker.get_latest_snapshot()
            worker_state = worker.integration_state()
        except Exception:
            self.network_inventory_failures += 1
            return self.last_network_inventory

        try:
            observed_failures = int(worker_state.get("failures", 0) or 0)
            if observed_failures > self.network_inventory_failures:
                self.network_inventory_failures = observed_failures
        except (TypeError, ValueError):
            pass

        if isinstance(latest, dict):
            self.last_network_inventory = latest

        return self.last_network_inventory

    # ========================================================
    # STRUCTURED DATA READ-MODEL SYNC (P0.7)
    # ========================================================

    def persist_data_read_model(
        self,
        observation: dict[str, Any] | None = None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Persist queryable endpoint/incident/decision state to SQLite.

        This path is deliberately non-authoritative.  A SQL failure is
        observable, but it cannot grant authorization, bypass canonical
        SecurityEvent admission, discard durable spool state, or stop the
        core security pipeline.
        """

        repository = self.data_repository
        if repository is None:
            return False

        if observation is None:
            observation = self.last_observation or {}
        if not isinstance(observation, dict):
            observation = {}

        if incidents is None:
            incidents = []
            engine = self.correlation_engine
            if engine is not None:
                try:
                    limit = int(getattr(engine, "MAX_ACTIVE_INCIDENTS", 1000))
                    result = engine.get_recent_incidents(limit=max(1, limit))
                    if isinstance(result, list):
                        incidents = result
                except Exception as exc:
                    self.data_repository_failures += 1
                    self.component_failures += 1
                    self.last_error = f"data_repository_incidents:{type(exc).__name__}"
                    return False

        resource_result = self.last_resource_result or {}
        if not isinstance(resource_result, dict):
            resource_result = {}
        resource_values = resource_result.get("resource", {})
        if not isinstance(resource_values, dict):
            resource_values = {}

        endpoint = {
            "endpoint_id": self._local_endpoint_id(),
            "hostname": str(socket.gethostname() or "agent-local"),
            "scope": "LOCAL_ENDPOINT",
            "runtime_version": self.VERSION,
            "mode": self.config.get("mode", "OBSERVE"),
            "runtime_status": "DEGRADED" if self.degraded else "HEALTHY",
            "resource_state": resource_result.get("state"),
            "cpu_percent": observation.get("cpu_percent", resource_values.get("cpu_percent")),
            "memory_percent": observation.get("memory_percent", resource_values.get("memory_percent")),
            "available_memory_mb": observation.get(
                "memory_available_mb",
                resource_values.get("memory_available_mb"),
            ),
            "process_count": observation.get("process_count"),
            "last_cycle": self.cycle_count,
        }

        try:
            result = repository.sync_cycle(
                endpoint=endpoint,
                incidents=incidents if isinstance(incidents, list) else [],
                risk=self.last_risk_result,
                policy=self.last_policy_result,
                verification=self.last_verification_result,
            )
            if not isinstance(result, dict) or result.get("accepted") is not True:
                raise RuntimeError("DATA_REPOSITORY_SYNC_REJECTED")

            self.data_repository_syncs += 1
            self.last_data_repository_result = result
            return True

        except Exception as exc:
            self.data_repository_failures += 1
            self.component_failures += 1
            self.last_error = f"data_repository:{type(exc).__name__}"
            return False

    # ========================================================
    # INCIDENTS
    # ========================================================

    def print_incidents(
        self,
    ) -> None:

        engine = (
            self.correlation_engine
        )

        if engine is None:
            return

        try:

            incidents = (
                engine.get_recent_incidents(
                    limit=20
                )
            )

        except Exception as exc:

            self.correlation_failures += 1
            self.component_failures += 1

            self.last_error = (
                f"incidents:"
                f"{type(exc).__name__}"
            )

            return

        print()
        print(
            "Incidents:"
        )

        if not incidents:

            print(
                "No incidents."
            )

            return

        for incident in incidents:

            try:

                print(
                    f"[{incident['severity']}] "
                    f"{incident['incident_id']} | "
                    f"risk={incident['risk_score']} | "
                    f"events={incident['event_count']} | "
                    f"key={incident['correlation_key']}"
                )

            except Exception:

                print(
                    "[INCIDENT] "
                    "Malformed incident record"
                )

    # ========================================================
    # EVENT STATE RECOVERY
    # ========================================================

    def process_recovery(
        self,
        snapshot: dict[str, Any],
        current_event_types: set[str],
    ) -> None:
        """
        Recover inactive detections through the same authoritative
        SecurityEvent admission boundary as normal detections.

        If canonical admission rejects the recovery event, the exact prior
        ACTIVE state is transactionally restored so recovery cannot bypass
        crypto/replay/durable/EventBus processing or disappear silently.
        """
        manager = self.state_manager
        if manager is None:
            return

        try:
            active_types = manager.get_active_event_types()
        except Exception as exc:
            self.state_failures += 1
            self.component_failures += 1
            self.degraded = True
            self.last_error = f"state_recovery:{type(exc).__name__}"
            return

        if not isinstance(active_types, (list, tuple, set)):
            self.state_failures += 1
            self.component_failures += 1
            self.degraded = True
            self.last_error = "state_recovery:INVALID_ACTIVE_TYPES"
            return

        for event_type in active_types:
            if event_type in current_event_types:
                continue

            try:
                recovered_event = SecurityEvent(
                    event_type=f"{event_type}_RECOVERED",
                    severity="INFO",
                    value=0,
                    source="EventState",
                    message=f"{event_type} holati tiklandi.",
                )
            except Exception as exc:
                self.component_failures += 1
                self.degraded = True
                self.last_error = f"recovery_event:{type(exc).__name__}"
                continue

            try:
                recovered_state = manager.recover(event_type)
            except Exception as exc:
                self.state_failures += 1
                self.component_failures += 1
                self.degraded = True
                self.last_error = f"state_recover:{type(exc).__name__}"
                continue

            if not recovered_state:
                continue

            result = self.admit_event(recovered_event)
            if not result.accepted:
                try:
                    manager.restore_active_state(event_type, recovered_state)
                except Exception as exc:
                    self.state_failures += 1
                    self.component_failures += 1
                    self.degraded = True
                    self.last_error = (
                        f"state_recovery_rollback:{type(exc).__name__}"
                    )
                else:
                    self.recovery_failures += 1
                    self.degraded = True
                    self.last_error = (
                        "recovery_admission:"
                        f"{getattr(result, 'reason', 'REJECTED')}"
                    )
                continue

            self.log_event(recovered_event)
            self.recovery_published += 1

            print()
            print("Recovery Event:")
            recovered_event.print_event()

    # ========================================================
    # HEALTH SNAPSHOT
    # ========================================================

    def health_snapshot(
        self,
    ) -> dict[str, Any]:

        health: dict[str, Any] = {

            "runtime": {
                "component":
                    "CyberDefenderRuntime",

                "version":
                    self.VERSION,

                "running":
                    self.running,

                "degraded":
                    self.degraded,

                "shutdown_requested":
                    self.shutdown_requested,

                "cycle_count":
                    self.cycle_count,

                "cycle_failures":
                    self.cycle_failures,

                "component_failures":
                    self.component_failures,

                "events_created":
                    self.events_created,

                "events_admitted":
                    self.events_admitted,

                "events_rejected":
                    self.events_rejected,

                "events_acked":
                    self.events_acked,

                "events_published":
                    self.events_published,

                "events_persisted_deferred":
                    self.events_persisted_deferred,

                "recovery_published":
                    self.recovery_published,

                "observer_failures":
                    self.observer_failures,

                "detector_failures":
                    self.detector_failures,

                "rule_failures":
                    self.rule_failures,

                "admission_failures":
                    self.admission_failures,

                "dispatch_failures":
                    self.dispatch_failures,

                "correlation_failures":
                    self.correlation_failures,

                "state_failures":
                    self.state_failures,

                "logger_failures":
                    self.logger_failures,

                "recovery_failures":
                    self.recovery_failures,

                "resource_snapshot_failures":
                    self.resource_snapshot_failures,

                "data_repository_failures":
                    self.data_repository_failures,

                "network_inventory_failures":
                    self.network_inventory_failures,

                "data_repository_syncs":
                    self.data_repository_syncs,

                "process_sensor_failures":
                    self.process_sensor_failures,

                "process_graph_failures":
                    self.process_graph_failures,

                "process_sensor_mode":
                    self.process_sensor_mode,

                "process_authority_config_error":
                    self.process_authority_config_error,

                "rust_process_sensor_binary_trusted":
                    self.rust_process_sensor_binary_trusted,

                "rust_process_shadow_enabled":
                    self.rust_process_shadow_enabled,

                "rust_process_shadow_failures":
                    self.rust_process_shadow_failures,

                "rust_process_canary_enabled":
                    self.rust_process_canary_enabled,

                "rust_process_canary_failures":
                    self.rust_process_canary_failures,

                "rust_process_canary_sample_every_cycles":
                    self.rust_process_canary_sample_every_cycles,

                "attack_graph_failures":
                    self.attack_graph_failures,

                "risk_engine_failures":
                    self.risk_engine_failures,
                "policy_engine_failures":
                    self.policy_engine_failures,

                "independent_verifier_failures":
                    self.independent_verifier_failures,

                "authorization_gate_failures":
                    self.authorization_gate_failures,

                "action_gateway_failures":
                    self.action_gateway_failures,

                "blast_radius_failures":
                    self.blast_radius_failures,

                "post_action_verifier_failures":
                    self.post_action_verifier_failures,

                "response_recovery_failures":
                    self.response_recovery_failures,

                "last_cycle_duration":
                    self.last_cycle_duration,

                "last_admission_reason":
                    self.last_admission_reason,

                "last_admission_stage":
                    self.last_admission_stage,

                "last_transport_disposition":
                    self.last_transport_disposition,

                "last_error":
                    self.last_error,
            }
        }

        controller = self.process_authority_controller
        if controller is None:
            health["process_sensor_authority"] = {
                "component": "ProcessSensorAuthorityController",
                "status": "UNAVAILABLE",
                "mode": self.process_sensor_mode,
                "authoritative_sensor": "ProcessSensor",
            }
        else:
            try:
                authority_health = controller.health_check()
                health["process_sensor_authority"] = (
                    authority_health
                    if isinstance(authority_health, dict)
                    else {"status": "INVALID_HEALTH_RESPONSE"}
                )
            except Exception as exc:
                health["process_sensor_authority"] = {
                    "component": "ProcessSensorAuthorityController",
                    "status": "DEGRADED",
                    "mode": self.process_sensor_mode,
                    "authoritative_sensor": "ProcessSensor",
                    "error": type(exc).__name__,
                }

        if self.last_process_authority_decision is not None:
            health["process_sensor_authority"]["runtime_decision"] = (
                self.last_process_authority_decision
            )

        # Rust process telemetry is intentionally a non-critical,
        # non-authoritative shadow health surface. A shadow failure must
        # never mark the security runtime degraded by itself.
        if not self.rust_process_shadow_enabled:
            health["rust_process_shadow"] = {
                "component": "RustProcessShadowProbe",
                "status": "DISABLED",
                "mode": "SHADOW_ONLY",
            }
        elif self.rust_process_shadow is None:
            health["rust_process_shadow"] = {
                "component": "RustProcessShadowProbe",
                "status": "DEGRADED",
                "mode": "SHADOW_ONLY",
                "error": self.last_rust_process_shadow_error,
            }
        else:
            try:
                rust_health = self.rust_process_shadow.health_check()
                health["rust_process_shadow"] = (
                    rust_health
                    if isinstance(rust_health, dict)
                    else {"status": "INVALID_HEALTH_RESPONSE"}
                )
            except Exception as exc:
                health["rust_process_shadow"] = {
                    "component": "RustProcessShadowProbe",
                    "status": "DEGRADED",
                    "mode": "SHADOW_ONLY",
                    "error": type(exc).__name__,
                }

        health["rust_process_shadow"]["binary_trusted"] = (
            self.rust_process_sensor_binary_trusted
        )
        health["rust_process_shadow"]["binary_sha256"] = (
            self.rust_process_sensor_sha256
        )

        if self.last_rust_process_shadow_result is not None:
            health["rust_process_shadow"]["comparison"] = (
                self.last_rust_process_shadow_result
            )

        # Rust v0.5.1 canary is non-critical and non-authoritative.  Its
        # status is observable, but it can never degrade the core runtime by
        # itself or become ProcessGraph authority in this release.
        if not self.rust_process_canary_enabled:
            health["rust_process_canary"] = {
                "component": "RustProcessCanary",
                "status": "DISABLED",
                "mode": "RUST_CANARY",
                "authoritative": False,
                "authoritative_sensor": "ProcessSensor",
                "promotion_bound": False,
            }
        elif self.rust_process_canary is None:
            health["rust_process_canary"] = {
                "component": "RustProcessCanary",
                "status": "DEGRADED",
                "mode": "RUST_CANARY",
                "authoritative": False,
                "authoritative_sensor": "ProcessSensor",
                "promotion_bound": False,
                "failure_count": self.rust_process_canary_failures,
                "last_error": self.last_rust_process_canary_error,
            }
        else:
            try:
                canary_health = self.rust_process_canary.health_check()
                health["rust_process_canary"] = (
                    canary_health
                    if isinstance(canary_health, dict)
                    else {"status": "INVALID_HEALTH_RESPONSE"}
                )
            except Exception as exc:
                health["rust_process_canary"] = {
                    "component": "RustProcessCanary",
                    "status": "DEGRADED",
                    "mode": "RUST_CANARY",
                    "authoritative": False,
                    "authoritative_sensor": "ProcessSensor",
                    "promotion_bound": False,
                    "error": type(exc).__name__,
                }

        if self.last_rust_process_canary_result is not None:
            health["rust_process_canary"]["last_result"] = (
                self.last_rust_process_canary_result
            )

        # Safety Core is a first-class health surface. It is the local
        # trust boundary and must never appear as UNKNOWN merely because
        # it is not part of the generic component object registry below.
        try:
            safety_health = self.safety.health_snapshot()
            health["safety_core"] = (
                safety_health
                if isinstance(safety_health, dict)
                else {"status": "INVALID_HEALTH_RESPONSE"}
            )
        except Exception as exc:
            health["safety_core"] = {
                "component": "SafetyCore",
                "status": "DEGRADED",
                "error": type(exc).__name__,
            }

        components = {

            "key_manager":
                self.key_manager,

            "replay_guard":
                self.replay_guard,

            "runtime_pipeline":
                self.runtime_pipeline,

            "admission_gateway":
                self.admission_gateway,

            "event_bus":
                self.event_bus,

            "resource_guard":
                self.resource_guard,

            "resource_adapter":
                self.resource_adapter,

            "event_rate_limiter":
                self.event_rate_limiter,

            "backpressure_controller":
                self.backpressure_controller,

            "evidence_retention":
                self.evidence_retention,

            "resource_safety_plane":
                self.resource_safety_plane,

            "resource_delivery_gate":
                self.resource_delivery_gate,

            "spool":
                self.spool,

            "pipeline":
                self.pipeline,

            "correlation_engine":
                self.correlation_engine,

            "correlation_adapter":
                self.correlation_adapter,

            "event_bridge":
                self.event_bridge,

            "observer":
                self.observer,

            "network_inventory":
                self.network_inventory,

            "process_sensor":
                self.process_sensor,

            "process_graph":
                self.process_graph,

            "attack_graph":
                self.attack_graph,

            "risk_engine":
                self.risk_engine,

            "policy_engine":
                self.policy_engine,

            "independent_verifier":
                self.independent_verifier,

            "authorization_gate":
                self.authorization_gate,

            "action_gateway":
                self.action_gateway,

            "blast_radius_guard":
                self.blast_radius_guard,

            "post_action_verifier":
                self.post_action_verifier,

            "recovery_planner":
                self.recovery_planner,

            "detector":
                self.detector,

            "rule_adapter":
                self.rule_adapter,

            "state_manager":
                self.state_manager,

            "logger":
                self.logger,

            "data_repository":
                self.data_repository,

            # Read-only runtime -> dashboard publisher is a real runtime
            # component and must be represented in health snapshots.
            # Without this entry the Owner Master Control component matrix
            # renders Runtime Publisher as UNKNOWN even while state is being
            # published successfully.
            "dashboard_publisher":
                self.dashboard_publisher,
        }

        for name, component in (
            components.items()
        ):

            if component is None:

                health[name] = {
                    "status":
                        "UNAVAILABLE"
                }

                continue

            method = getattr(
                component,
                "health_check",
                None,
            )

            if not callable(method):

                health[name] = {
                    "status":
                        "UNKNOWN"
                }

                continue

            try:

                result = method()

                if not isinstance(
                    result,
                    dict,
                ):
                    health[name] = {
                        "status":
                            "INVALID_HEALTH_RESPONSE"
                    }

                else:

                    health[name] = result

            except Exception as exc:

                health[name] = {
                    "status":
                        "DEGRADED",

                    "error":
                        type(exc).__name__,
                }

        # ----------------------------------------------------
        # Overall health determination
        # ----------------------------------------------------

        critical_components = (
            "key_manager",
            "runtime_pipeline",
            "admission_gateway",
            "resource_guard",
            "resource_safety_plane",
            "resource_delivery_gate",
            "event_bus",
            "spool",
            "pipeline",
            "state_manager",
            "logger",
        )

        critical_failure = False

        for name in critical_components:

            component_health = (
                health.get(
                    name,
                    {},
                )
            )

            if (
                component_health.get(
                    "status"
                )
                != "HEALTHY"
            ):

                critical_failure = True

                break

        persistence_failure = (
            self.state_failures > 0
            or self.logger_failures > 0
        )
        safety_status = str(
            health.get("safety_core", {}).get("status", "UNKNOWN")
        ).upper()
        safety_failure = safety_status not in {"SAFE", "HEALTHY"}

        # Recovery is current health, not a permanent latch derived from a
        # historical failure counter. Preserve all other degradation latches.
        pipeline_health = health.get("pipeline", {})
        recovery_health = pipeline_health.get("recovery", {})
        recovery_active = bool(recovery_health.get("blocked"))
        recovery_only = (
            recovery_active
            and all(health.get(name, {}).get("status") == "HEALTHY"
                    for name in critical_components if name != "pipeline")
            and all(value is None or value.get("status") == "HEALTHY"
                    for value in pipeline_health.get("dependencies", {}).values())
            and pipeline_health.get("admission_binding", {}).get("verifier_bound") is True
        )
        if (critical_failure and not recovery_only) or persistence_failure or safety_failure:
            self.degraded = True

        health["runtime"]["status"] = (
            "DEGRADED"
            if (
                self.degraded
                or critical_failure
            )
            else "HEALTHY"
        )

        return health

    # ========================================================
    # DASHBOARD STATE PUBLICATION
    # ========================================================

    def publish_dashboard_state(
        self,
        observation: dict[str, Any] | None = None,
        incidents: list[dict[str, Any]] | None = None,
    ) -> bool:
        """
        Publish the latest read-only runtime state to the dashboard.

        Security properties:
            - Dashboard never controls the runtime.
            - Publication failure cannot stop the security cycle.
            - State is generated only from runtime-owned data.
            - RuntimeStatePublisher performs the atomic write.
        """

        publisher = self.dashboard_publisher

        if publisher is None:
            return False

        if observation is None:
            observation = self.last_observation or {}

        if incidents is None:
            engine = self.correlation_engine
            incidents = []

            if engine is not None:
                try:
                    result = engine.get_recent_incidents(limit=20)

                    if isinstance(result, list):
                        incidents = result

                except Exception as exc:
                    self.correlation_failures += 1
                    self.component_failures += 1
                    self.last_error = (
                        f"dashboard_incidents:"
                        f"{type(exc).__name__}"
                    )

        try:
            health = self.health_snapshot()

            runtime_health = health.get(
                "runtime",
                {},
            )

            runtime_state = {
                "status": runtime_health.get(
                    "status",
                    "UNKNOWN",
                ),
                "version": runtime_health.get(
                    "version",
                    self.VERSION,
                ),
                "running": self.running,
                "started_at": self.started_at,
                "degraded": self.degraded,
                "mode": self.config.get(
                    "mode",
                    "OBSERVE",
                ),
                "cycle_count": self.cycle_count,
                "cycle_failures": self.cycle_failures,
                "component_failures": (
                    self.component_failures
                ),
                "events_created": (
                    self.events_created
                ),
                "events_admitted": (
                    self.events_admitted
                ),
                "events_rejected": (
                    self.events_rejected
                ),
                "events_acked": (
                    self.events_acked
                ),
                "events_published": (
                    self.events_published
                ),
                "events_persisted_deferred": (
                    self.events_persisted_deferred
                ),
                "recovery_published": (
                    self.recovery_published
                ),
                "last_cycle_started": (
                    self.last_cycle_started
                ),
                "last_cycle_completed": (
                    self.last_cycle_completed
                ),
                "last_cycle_duration": (
                    self.last_cycle_duration
                ),
                "last_error": self.last_error,
                "last_transport_disposition": self.last_transport_disposition,
                "resource_snapshot": (
                    self.resource_safety_plane.get_resource_snapshot()
                    if self.resource_safety_plane is not None
                    else None
                ),
                "attack_graph": self.last_attack_graph_result or {},
                "risk": self.last_risk_result or {},
                "policy": self.last_policy_result or {},
                "verification": self.last_verification_result or {},
                "authorization": self.last_authorization_result or {},
                "action_gateway": self.last_action_result or {},
                "blast_radius": self.last_blast_radius_result or {},
                "post_action_verification": self.last_post_action_verification_result or {},
                "response_recovery": self.last_response_recovery_result or {},
                "response_lifecycle": self.last_response_lifecycle_result or {},
                "process_inventory": list(self.last_process_inventory[:18]),
                "network_inventory": (
                    dict(self.last_network_inventory)
                    if isinstance(self.last_network_inventory, dict)
                    else {}
                ),
            }

            
            runtime_state["started_at"] = float(
                self.started_at
            )

            runtime_state["running"] = bool(
                self.running
            )

            result = publisher.publish(
                runtime=runtime_state,
                health=health,
                observation=observation,
                incidents=incidents,
            )

            if not result:
                self.component_failures += 1
                return False

            return True

        except Exception as exc:
            self.component_failures += 1
            self.last_error = (
                f"dashboard_publish:"
                f"{type(exc).__name__}"
            )

            # Dashboard is observability only.
            # Never degrade the security runtime solely because
            # the dashboard publication failed.
            return False

    # ========================================================
    # PRINT HEALTH
    # ========================================================

    def print_health(
        self,
    ) -> None:

        health = (
            self.health_snapshot()
        )

        runtime_health = health.get(
            "runtime",
            {},
        )

        print()
        print(
            "Runtime Health:"
        )

        print(
            f"Version: "
            f"{runtime_health.get('version')}"
        )

        print(
            f"Status: "
            f"{runtime_health.get('status')}"
        )

        print(
            f"Cycles: "
            f"{runtime_health.get('cycle_count')}"
        )

        print(
            f"Created: "
            f"{runtime_health.get('events_created')}"
        )

        print(
            f"Admitted: "
            f"{runtime_health.get('events_admitted')}"
        )

        print(
            f"Rejected: "
            f"{runtime_health.get('events_rejected')}"
        )

        print(
            f"ACKed: "
            f"{runtime_health.get('events_acked')}"
        )

        print(
            f"Recovery published: "
            f"{runtime_health.get('recovery_published')}"
        )

        print(
            f"Component failures: "
            f"{runtime_health.get('component_failures')}"
        )

        runtime_pipeline = (
            health.get(
                "runtime_pipeline",
                {},
            )
        )

        print(
            "Security Pipeline: "
            f"{runtime_pipeline.get('status', 'UNKNOWN')}"
        )

        gateway = (
            health.get(
                "admission_gateway",
                {},
            )
        )

        print(
            "Crypto Admission: "
            f"{gateway.get('status', 'UNKNOWN')}"
        )

        replay = (
            health.get(
                "replay_guard",
                {},
            )
        )

        print(
            "Replay Guard: "
            f"{replay.get('status', 'UNKNOWN')}"
        )

        spool = (
            health.get(
                "spool",
                {},
            )
        )

        print(
            "Durable Spool: "
            f"{spool.get('status', 'UNKNOWN')}"
        )

        data_repository = health.get(
            "data_repository",
            {},
        )
        print(
            "Structured Data: "
            f"{data_repository.get('status', 'UNKNOWN')}"
        )

    # ========================================================
    # START
    # ========================================================

    def begin_managed_loop(self) -> None:
        """Mark the runtime active when an external host owns the cycle loop.

        Windows Service hosting uses ServiceRunner rather than start() so SCM
        can own stop signalling.  This method only updates lifecycle state; it
        does not execute a cycle and never grants privileged authorization.
        """
        self.running = True
        self.shutdown_requested = False

    def start(
        self,
    ) -> None:
        """
        Start runtime.

        Supports:

            CYBERDEFENDER_ONESHOT=1

        for deterministic testing.

        Default:

            continuous runtime
        """

        if self.running:
            return

        self.running = True
        self.shutdown_requested = False

        interval = (
            self._loop_interval()
        )

        oneshot = (
            os.getenv(
                "CYBERDEFENDER_ONESHOT",
                "",
            )
            .strip()
            .lower()
            in {
                "1",
                "true",
                "yes",
                "on",
            }
        )

        print()
        print(
            "=========================================="
        )

        print(
            " CyberDefender Hardened Runtime"
        )

        print(
            f" Version: {self.VERSION}"
        )

        print(
            " Security-First / Fail-Safe"
        )

        print(
            " P11.20 Runtime Orchestrator"
        )

        print(
            "=========================================="
        )

        print(
            f"Loop interval: {interval}s"
        )

        print(
            f"Mode: "
            f"{self.config.get('mode')}"
        )

        print(
            "Execution: "
            f"{'ONE-SHOT' if oneshot else '24/7'}"
        )

        while self.running:

            cycle_started = (
                time.monotonic()
            )

            try:

                self.run_cycle()

            except KeyboardInterrupt:

                raise

            except Exception as exc:

                self.cycle_failures += 1
                self.component_failures += 1

                self.degraded = True

                self.last_error = (
                    f"cycle:"
                    f"{type(exc).__name__}"
                )

                try:

                    self.safety.enter_safe_mode(
                        "Runtime cycle failure: "
                        f"{type(exc).__name__}: "
                        f"{exc}"
                    )

                except Exception:
                    pass

                print()
                print(
                    "RUNTIME CYCLE FAILURE"
                )

                print(
                    f"Type: "
                    f"{type(exc).__name__}"
                )

                print(
                    "Fail-safe mode engaged."
                )

                if oneshot:
                    break

            if oneshot:
                break

            elapsed = (
                time.monotonic()
                - cycle_started
            )

            remaining = (
                interval
                - elapsed
            )

            if remaining > 0:

                try:

                    time.sleep(
                        remaining
                    )

                except KeyboardInterrupt:

                    raise

        self.running = False

    # ========================================================
    # COMPONENT CLOSE
    # ========================================================

    def close(self) -> None:
        """Release runtime-owned external resources deterministically.

        This method is idempotent and intentionally safe to call from normal
        shutdown, test cleanup, or exception paths.
        """
        canary = self.rust_process_canary
        if canary is not None:
            try:
                canary.close()
                self.rust_process_canary = None
                self.child_cleanup_verified = True
            except Exception:
                # Retain ownership; caller may keep Python alive but cannot
                # create another native owner until exit is verified.
                self.child_cleanup_verified = False

        network_inventory = self.network_inventory
        self.network_inventory = None
        if network_inventory is not None:
            try:
                network_inventory.close()
            except Exception:
                # Optional read-only telemetry must never block shutdown.
                pass

        repository = self.data_repository
        self.data_repository = None
        if repository is not None:
            try:
                repository.close()
            except Exception:
                # Shutdown must remain fail-safe even if an optional
                # non-authoritative read-model reports a close error.
                pass

    def __enter__(self) -> "CyberDefenderRuntime":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ========================================================
    # STOP
    # ========================================================

     # ========================================================
    # STOP
    # ========================================================

    def stop(
        self,
        reason: str = (
            "Runtime shutdown"
        ),
    ) -> None:

        self.shutdown_requested = True
        self.running = False

        try:

            self.safety.enter_safe_mode(
                reason
            )

        except Exception:
            pass

        # ----------------------------------------------------
        # FINAL DASHBOARD SNAPSHOT
        # ----------------------------------------------------
        # The runtime is already stopped at this point.
        # Publish the final authoritative state so the
        # dashboard cannot continue reporting running=True.
        try:

            self.publish_dashboard_state(
                observation=self.last_observation,
            )

        except Exception:

            # Dashboard publication must NEVER prevent
            # safe shutdown.
            pass

        self.close()

# ============================================================
# CONFIGURATION
# ============================================================

def _load_runtime_config(
    safety: SafetyCore,
) -> dict[str, Any] | None:

    try:

        config = load_config()

    except ConfigError as exc:

        try:
            safety.enter_safe_mode(
                f"Config xatosi: {exc}"
            )
        except Exception:
            pass

        print(
            f"CONFIG ERROR: {exc}"
        )

        return None

    if not isinstance(
        config,
        dict,
    ):

        try:
            safety.enter_safe_mode(
                "Config object invalid."
            )
        except Exception:
            pass

        return None

    if config.get(
        "enabled"
    ) is not True:

        try:
            safety.enter_safe_mode(
                "CyberDefender disabled."
            )
        except Exception:
            pass

        print(
            "CyberDefender disabled."
        )

        return None

    safety_config = config.get(
        "safety",
        {},
    )

    if not isinstance(
        safety_config,
        dict,
    ):

        try:
            safety.enter_safe_mode(
                "Safety config invalid."
            )
        except Exception:
            pass

        return None

    if safety_config.get(
        "fail_safe"
    ) is not True:

        try:
            safety.enter_safe_mode(
                "Fail-safe disabled."
            )
        except Exception:
            pass

        print(
            "Fail-safe configuration "
            "must remain enabled."
        )

        return None

    # --------------------------------------------------------
    # Current autonomous mode restriction
    # --------------------------------------------------------

    if config.get(
        "mode"
    ) != "OBSERVE":

        try:
            safety.enter_safe_mode(
                "Only OBSERVE mode currently "
                "allowed."
            )
        except Exception:
            pass

        print(
            "Only OBSERVE mode is currently "
            "allowed."
        )

        return None

    return config


def build_managed_runtime(*, allow_optional_sensors: bool = True) -> "CyberDefenderRuntime":
    """Build a runtime for an external lifecycle owner such as Windows SCM.

    This is the canonical non-interactive bootstrap path.  It preserves the
    same fail-safe configuration and critical-component health gates used by
    the interactive main() entry point, but it does not start an internal
    loop.  The caller owns the loop and shutdown lifecycle.
    """
    safety = SafetyCore()
    runtime: CyberDefenderRuntime | None = None
    try:
        config = _load_runtime_config(safety)
        if config is None:
            raise RuntimeBootstrapError(
                "Managed runtime configuration rejected by fail-safe bootstrap."
            )

        runtime = CyberDefenderRuntime(safety, config, allow_optional_sensors=allow_optional_sensors)
        health = runtime.health_snapshot()
        runtime_health = health.get("runtime", {}) if isinstance(health, dict) else {}
        if runtime_health.get("status") != "HEALTHY":
            try:
                safety.enter_safe_mode("Managed runtime initial health gate failed.")
            except Exception:
                pass
            raise RuntimeBootstrapError("Managed runtime initial health gate failed.")

        for component_name in (
            "key_manager",
            "runtime_pipeline",
            "admission_gateway",
            "spool",
            "pipeline",
        ):
            component_health = health.get(component_name, {})
            if not isinstance(component_health, dict) or component_health.get("status") != "HEALTHY":
                try:
                    safety.enter_safe_mode(
                        f"Managed critical component {component_name} HEALTHY emas."
                    )
                except Exception:
                    pass
                raise RuntimeBootstrapError(
                    f"Managed critical health gate failed: {component_name}"
                )

        return runtime
    except Exception:
        if runtime is not None:
            try:
                runtime.close()
            except Exception:
                pass
        raise


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    safety = SafetyCore()

    runtime: CyberDefenderRuntime | None = None

    try:

        # ====================================================
        # CONFIG
        # ====================================================

        config = (
            _load_runtime_config(
                safety
            )
        )

        if config is None:
            return

        # ====================================================
        # STARTUP INFORMATION
        # ====================================================

        print()
        print(
            "CyberDefender Agent starting..."
        )

        print(
            f"Mode: "
            f"{config.get('mode')}"
        )

        print(
            f"Enabled: "
            f"{config.get('enabled')}"
        )

        print(
            "Fail-safe: "
            f"{config.get('safety', {}).get('fail_safe')}"
        )

        print()
        print(
            "Safety Core:"
        )

        print(
            "System modification: "
            f"{safety.can_modify_system()}"
        )

        print(
            "Firewall modification: "
            f"{safety.can_modify_firewall()}"
        )

        print(
            "Registry modification: "
            f"{safety.can_modify_registry()}"
        )

        print(
            "Service modification: "
            f"{safety.can_modify_services()}"
        )

        # ====================================================
        # RUNTIME BOOTSTRAP
        # ====================================================

        runtime = (
            CyberDefenderRuntime(
                safety,
                config,
            )
        )

        # ====================================================
        # INITIAL HEALTH GATE
        # ====================================================

        health = (
            runtime.health_snapshot()
        )

        runtime_health = (
            health.get(
                "runtime",
                {},
            )
        )

        if (
            runtime_health.get(
                "status"
            )
            != "HEALTHY"
        ):

            safety.enter_safe_mode(
                "Runtime initial health "
                "gate failed."
            )

            print(
                "Runtime initial health "
                "gate FAILED."
            )

            return

        # ----------------------------------------------------
        # Critical components must be healthy
        # ----------------------------------------------------

        critical_components = (
            "key_manager",
            "runtime_pipeline",
            "admission_gateway",
            "spool",
            "pipeline",
        )

        for component_name in (
            critical_components
        ):

            component_health = (
                health.get(
                    component_name,
                    {},
                )
            )

            if (
                component_health.get(
                    "status"
                )
                != "HEALTHY"
            ):

                safety.enter_safe_mode(
                    "Critical component "
                    f"{component_name} "
                    "HEALTHY emas."
                )

                print(
                    "CRITICAL HEALTH GATE FAILED:"
                    f" {component_name}"
                )

                return

        # ====================================================
        # START
        # ====================================================

        runtime.start()

    except KeyboardInterrupt:

        print()
        print(
            "CyberDefender shutdown requested "
            "by operator."
        )

        try:

            safety.enter_safe_mode(
                "Agent interrupted by operator"
            )

        except Exception:
            pass

        if runtime is not None:

            runtime.stop(
                "Operator shutdown"
            )

    except RuntimeBootstrapError as exc:

        print()
        print(
            "CYBERDEFENDER BOOTSTRAP FAILURE"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        try:

            safety.enter_safe_mode(
                f"Runtime bootstrap failure: "
                f"{exc}"
            )

        except Exception:
            pass

    except ConfigError as exc:

        print()
        print(
            "CYBERDEFENDER CONFIGURATION FAILURE"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        try:

            safety.enter_safe_mode(
                f"Configuration failure: "
                f"{exc}"
            )

        except Exception:
            pass

    except Exception as exc:

        print()
        print(
            "CYBERDEFENDER UNEXPECTED RUNTIME FAILURE"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        try:

            safety.enter_safe_mode(
                "Unexpected runtime failure: "
                f"{type(exc).__name__}: "
                f"{exc}"
            )

        except Exception:
            pass

    finally:

        # ====================================================
        # FINAL SAFE SHUTDOWN
        # ====================================================

        if runtime is not None:

            runtime.running = False
            runtime.close()

        try:

            safety.enter_safe_mode(
                "Runtime termination safety state"
            )

        except Exception:
            pass


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()




