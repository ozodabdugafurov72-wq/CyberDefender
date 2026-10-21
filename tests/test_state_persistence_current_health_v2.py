from agent.main import CyberDefenderRuntime


active = CyberDefenderRuntime._persistence_failure_active


# Historical runtime counters remain visible evidence, but current persistence
# health is authoritative for whether the runtime is actively degraded.
assert active(
    health={"state_manager": {"status": "HEALTHY"}},
    logger_failures=0,
) is False

# Missing or non-healthy state health remains fail-closed.
assert active(health={}, logger_failures=0) is True
assert active(
    health={"state_manager": {"status": "DEGRADED"}},
    logger_failures=0,
) is True

# Logger persistence failures retain their existing fail-closed behavior.
assert active(
    health={"state_manager": {"status": "HEALTHY"}},
    logger_failures=1,
) is True

print("STATE_PERSISTENCE_CURRENT_HEALTH_V2=PASS")
