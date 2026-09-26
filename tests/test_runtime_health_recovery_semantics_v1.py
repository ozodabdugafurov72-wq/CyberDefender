from agent.main import CyberDefenderRuntime


resolve = CyberDefenderRuntime._resolve_degraded_state


# Active security/health degradation must always remain degraded.
assert resolve(
    current_degraded=False,
    active_degradation=True,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
) is True

assert resolve(
    current_degraded=True,
    active_degradation=True,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
) is True


# Confirmed stale transient latch may recover.
assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
) is False


# Do NOT clear if current runtime evidence still reports failures.
assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=1,
    component_failures=0,
    last_error=None,
) is True

assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=0,
    component_failures=1,
    last_error=None,
) is True

assert resolve(
    current_degraded=True,
    active_degradation=False,
    cycle_failures=0,
    component_failures=0,
    last_error="CURRENT_RUNTIME_ERROR",
) is True


# Healthy runtime remains healthy.
assert resolve(
    current_degraded=False,
    active_degradation=False,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
) is False


print("RUNTIME_HEALTH_RECOVERY_SEMANTICS=PASS")
