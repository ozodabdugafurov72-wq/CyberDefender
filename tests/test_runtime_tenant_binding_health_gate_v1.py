from agent.main import CyberDefenderRuntime


resolve = CyberDefenderRuntime._resolve_degraded_state


# Tenantless records remain pending and unacknowledged.  A non-zero pending
# count is therefore an active health failure, even when all other components
# report healthy and no current error string is present.
assert resolve(
    current_degraded=False,
    active_degradation=False,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
    tenant_binding_pending=1,
) is True

assert resolve(
    current_degraded=False,
    active_degradation=False,
    cycle_failures=0,
    component_failures=0,
    last_error=None,
    tenant_binding_pending=0,
) is False

print("RUNTIME_TENANT_BINDING_HEALTH_GATE=PASS")
