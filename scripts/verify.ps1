$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "runtime_env.ps1")
Set-Location $ProjectRoot

Write-Host "=== import preflight ==="
& $VenvPython -c "import agent; from agent.main import CyberDefenderRuntime; print('agent import OK | Runtime', CyberDefenderRuntime.VERSION)"
if ($LASTEXITCODE -ne 0) { throw "FAILED: Python project import preflight" }

$Tests = @(
    "tests\test_state_root_isolation_v1.py",
    "tests\test_sqlite_bootstrap_cleanup_v1.py",
    "tests\test_state_failure_health_v1.py",
    "tests\test_recovery_rejection_rollback_v1.py",
    "tests\test_recovery_full_traversal_v1.py",
    "tests\test_eventbus_v2_4_priority_fairness_v1_0.py",
    "tests\test_eventbus_v2_4_shutdown_race_v1_1.py",
    "test_main_full_runtime_traversal_v1.py",
    "tests\test_process_graph_coverage_aware_v1.py",
    "tests\test_process_sensor_authority_foundation_v1.py",
    "tests\test_process_sensor_authority_runtime_integration_v1.py",
    "tests\test_process_sensor_runtime_config_v1.py",
    "tests\test_rust_process_v05_wire_contract_v1.py",
    "tests\test_rust_process_enrichment_parity_v1.py",
    "tests\test_native_process_supervisor_contract_v1.py",
    "tests\test_rust_process_canary_contract_v1.py",
    "tests\test_process_sensor_canary_runtime_integration_v1.py",
    "test_main_correlation_ownership_v1_5.py",
    "test_owner_master_control_v3.py",
    "tests\test_owner_dashboard_runtime_contract_v3_5.py",
    "tests\test_owner_admin_sensor_plane_v1.py",
    "tests\test_owner_dashboard_bounded_log_tail_v1.py",
    "tests\test_event_logger_rotation_retention_v1.py",
    "tests\test_correlation_evidence_compaction_v1.py",
    "tests\test_resource_incident_coalescing_v1.py",
    "tests\test_owner_control_semantics_v3_5.py",
    "tests\test_owner_dashboard_rotated_log_tail_v1.py",
    "tests\test_sqlite_data_foundation_v1.py",
    "tests\test_sqlite_runtime_integration_v1.py",
    "tests\test_sqlite_failure_isolation_v1.py",
    "tests\test_demo_operations_read_model_v1.py",
    "tests\test_demo_scenario_safety_v1.py",
    "tests\test_owner_demo_operations_api_v3_5.py",
    "tests\test_owner_demo_ui_contract_v1.py",
    "tests\test_service_runner_lifecycle_v1.py",
    "tests\test_service_managed_runtime_integration_v1_1.py",
    "tests\test_service_runner_resilience_v1_1.py",
    "tests\test_distribution_repository_v1.py",
    "tests\test_distribution_http_integration_v1.py",
    "tests\test_owner_fleet_contract_v3_5.py",
    "tests\test_windows_service_foundation_v1.py",
    "tests\test_machine_installer_fail_closed_v1.py",
    "tests\test_direct_service_host_contract_v1.py",
    "tests\test_owner_fleet_ui_contract_v1.py",
    "tests\test_process_display_v1.py",
    "tests\test_presentation_dashboard_contract_v1.py"
)

foreach ($Test in $Tests) {
    Write-Host "=== $Test ==="
    & $VenvPython $Test
    if ($LASTEXITCODE -ne 0) { throw "FAILED: $Test" }
}
Write-Host "All release-gate tests PASS."
