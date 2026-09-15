# Proposed isolated topology

EXTERNAL_PREREQUISITE: staff choose a private switch or isolated VLAN with no uplink or bridge to university/production networks. Verify that the example range below does not overlap local routing before adoption. This document configures nothing.

| Role | Proposed static address | Status |
|---|---|---|
| Staff evidence station / controller, optional | 10.77.45.2/28 | EXTERNAL_PREREQUISITE |
| Disposable target A | 10.77.45.3/28 | EXTERNAL_PREREQUISITE |
| Disposable targets B–D | 10.77.45.4–6/28 | EXTERNAL_PREREQUISITE |
| DHCP, DNS and default gateway | None during isolated test phase | EXTERNAL_PREREQUISITE |

With two machines, use one evidence station and one disposable target. With five, add three targets; serialize fault branches. Local CyberDefender HTTP endpoints remain loopback-only according to the existing installer; this plan does not expose them over the VLAN.

EXTERNAL_PREREQUISITE: internet is disabled during faults. If dependency preparation requires egress, staff use a separately authorized staging phase, then disconnect and verify isolation. Approved removable media may transfer signed/hash-verified dependencies and sanitized evidence. Do not forward credentials or use shared production folders.

UNVERIFIED_UNTIL_LAB: record actual interface/IP/switch membership and isolation checks. Do not treat a proposed subnet as evidence that isolation exists.
