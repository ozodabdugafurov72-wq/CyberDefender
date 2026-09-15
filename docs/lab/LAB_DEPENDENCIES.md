# Dependency preparation

READY_LOCALLY: requirements and platform rules are documented in [H1D9_LAB_DEPENDENCIES.md](../H1D9_LAB_DEPENDENCIES.md). Actual requirements: psutil >=7.2,<8; cryptography >=46,<47; pywin32 >=310 on Windows. Target Python must be approved x64 Python 3.13+; local source testing uses the existing 3.14 environment. Windows PowerShell 5.1 is required by the existing runbook. The preserved package carries the pinned Rust release binary; Cargo is only needed for source Rust tests.

EXTERNAL_PREREQUISITE — UNRESOLVED: no independently verified complete offline Python installer/wheel bundle is available as a sprint deliverable. Do not copy the development venv or claim local imports prove an offline installation will succeed.

EXTERNAL_PREREQUISITE: staff supply the trusted Python installer, compatible wheels for all direct/transitive requirements and pip itself (the installer upgrades pip). Verify publisher provenance/signatures and keep exact versions and SHA-256 inventory outside guest checkpoints. Follow approved software procurement; this sprint downloads or installs nothing.

UNVERIFIED_UNTIL_LAB: in a disposable clean environment, prove the complete installation with networking disconnected and PIP_NO_INDEX=1 / PIP_FIND_LINKS set to the verified bundle for that installation shell. Record pip check and safe version output. Do not bypass script-signing or execution policy; resolve policy prerequisites through staff.
