# H1D9 university dependencies

This package contains source and the pinned Rust 0.5.1 release executable. It is not an offline Windows installer bundle. No production state, virtual environment, guard key or fleet credential is included.

Required target: staff-designated disposable Windows 11 x64 build 26100 or newer, NTFS C: with at least 20 GiB free, 8 GiB RAM with 3 GiB available, elevated staff-approved shell, Python 3.13+ x64, Windows PowerShell 5.1, loopback ports 8775/8785 free. Prefer a VM with a verified full checkpoint and isolated networking; a physical university lab machine requires explicit staff permission, no unrelated data and a proven recovery image. Protected HP host and personal Acer models are denied.

Actual requirements.txt: psutil 7.2.2; cryptography 50.0.2; pywin32 312 on Windows. These exact pins replace the former cryptography 46.x range, which is affected by published 2026 advisories. Local development verification used Python 3.14; the requirements file is authoritative for dependency versions. The installer creates a fresh venv, upgrades pip and installs requirements. It also needs transitive wheels (including cffi/pycparser as selected by pip), compatible Windows x64 ABI wheels and any runtime prerequisites of the selected trusted Python/pywin32/cryptography builds. Cargo is not needed merely to install the packaged release binary; cargo tests require a trusted Rust toolchain and its cached dependencies.

No trusted complete offline Python installer/wheel bundle was found on this host. **Offline installation is BLOCKED until staff prepare and validate one.** Do not copy the development venv. Obtain Python and dependencies through the university's approved software channel, verify publisher signatures and staff-pinned SHA-256 inventories. No such download or installation has been performed by this preparation task.

For an offline lab, staff must include pip itself (the installer upgrades it), all requirements and transitive wheels for the exact target Python version. On the disposable target only, set PIP_NO_INDEX=1 and PIP_FIND_LINKS to that verified wheel directory for the installation shell. Prove a clean venv install with network disconnected before declaring DependenciesReady. Keep wheel inventory/version/hash evidence outside the VM checkpoint. For online preparation, use approved controlled egress, then isolate before fault tests; do not bridge to university/production networks.

Read-only checks in the lab shell:

```powershell
& $Python -c 'import sys,struct,ssl; print(sys.version); assert sys.version_info >= (3,13) and struct.calcsize("P")==8'
& $Python -c 'import psutil,cryptography,win32api; print(psutil.__version__,cryptography.__version__)'
& $Python -m pip check
```

Do not infer dependency readiness from imports on the production host. A preflight WARN requires staff review; it is not permission to enable Windows features, change execution policy, boot settings or install virtualization software.
