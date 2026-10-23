# Rust release provenance — 2026-10-23

This record covers the isolated Windows x64 build of the process sensor. It is
source provenance only; no live service or endpoint was changed.

## Pinned inputs

- Git commit: `16782f0d9cfa97fb45b070c5124dc0c724f26ede`
- Packaging commit containing the verified binary: `531130b12c600b9f4646d97618fd021a5f76de07` (parent of this documentation update)
- Toolchain: Rust `1.98.1`, target `x86_64-pc-windows-msvc`
- Lock mode: `cargo build --locked --release`
- Reproducible link flag: MSVC `/Brepro`, configured in `.cargo/config.toml`
- Toolchain pin: `rust-toolchain.toml`
- Process sensor `Cargo.lock`: package-only, no third-party crates
- PSI v0.1/v0.2 `Cargo.lock`: package-only, no third-party crates

## A/B result

Two clean isolated builds from the same commit and pinned inputs produced the
same process-sensor executable:

`a8a8a4add316fd061901e7a8094daf0262dddd2fed1ebb948ce871d935746b44`

Size: `195584` bytes. A/B byte comparison: PASS. PE format: Windows x64
COFF executable. The executable is currently unsigned (`Authenticode:
NotSigned`); signing remains an external release prerequisite.

Commands used:

```text
cargo build --locked --release --target-dir <isolated-target-A>
cargo build --locked --release --target-dir <isolated-target-B>
```

The binary may be included in the candidate only with this exact hash and the
matching source/toolchain provenance. No deployment or service operation was
performed.

