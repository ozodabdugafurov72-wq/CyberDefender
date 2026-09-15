# CyberDefender NDR Edge Foundation v0.2

Status: **synthetic-only bounded metadata aggregation**.

## Purpose

Prepare a high-concurrency, bounded edge feature layer for the PSI multi-window model while keeping live network authority disabled.

## Fixed windows

The edge emits bounded feature snapshots for `5s / 30s / 5m / 1h / 6h / 24h`.

## Current restrictions

- accepts only `TrustLevel = SYNTHETIC`
- accepts only `Mode = SYNTHETIC`
- requires `Authorization = NOT_GRANTED`
- no live packet capture
- no raw packet parsing
- no sockets
- no firewall/routing changes
- no process or host actuator
- no automatic response

## Bounded state

- max observations: 2048
- max sources: 128
- max evidence references per window: 24
- max active horizon: 24 hours
- duplicate event identity is rejected across the active horizon
- capacity exhaustion fails closed
- state is protected by a mutex for concurrent synthetic producers

## Low-and-slow preservation

Short windows do not erase sparse long-horizon behavior. `LongHorizonOnly` is emitted when the 1-hour view contains at least three observations while the 30-second view contains at most one. A per-window `LowAndSlow` feature requires span >= 120 seconds with no more than one event in the last 5 seconds.

## Output discipline

A snapshot is not a detection, not a threat probability, not a risk score, and not an authorization. `Authorization = NOT_GRANTED` and live capture remains `DISABLED`.
