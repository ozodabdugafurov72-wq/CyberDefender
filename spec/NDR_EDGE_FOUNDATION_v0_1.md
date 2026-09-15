# CyberDefender Go NDR Edge Foundation v0.1

This milestone is a **bounded synthetic metadata feature accumulator**, not a live packet collector.

## Purpose

Prepare the concurrency/bounded-state edge layer that can later sit before language-neutral evidence transport and the Rust PSI core.

## Current restrictions

- accepts only `TrustLevel = SYNTHETIC`
- accepts only `Mode = SYNTHETIC`
- requires `Authorization = NOT_GRANTED`
- no packet capture
- no raw packet parsing
- no sockets
- no firewall/routing changes
- no process or host actuator
- no automatic response

## Bounded state

- max observations: 512
- max sources: 64
- max evidence references per snapshot: 16
- max active window: 24 hours
- duplicate active-window identity is rejected
- capacity exhaustion fails closed rather than silently expanding memory

## Output

The feature snapshot contains observation count, unique targets, unique ports, failure ratio, span, recent burst count, a low-and-slow feature and bounded evidence references.

A snapshot is not a detection, not a risk score and not an authorization.
