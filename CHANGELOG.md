# Changelog

## Unreleased

## 0.2.1

- Preserve the acknowledged uplink sequence during queue capacity and age
  pressure, record dropped evidence, and schedule reconciliation instead of
  creating an unrecoverable Core cursor gap.
- Allow an enrolled Connector to restart after its one-time pairing-code file
  has been consumed, while keeping the Home Assistant token fail-closed.
- Repair persisted queue tails that conflict with the authoritative Core cursor
  during startup and schedule a full reconciliation snapshot.
- Re-establish inactive, stale-generation, or expired Hub sessions without
  restarting the Connector, while leaving sequence-gap conflicts fail-closed.
- Bound state-event upload batches to a configurable 1–100 events, defaulting
  to 50, so Core projection completes within the HTTP request budget.
- Call Home Assistant services without requesting response data, allowing
  non-response actions such as light turn-on/turn-off to ACK successfully.

## 0.2.0

- Support one runtime in two installation profiles: Home Assistant OS/Supervised
  Add-on and Home Assistant Container standalone companion.
- Read standalone Home Assistant and pairing credentials from mounted secret
  files instead of environment values.
- Auto-generate and persist an installation ID when users do not provide one.
- Publish versioned amd64 and aarch64 Add-on images from signed version tags.

## 0.1.0

- Bootstrap the independent ZedHub Connector repository.
- Freeze Home Assistant app, Python package, container, and Core profile
  identifiers.
