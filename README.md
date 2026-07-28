# ZedHub Connector

`ZedHub Connector` is the outbound connector runtime that connects a local
Home Assistant installation to ZedIoT Core.

## Release identities

| Surface | Identifier |
|---|---|
| Product | `ZedHub Connector` |
| Home Assistant store name | `ZedIoT Hub Connector` |
| Repository | `zediot-hub-connector` |
| Home Assistant app slug | `zediot_hub_connector` |
| Python package | `zediot_ha_hub_connector` |
| Container service | `zediot-hub-connector` |
| IoT Core profile key | `home_assistant` |

## Status

HUB-02 implementation candidate. The repository now contains a Home Assistant
App manifest, Supervisor WebSocket snapshot/event client, key-bound Core
session client, bounded SQLite store-and-forward queue, low-frequency
reconciliation, runtime heartbeat/lease and bounded retry/circuit breaker.

Local focused tests are required before publishing an installable image. Live
Home Assistant and IoT Core approval/session smoke remains a separate gate.

## Responsibilities

The connector owns:

- local Home Assistant discovery and event subscription;
- an outbound authenticated session to IoT Core;
- a bounded store-and-forward queue;
- allowlisted local command execution;
- short-lived local rule package execution.

The connector does not own:

- IoT Core tenants, roles, grants, mappings, or final audit truth;
- final presence, latest-state, command, or rule status;
- provider-specific Tuya/GHE identity and protocol behavior;
- arbitrary Home Assistant service execution;
- long-term telemetry storage.

See [docs/architecture-boundary.md](docs/architecture-boundary.md) for the
repository boundary.

## Planned distribution

- Home Assistant OS: third-party Home Assistant app repository.
- Home Assistant Container or managed Linux: standalone Docker image using the
  same Python runtime.
- Architectures: `amd64` and `aarch64`.

Pre-built images are not published until Core contract, multi-architecture
build, revoke and live fault-smoke gates pass.

## Runtime contract

- HA access uses `homeassistant_api: true` and the local `SUPERVISOR_TOKEN`.
- The token is never sent to Core or written to the queue.
- Pairing input is a self-contained one-time code returned by IoT Core.
- Incremental `state_changed` events use a durable monotonic sequence.
- The queue is bounded by both 24 hours and 100 MiB; dropped rows are counted.
- Full reconciliation defaults to every 6 hours and can be configured only
  within 6–24 hours.
- Core retries are bounded and protected by a closed/open/half-open circuit
  breaker.
