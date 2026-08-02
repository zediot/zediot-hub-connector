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

The repository contains one shared runtime with two distribution profiles:

- Home Assistant OS/Supervised app using the local Supervisor API;
- Home Assistant Container/managed Linux companion container using a
  read-only long-lived-token file.

Pairing, session, bounded replay, command receipt and local rule focused tests
are required before publishing a versioned multi-architecture image. Internal
Home Assistant Container enrollment/session/uplink smoke has passed; anonymous
repository and registry access remains the public-release gate.

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

## Distribution

- Home Assistant OS/Supervised: third-party Home Assistant app repository.
- Home Assistant Container or managed Linux: standalone Docker image using the
  same Python runtime.
- Architectures: `amd64` and `aarch64`.

The Home Assistant app consumes versioned images from the project registry.
The registry and repository must be anonymously readable before giving the
repository URL to ordinary users.

## Runtime contract

- HA OS/Supervised access uses `homeassistant_api: true` and the local
  `SUPERVISOR_TOKEN`.
- HA Container access uses `ZEDIOT_HA_TOKEN_FILE`; the token must be mounted
  read-only and must not be placed in an environment variable.
- The token is never sent to Core or written to the queue.
- Pairing input is a self-contained one-time code returned by IoT Core.
- Incremental `state_changed` events use a durable monotonic sequence.
- The queue is bounded by both 24 hours and 100 MiB. Capacity overflow rejects
  the new item without breaking the acknowledged sequence prefix; age expiry
  clears the non-replayable tail back to the last Core ACK cursor. Both paths
  increment dropped evidence and schedule a full reconciliation snapshot.
- Full reconciliation defaults to every 6 hours and can be configured only
  within 6–24 hours.
- Core retries are bounded and protected by a closed/open/half-open circuit
  breaker.
