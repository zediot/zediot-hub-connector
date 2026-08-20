# ZedHub Connector

`ZedHub Connector` is the outbound connector runtime that connects a local
Home Assistant installation to ZedIoT Core.

## Release identities

| Surface | Identifier |
|---|---|
| Product | `ZedHub Connector` |
| Home Assistant store name | `ZedIoT Hub Connector` |
| Public repository | `github.com/zediot/zediot-hub-connector` |
| Home Assistant app slug | `zediot_hub_connector` |
| Python package | `zediot_ha_hub_connector` |
| Container service | `zediot-hub-connector` |
| IoT Core profile key | `home_assistant` |

## Status

The repository contains one shared runtime with two distribution profiles:

- Home Assistant OS/Supervised app using the local Supervisor API;
- Home Assistant Container/managed Linux companion container using a
  read-only long-lived-token file.

Pairing, session recovery, bounded replay, command receipt and local rule
focused tests are required before publishing a versioned multi-architecture
image. Internal Home Assistant Container enrollment/session/uplink smoke must
pass together with anonymous repository and registry access.

The GitLab development pipeline and public GitHub pipeline both install the
package with its `test` extra and run the pytest suite before any tagged image
job. Distribution metadata tests keep the package, app manifest, standalone
Compose and environment example on the same version.

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

- Home Assistant OS/Supervised: public third-party Home Assistant app
  repository at `https://github.com/zediot/zediot-hub-connector`.
- Home Assistant Container or managed Linux: standalone Docker image using the
  same Python runtime.
- Architectures: `amd64` and `aarch64`.

The Home Assistant app consumes versioned per-architecture images from GHCR:
`ghcr.io/zediot/amd64-zediot-hub-connector` and
`ghcr.io/zediot/aarch64-zediot-hub-connector`. The standalone profile consumes
the multi-architecture `ghcr.io/zediot/zediot-hub-connector` image. All three
packages and the GitHub repository must be anonymously readable before giving
the repository URL to ordinary users.

Private GitLab remains the development source of truth. Only reviewed release
commits and tags are mirrored to GitHub; public GitHub changes must not create
a second development truth source.

## Runtime contract

- HA OS/Supervised access uses `homeassistant_api: true` and the local
  `SUPERVISOR_TOKEN`.
- HA Container access uses `ZEDIOT_HA_TOKEN_FILE`; the token must be mounted
  read-only and must not be placed in an environment variable.
- The token is never sent to Core or written to the queue.
- Pairing input is a self-contained one-time code returned by IoT Core.
- The pairing code is required only until a connector identity is persisted;
  an enrolled Connector must restart with the consumed code file empty.
- IoT Core is the authority for session `effective_grants`. The Connector starts
  only the inventory, state, command, and local-rule loops allowed by that set;
  a missing field is fail-closed and does not enable any data-plane capability.
- `SIGTERM` and `SIGINT` trigger a bounded session disconnect before exit so a
  normal container restart does not wait for the old Core lease to expire.
- Connector proof-of-possession currently uses a persisted Ed25519 identity.
  Enrollment and activation declare the credential-bound algorithm explicitly;
  an authentication challenge that declares a different algorithm fails closed.
  Rule-package signature verification is an independent trust contract.
- Incremental `state_changed` events use a durable monotonic sequence.
- Event uplink batches default to 50 items and are bounded to 1–100 so Core
  projection completes within the Connector HTTP timeout instead of creating
  overlapping retries.
- The queue is bounded by both 24 hours and 100 MiB. Capacity overflow rejects
  the new item without breaking the acknowledged sequence prefix; age expiry
  clears the non-replayable tail back to the last Core ACK cursor. Both paths
  increment dropped evidence and schedule a full reconciliation snapshot.
- On startup, the Core cursor is authoritative. A persisted queue tail that no
  longer starts at `cursor + 1` is discarded and replaced by reconciliation
  instead of retrying a permanent sequence conflict.
- Full reconciliation defaults to every 6 hours and can be configured only
  within 6–24 hours.
- Core retries are bounded and protected by a closed/open/half-open circuit
  breaker.
- Inactive, stale-generation, and expired Hub sessions are re-authenticated and
  re-established automatically. Sequence gaps remain reconciliation errors and
  do not trigger session replacement.
