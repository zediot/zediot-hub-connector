# ZedHub Connector

`ZedHub Connector` is the outbound edge runtime that connects a local
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

This repository is a pre-implementation bootstrap. It freezes ownership,
packaging, and release identifiers, but it is not yet an installable Home
Assistant app.

The Home Assistant `config.yaml`, runtime image, pairing flow, and session
implementation will be added through the IoT Core `R6-S4-B1m` and
`R6-S4-B1n` stories. Until those contracts are implemented and validated,
the `zediot_hub_connector/` directory intentionally contains no app manifest.

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

Pre-built images are not published from this bootstrap commit.
