# Repository Instructions

## Scope

This repository owns the ZedHub Connector edge runtime and its Home Assistant
and standalone Docker packaging.

## Boundaries

- Keep Home Assistant protocol handling in adapter modules.
- Keep cloud pairing and session contracts provider-neutral.
- Do not import GHE, Tuya proxy, or IoT Core server modules.
- Do not persist long-term telemetry or authoritative cloud state.
- Never log pairing codes, access tokens, Supervisor tokens, private keys, or
  Home Assistant long-lived tokens.
- The Home Assistant app and standalone Docker package must run the same Python
  runtime.

## Delivery

- Contract changes must be coordinated with the IoT Core contract source.
- Do not publish an installable app before pairing, session, secret storage,
  bounded queue, and revoke behavior have focused tests.
- Support `amd64` and `aarch64` release images.
