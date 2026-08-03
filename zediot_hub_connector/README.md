# ZedIoT Hub Connector App

The Home Assistant app runs the same `zediot_ha_hub_connector` runtime as the
standalone image. It maintains only bounded delivery queues, command receipts,
verified active local-rule packages and short-retention execution evidence.

## Install

The repository URL and versioned `{arch}` images must be anonymously readable
before this flow is offered to ordinary users. A private GitLab sign-in redirect
is not a released Add-on repository.

1. In IoT Core, open the target Home Assistant integration and create a
   one-time Hub Connector pairing code scoped to the target HOME.
2. In Home Assistant, add
   `https://github.com/zediot/zediot-hub-connector` to the App Store repository
   list.
3. Install **ZedIoT Hub Connector**.
4. Set only `core_url`, the one-time `pairing_code`, and an optional
   `display_name`.
5. Start the app, then return to IoT Core and approve the displayed connector
   fingerprint and requested grants.

The app obtains a local Supervisor token through `homeassistant_api: true`.
That token never leaves Home Assistant and is never written to the queue,
runtime evidence, or IoT Core.

Local rules are fail-closed: only signed packages from a configured trusted key
id, the current integration instance, the supported runtime version and the
reviewed `light.power` action profile can execute. Raw Home Assistant payloads,
tokens and credentials are never persisted in rule evidence.
