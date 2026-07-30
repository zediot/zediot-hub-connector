# ZedIoT Hub Connector App

The Home Assistant app runs the same `zediot_ha_hub_connector` runtime as the
standalone image. It maintains only bounded delivery queues, command receipts,
verified active local-rule packages and short-retention execution evidence.

Local rules are fail-closed: only signed packages from a configured trusted key
id, the current integration instance, the supported runtime version and the
reviewed `light.power` action profile can execute. Raw Home Assistant payloads,
tokens and credentials are never persisted in rule evidence.
