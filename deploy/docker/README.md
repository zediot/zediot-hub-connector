# Standalone Docker Distribution

Use this package when Home Assistant runs as **Home Assistant Container** or on
managed Linux without the Supervisor Add-on Store.

## Prerequisites

1. Create a Home Assistant long-lived access token from the target HA user's
   profile. The account must be able to read the intended areas, devices,
   entities and states.
2. In IoT Core, create a one-time Hub Connector pairing code scoped to the
   target HOME.
3. Confirm the Connector can reach both Home Assistant and IoT Core using
   outbound connections. Do not expose HA port `8123` to the public Internet.

## Install

```bash
cd deploy/docker
cp .env.example .env
mkdir -p secrets
printf '%s' '<HA_LONG_LIVED_TOKEN>' > secrets/ha_token
printf '%s' '<ONE_TIME_PAIRING_CODE>' > secrets/pairing_code
chmod 600 secrets/ha_token secrets/pairing_code
docker compose up -d
```

For a local source build:

```bash
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

After the first start, approve the connector fingerprint and requested grants
in IoT Core. Once approval succeeds, delete the consumed local pairing-code
file and recreate it only for a new enrollment:

```bash
truncate -s 0 secrets/pairing_code
```

The Home Assistant credential is mounted from a read-only secret file. It must
not be placed in a Compose environment variable, committed to Git, written to
logs, or uploaded to IoT Core. Connector identity, bounded queues and receipts
are persisted only in the `connector_state` volume.

## NAS defaults

When Home Assistant uses host networking, Docker's `host.docker.internal`
gateway normally reaches it at:

```text
ws://host.docker.internal:8123/api/websocket
```

Override `ZEDIOT_HA_WEBSOCKET_URL` when the NAS does not provide the
`host-gateway` mapping.
