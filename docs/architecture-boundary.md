# Architecture Boundary

## Runtime topology

```text
Home Assistant
    |
    | local REST/WebSocket API
    v
ZedHub Connector
    |
    | outbound WSS/HTTPS
    v
IoT Core Hub Session / Integration Access Service
```

Home Assistant is the first profile. The cloud contract remains based on the
generic Integration Instance, source object ledger, canonical runtime evidence,
and command acknowledgement model.

## Trust boundary

The Home Assistant app reads the Supervisor token from its process environment.
The standalone Docker distribution reads the Home Assistant token from a
read-only secret file. Neither token may leave the local network.

Cloud identity is established through scoped pairing, a local asymmetric key
pair, fingerprint approval, proof of possession, and a short-lived key-bound
session token.

## Ownership boundary

| Data or behavior | Owner |
|---|---|
| Home Assistant private API details | ZedHub Connector |
| Bounded replay queue | ZedHub Connector |
| Tenant, Integration Instance, grants | IoT Core |
| Mapping and Core asset identity | IoT Core |
| Final presence/latest/command state | IoT Core |
| Long-term telemetry and audit | IoT Core |
| Tuya private protocol behavior | GHE Proxy/Adapter |

## Duplicate-source protection

Devices already managed by a direct provider integration must not be created a
second time through Home Assistant. The connector must apply the ownership
policy returned by IoT Core before projecting a Home Assistant source object.
