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
session token. The one-time pairing code is a bootstrap input, not a permanent
runtime dependency; the persisted key-bound identity owns restart continuity.

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

Queue retention must never create a gap in the Core-owned uplink cursor. When
the byte limit is reached, the Connector preserves the already queued
contiguous prefix and rejects the new item. When the age limit invalidates the
prefix, it clears the remaining unacknowledged tail and restarts from the last
Core ACK cursor. Startup also compares the persisted tail with the
authoritative Core cursor and clears a tail that does not start at the next
expected sequence. All three cases emit dropped-count evidence and require a
full reconciliation snapshot before the runtime returns to steady state.

Each snapshot contains two bounded facets captured from the same Home Assistant
read: inventory objects and current-state observations. Inventory remains the
source-object ledger input; current state is projected by the Home Assistant
profile and is not persisted by the Connector as authoritative cloud state.
State values participate in the snapshot version so a state-only change is not
mistaken for a duplicate inventory snapshot.

The queue persists a delivery-attempt counter per item. A first delivery uses
`realtime` only when it was collected while connected. Data collected while the
circuit is open, and any retry after a failed or uncertain HTTP delivery, uses
`replay`, including after restart. Replay preserves source event time and
idempotency identity, and IoT Core treats it as historical evidence rather than
new realtime authority.

An uncertain HTTP delivery fences the entire pending queue, not only the batch
that was handed to the client. Events may be appended while an upload is in
flight; without this fence they could survive a failed predecessor with a false
`realtime` label. The persisted attempt marker therefore advances every pending
row before retry or restart recovery.

## Session token binding

IoT Core binds a session to the JTI of the token that created it. A refreshed
token does not inherit that binding: the connector must call
`POST /api/hub/v1/sessions/{session_id}/token` with the current
`lease_generation` whenever it mints a new access token while a session is
still open. Rebinding does not change the lease generation; it only moves the
binding to the new token.

Skipping the rebind is not a degraded mode, it is a stall. Every later
heartbeat is answered with 403 `Hub session token binding mismatch`, and 403 is
not one of the conditions that re-establish a session, so the connector keeps
sending doomed heartbeats until the 90-second lease expires and Core finally
answers 409. Production showed the cost: a 900-second token refreshed 60
seconds early produced roughly 14 good minutes and 2 dead ones, 22 sessions in
six hours where a healthy gateway had 2, and an audit trail of 13
`hub.auth.token.issue` against 0 `hub.session.token_rebind`.

Two call sites deliberately do not rebind. Session creation has no session to
rebind yet, and teardown must keep using the token that owns the session rather
than minting a fresh one at the refresh boundary.

## Duplicate-source protection

Devices already managed by a direct provider integration must not be created a
second time through Home Assistant. The connector must apply the ownership
policy returned by IoT Core before projecting a Home Assistant source object.
