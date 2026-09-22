# Changelog

## 0.3.5

- Wait out a held session lease instead of crash-restarting. After a restart,
  creating a session while the previous process's lease is still live returns
  409 `active_lease_conflict`. The connector only called `raise_for_status()`,
  so the error escaped `run_forever`, the process exited, the container restart
  policy brought it back, and it collided again after a cold start. Observed in
  production: 7 rejections between 08:16 and 08:19 on 2026-09-19, about 30s
  apart — the cadence of cold starts — each one adding a
  `connector_clone_suspected` audit, while Core knew the answer from the first
  rejection.
- Core now returns `active_lease_expires_at` and `retry_after_seconds` with that
  409. The connector recognises it (`HubLeaseConflictError`), waits
  `retry_after_seconds + 1` in place and retries. The extra second covers Core's
  `lease_expires_at < now` check landing a few milliseconds early on a whole-second
  boundary. Older Core versions that send only the message string get a fixed
  30s wait; hints are capped at 600s so a bogus value cannot park the connector
  for hours.
- Only that conflict is waited out. Other 409s on the same endpoint (contract
  mismatch, inactive integration instance) will not heal by waiting and still
  raise.
- The wait uses the stop event, so SIGTERM during it returns immediately without
  another attempt. Startup and session recovery share `_establish_session`, so
  both paths are covered.

## 0.3.4

- Rebind the live session whenever the access token is rotated. Core binds a
  session to the jti of the token that created it, so refreshing the token
  without calling `POST /sessions/{id}/token` made every subsequent heartbeat
  fail with 403 `Hub session token binding mismatch`. 403 was not in the
  "session must be re-established" set, so the client spun until the 90s lease
  expired and only then got a 409 and rebuilt. Observed in production: the
  token is requested with a hardcoded 900s TTL and refreshed 60s early, so the
  connector lost its session roughly every 16 minutes (14 minutes of healthy
  30s heartbeats, then ~2 minutes of guaranteed-failing ones). Six hours showed
  22 sessions where a healthy gateway had 2, and the audit trail showed 13
  `hub.auth.token.issue` against 0 `hub.session.token_rebind`.
- Treat a 403 carrying `Hub session token binding mismatch` or
  `Hub session has no token binding` as "re-establish the session", so any
  future binding drift costs one session rebuild instead of 90 seconds of
  failing heartbeats. 403 bodies carry the detail under `data.detail` rather
  than as a bare string, which the parser now handles.
- `connect_session` and `disconnect_session` deliberately do not rebind:
  the former has no session yet, and teardown must keep using the token that
  owns the session rather than minting a fresh one at the refresh boundary.

## 0.3.3

- Split reconciliation out of the heartbeat loop. Collecting the Home Assistant
  snapshot is synchronous and can occupy its thread for minutes, while the Hub
  session lease is only 90 seconds, so a slow snapshot stopped the heartbeat and
  killed the session. Observed in production: 23 sessions in six hours (a healthy
  gateway had 2), heartbeats exactly every 30s then silent for ~3 minutes before
  a new session. The dead session also meant the snapshot never uploaded, so
  `reconciliation_required` never cleared and the cycle repeated every 13 minutes,
  leaving newly assigned Home Assistant areas unable to reach Core.
- Bound the whole snapshot collection with a hard deadline (20s, well under the
  lease). A per-recv timeout cannot cap it because `_receive_non_ping` loops, so a
  steady ping stream had no upper bound.
- Fix `source_event_id` collisions within a batch. The id was
  `ha:{context_id}:{sha(entity_id)}`, but a single Home Assistant context can carry
  several state changes for the same entity, so two events produced one id and Core
  rejected the whole batch as non-unique. One batch was rejected 5946 times, blocking
  all uplink behind it. The id now folds in `last_updated`, both generators share one
  implementation, and batch assembly truncates at a duplicate id as a second guard.


- Include bounded Home Assistant current-state observations in every bootstrap
  and reconciliation snapshot so unchanged inventory cannot hide changed state.
- Persist upload attempt evidence in the bounded SQLite queue. Connected first
  delivery is realtime; circuit-open collection and any retry after a failed or
  uncertain delivery, including after process restart, are replay while
  preserving source identity and sequence.
- Fence the complete pending queue after any uncertain HTTP delivery, including
  items appended behind the failed batch. This closes the race where those
  follower items could otherwise retain realtime delivery semantics after Core
  recovery or Connector restart.

## 0.3.2

- Stop the rule-package poll loop from busy-waiting on control directives. Core
  returns the full list of revoked/expired packages on every claim rather than a
  consumable queue, so counting each returned control as progress made the loop
  skip its sleep forever. Measured on the test NAS at 52 requests per second,
  sustained for six days after a single package was revoked.
- Count a control as progress only when it actually changed local state.
  `apply_control` already reported this; the caller discarded it.
- Sleep a short minimum between polls even when there is work, so a future
  mistake in the progress signal degrades to five requests per second instead of
  fifty.
- Correct the rule-runtime test double, which consumed control directives on
  first delivery. Every rule test therefore ran in a world where this failure
  mode could not occur.

## 0.3.1

- Map `share` into the Add-on so a pre-provisioned install can actually read its
  credential bundle. Without the mapping the container saw only its own `/data`,
  which left the `0.3.0` provisioning options unusable on Home Assistant OS.
- Map it read-write rather than read-only, because the one-time claim code must
  be deleted after it is consumed.
- Add `deploy/docker/compose.provisioned.yaml` and document the standalone
  pre-provisioned install, which `0.3.0` shipped without any Compose wiring.

## 0.3.0

- Support pre-provisioned (one-device-one-secret) bootstrap: activate against
  Core with a tenant/product/device triple, then wait for the user to bind the
  gateway instead of failing the start-up.
- Keep the pairing-code path as the default so existing installations upgrade
  without configuration changes; the bootstrap mode is chosen per install and
  recorded in the identity file.
- Read the device secret only from a provisioning bundle file, never from an
  Add-on option or environment variable, so it stays out of `/data/options.json`,
  Supervisor diagnostics and `docker inspect`.
- Hold the data plane closed until binding completes, so an activated but
  unbound gateway cannot upload telemetry.
- Expose `tenant_id`, `product_key`, `device_name`, `provisioning_bundle_file`
  and `claim_code_file` as optional Add-on options; all are absent by default.
- Raise package, Add-on, standalone Compose and environment-example versions to
  `0.3.0`.

## 0.2.1

- Add the public GitHub App Repository and GHCR release workflow for anonymous
  Home Assistant OS/Supervised and Container installation.
- Keep private GitLab as the development source of truth while publishing only
  reviewed commits and version tags to `github.com/zediot/zediot-hub-connector`.
- Preserve the acknowledged uplink sequence during queue capacity and age
  pressure, record dropped evidence, and schedule reconciliation instead of
  creating an unrecoverable Core cursor gap.
- Allow an enrolled Connector to restart after its one-time pairing-code file
  has been consumed, while keeping the Home Assistant token fail-closed.
- Repair persisted queue tails that conflict with the authoritative Core cursor
  during startup and schedule a full reconciliation snapshot.
- Re-establish inactive, stale-generation, or expired Hub sessions without
  restarting the Connector, while leaving sequence-gap conflicts fail-closed.
- Bound state-event upload batches to a configurable 1–100 events, defaulting
  to 50, so Core projection completes within the HTTP request budget.
- Call Home Assistant services without requesting response data, allowing
  non-response actions such as light turn-on/turn-off to ACK successfully.
- Keep package, Add-on, standalone Compose and environment-example versions on
  `0.2.1`, and expose the bounded event batch size in the Container profile.
- Replace the ineffective unittest release job with an installed pytest suite
  that must pass before tagged multi-architecture image builds.

## 0.2.0

- Support one runtime in two installation profiles: Home Assistant OS/Supervised
  Add-on and Home Assistant Container standalone companion.
- Read standalone Home Assistant and pairing credentials from mounted secret
  files instead of environment values.
- Auto-generate and persist an installation ID when users do not provide one.
- Publish versioned amd64 and aarch64 Add-on images from signed version tags.

## 0.1.0

- Bootstrap the independent ZedHub Connector repository.
- Freeze Home Assistant app, Python package, container, and Core profile
  identifiers.
