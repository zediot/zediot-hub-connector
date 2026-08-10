# Changelog

## Unreleased

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
