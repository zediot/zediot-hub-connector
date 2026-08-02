# Changelog

## Unreleased

- Preserve the acknowledged uplink sequence during queue capacity and age
  pressure, record dropped evidence, and schedule reconciliation instead of
  creating an unrecoverable Core cursor gap.

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
