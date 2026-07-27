# Standalone Docker Distribution

This directory will package the same `zediot_ha_hub_connector` runtime for Home
Assistant Container and managed Linux installations.

The Home Assistant credential must be mounted from a read-only secret file. It
must not be placed in a compose environment variable or uploaded to IoT Core.
