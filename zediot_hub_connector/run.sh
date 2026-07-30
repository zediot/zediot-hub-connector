#!/usr/bin/with-contenv bashio
set -euo pipefail

export ZEDIOT_HA_AUTH_MODE=supervisor
export ZEDIOT_HA_WEBSOCKET_URL=ws://supervisor/core/websocket
export ZEDIOT_RUNTIME_KIND=home_assistant_addon

exec zediot-hub-connector
