from __future__ import annotations

import logging

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    HubConnectorRuntime(ConnectorConfig.from_env()).run_forever()


if __name__ == "__main__":
    main()
