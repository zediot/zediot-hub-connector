from __future__ import annotations

import logging
import signal

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    runtime = HubConnectorRuntime(ConnectorConfig.from_env())

    def stop(signum: int, _frame: object) -> None:
        signal_name = signal.Signals(signum).name.lower()
        runtime.request_stop(reason_code=f"connector_{signal_name}")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    runtime.run_forever()


if __name__ == "__main__":
    main()
