import unittest

from zediot_ha_hub_connector import RELEASE_IDENTIFIERS


class ReleaseIdentifiersTest(unittest.TestCase):
    def test_frozen_release_identifiers(self) -> None:
        self.assertEqual(RELEASE_IDENTIFIERS.product_name, "ZedHub Connector")
        self.assertEqual(
            RELEASE_IDENTIFIERS.home_assistant_store_name,
            "ZedIoT Hub Connector",
        )
        self.assertEqual(
            RELEASE_IDENTIFIERS.repository_name,
            "zediot-hub-connector",
        )
        self.assertEqual(
            RELEASE_IDENTIFIERS.addon_slug,
            "zediot_hub_connector",
        )
        self.assertEqual(
            RELEASE_IDENTIFIERS.python_package,
            "zediot_ha_hub_connector",
        )
        self.assertEqual(
            RELEASE_IDENTIFIERS.container_service,
            "zediot-hub-connector",
        )
        self.assertEqual(
            RELEASE_IDENTIFIERS.core_profile_key,
            "home_assistant",
        )


if __name__ == "__main__":
    unittest.main()
