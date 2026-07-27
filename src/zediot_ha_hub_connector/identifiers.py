"""Frozen public identifiers for all ZedHub Connector release surfaces."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReleaseIdentifiers:
    product_name: str
    home_assistant_store_name: str
    repository_name: str
    addon_slug: str
    python_package: str
    container_service: str
    core_profile_key: str


RELEASE_IDENTIFIERS = ReleaseIdentifiers(
    product_name="ZedHub Connector",
    home_assistant_store_name="ZedIoT Hub Connector",
    repository_name="zediot-hub-connector",
    addon_slug="zediot_hub_connector",
    python_package="zediot_ha_hub_connector",
    container_service="zediot-hub-connector",
    core_profile_key="home_assistant",
)
