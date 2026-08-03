from __future__ import annotations

from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def test_distribution_surfaces_match_package_version():
    package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = package["project"]["version"]
    addon = (ROOT / "zediot_hub_connector/config.yaml").read_text(
        encoding="utf-8"
    )
    compose = (ROOT / "deploy/docker/compose.yaml").read_text(encoding="utf-8")
    env_example = (ROOT / "deploy/docker/.env.example").read_text(
        encoding="utf-8"
    )
    pipeline = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")

    addon_version = re.search(r"^version:\s*(\S+)\s*$", addon, re.MULTILINE)
    assert addon_version is not None
    assert addon_version.group(1) == version
    assert f"/amd64:{version}" in compose
    assert f"/amd64:{version}" in env_example
    assert "ZEDIOT_EVENT_BATCH_SIZE: ${ZEDIOT_EVENT_BATCH_SIZE:-50}" in compose
    assert "ZEDIOT_EVENT_BATCH_SIZE=50" in env_example
    assert 'python -m pip install --disable-pip-version-check ".[test]"' in pipeline
    assert "python -m pytest -q -p no:cacheprovider" in pipeline
    assert "unittest discover" not in pipeline
