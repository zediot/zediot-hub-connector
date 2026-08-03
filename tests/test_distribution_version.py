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
    public_pipeline = (ROOT / ".github/workflows/public-release.yml").read_text(
        encoding="utf-8"
    )
    repository = (ROOT / "repository.yaml").read_text(encoding="utf-8")

    addon_version = re.search(r"^version:\s*(\S+)\s*$", addon, re.MULTILINE)
    assert addon_version is not None
    assert addon_version.group(1) == version
    assert f"ghcr.io/zediot/zediot-hub-connector:{version}" in compose
    assert f"ghcr.io/zediot/zediot-hub-connector:{version}" in env_example
    assert "url: https://github.com/zediot/zediot-hub-connector" in repository
    assert "url: https://github.com/zediot/zediot-hub-connector" in addon
    assert "image: ghcr.io/zediot/{arch}-zediot-hub-connector" in addon
    assert "ZEDIOT_EVENT_BATCH_SIZE: ${ZEDIOT_EVENT_BATCH_SIZE:-50}" in compose
    assert "ZEDIOT_EVENT_BATCH_SIZE=50" in env_example
    assert 'python -m pip install --disable-pip-version-check ".[test]"' in pipeline
    assert "python -m pytest -q -p no:cacheprovider" in pipeline
    assert "unittest discover" not in pipeline
    assert "packages: write" in public_pipeline
    assert "python -m pytest -q -p no:cacheprovider" in public_pipeline
    assert "ghcr.io/zediot/${{ matrix.arch }}-zediot-hub-connector" in public_pipeline
    assert "ghcr.io/zediot/zediot-hub-connector" in public_pipeline
    assert "registry.gitlab.osvie.com" not in "\n".join(
        (repository, addon, compose, env_example)
    )
