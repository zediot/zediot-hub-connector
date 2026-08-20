from __future__ import annotations

import json

import pytest

from zediot_ha_hub_connector.identity import ConnectorIdentityStore


def test_legacy_identity_is_persisted_as_ed25519(tmp_path):
    store = ConnectorIdentityStore(tmp_path)
    store.load_or_create()
    state_path = tmp_path / "connector_identity.json"
    state_path.write_text(
        json.dumps(
            {
                "connector_id": "hub-legacy",
                "credential_id": "hcred-legacy",
            }
        ),
        encoding="utf-8",
    )

    identity = store.load_or_create()

    assert identity.signature_algorithm == "Ed25519"
    assert json.loads(state_path.read_text(encoding="utf-8"))[
        "signature_algorithm"
    ] == "Ed25519"


def test_identity_rejects_an_algorithm_that_does_not_match_its_key(tmp_path):
    store = ConnectorIdentityStore(tmp_path)
    store.load_or_create()
    (tmp_path / "connector_identity.json").write_text(
        json.dumps({"signature_algorithm": "ES256"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported connector signature algorithm"):
        store.load_or_create()
