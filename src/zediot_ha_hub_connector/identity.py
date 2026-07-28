from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True)
class ConnectorIdentity:
    private_key: Ed25519PrivateKey
    enrollment_id: str | None
    connector_id: str | None
    credential_id: str | None
    exchange_receipt: str | None


class ConnectorIdentityStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.key_path = state_dir / "connector_ed25519.pem"
        self.state_path = state_dir / "connector_identity.json"
        state_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create(self) -> ConnectorIdentity:
        private_key = self._load_or_create_key()
        state = self._load_state()
        return ConnectorIdentity(
            private_key=private_key,
            enrollment_id=state.get("enrollment_id"),
            connector_id=state.get("connector_id"),
            credential_id=state.get("credential_id"),
            exchange_receipt=state.get("exchange_receipt"),
        )

    def save_exchange(
        self,
        *,
        enrollment_id: str,
        connector_id: str,
        credential_id: str,
        exchange_receipt: str,
    ) -> ConnectorIdentity:
        self._write_private_json(
            self.state_path,
            {
                "enrollment_id": enrollment_id,
                "connector_id": connector_id,
                "credential_id": credential_id,
                "exchange_receipt": exchange_receipt,
            },
        )
        return self.load_or_create()

    def public_key_pem(self, identity: ConnectorIdentity) -> str:
        return identity.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            key = serialization.load_pem_private_key(
                self.key_path.read_bytes(),
                password=None,
            )
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("connector key is not Ed25519")
            return key
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._write_private_bytes(self.key_path, data)
        return key

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    @staticmethod
    def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
        ConnectorIdentityStore._write_private_bytes(
            path,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
        )

    @staticmethod
    def _write_private_bytes(path: Path, payload: bytes) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(payload)
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)
