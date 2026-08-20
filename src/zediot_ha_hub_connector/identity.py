from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SIGNATURE_ALGORITHM_ED25519 = "Ed25519"


# 引导模式（43 附录 A.3 / A.9）。存量实例的 connector_identity.json 里没有
# 这个字段，读出来是 None——**必须**当作 pairing 处理，否则升级后会把已经
# 在跑的设备判成"需要重新激活"，那正是 A.9 不可退让的那条。
BOOTSTRAP_PAIRING = "pairing_code"
BOOTSTRAP_PROVISIONED = "device_secret"

# 绑定状态（43 附录 A.8）。装机与售后靠它区分"设备故障"与"等你操作"。
BINDING_AWAITING_ACTIVATION = "awaiting_activation"
BINDING_AWAITING_BINDING = "awaiting_binding"
BINDING_AWAITING_APPROVAL = "awaiting_approval"
BINDING_READY = "ready"


@dataclass(frozen=True)
class ConnectorIdentity:
    private_key: Ed25519PrivateKey
    enrollment_id: str | None
    connector_id: str | None
    credential_id: str | None
    exchange_receipt: str | None
    signature_algorithm: str = SIGNATURE_ALGORITHM_ED25519
    # --- 预发放路径新增（R6-S5-EDGE-02）---
    tenant_id: str | None = None
    product_key: str | None = None
    device_name: str | None = None
    identity_id: str | None = None
    binding_state: str | None = None
    bound_space_node_id: str | None = None
    bootstrap_mode: str | None = None

    @property
    def effective_bootstrap_mode(self) -> str:
        """没有标记的一律当配对路径。

        存量 connector_identity.json 里不存在这个字段，猜成预发放会让升级
        后的第一次启动去走激活流程，而它根本没有 device_secret——直接把
        现网设备打死。默认值必须偏向旧路径。
        """
        return self.bootstrap_mode or BOOTSTRAP_PAIRING

    def sign_challenge(self, message: bytes) -> bytes:
        """Sign a Core challenge with the algorithm bound to this identity."""
        if self.signature_algorithm != SIGNATURE_ALGORITHM_ED25519:
            raise ValueError(
                f"unsupported connector signature algorithm: {self.signature_algorithm}"
            )
        return self.private_key.sign(message)


class ConnectorIdentityStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.key_path = state_dir / "connector_ed25519.pem"
        self.state_path = state_dir / "connector_identity.json"
        state_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create(self) -> ConnectorIdentity:
        private_key = self._load_or_create_key()
        state = self._load_state()
        signature_algorithm = state.get("signature_algorithm")
        if signature_algorithm is None:
            # Legacy identities are Ed25519 by construction. Persist the inferred
            # value so later restarts never reinterpret the existing key.
            signature_algorithm = SIGNATURE_ALGORITHM_ED25519
            state = {**state, "signature_algorithm": signature_algorithm}
            self._write_private_json(self.state_path, state)
        if signature_algorithm != SIGNATURE_ALGORITHM_ED25519:
            raise ValueError(
                f"unsupported connector signature algorithm: {signature_algorithm}"
            )
        return ConnectorIdentity(
            private_key=private_key,
            enrollment_id=state.get("enrollment_id"),
            connector_id=state.get("connector_id"),
            credential_id=state.get("credential_id"),
            exchange_receipt=state.get("exchange_receipt"),
            signature_algorithm=signature_algorithm,
            tenant_id=state.get("tenant_id"),
            product_key=state.get("product_key"),
            device_name=state.get("device_name"),
            identity_id=state.get("identity_id"),
            binding_state=state.get("binding_state"),
            bound_space_node_id=state.get("bound_space_node_id"),
            bootstrap_mode=state.get("bootstrap_mode"),
        )

    def save_exchange(
        self,
        *,
        enrollment_id: str,
        connector_id: str,
        credential_id: str,
        exchange_receipt: str,
    ) -> ConnectorIdentity:
        self._merge_state(
            {
                "enrollment_id": enrollment_id,
                "connector_id": connector_id,
                "credential_id": credential_id,
                "exchange_receipt": exchange_receipt,
                "bootstrap_mode": BOOTSTRAP_PAIRING,
                "binding_state": BINDING_READY,
            }
        )
        return self.load_or_create()

    def save_activation(
        self,
        *,
        tenant_id: str,
        product_key: str,
        device_name: str,
        identity_id: str | None,
        binding_state: str,
        bound_space_node_id: str | None,
        connector_id: str | None = None,
        credential_id: str | None = None,
    ) -> ConnectorIdentity:
        """记录预发放路径的激活结果（43 附录 A.3/A.4）。

        connector_id / credential_id 在**绑定之前是空的**——Core 侧要到绑定
        时才建 connector（43 第 4.3 节偏差 2）。因此这里允许为空，
        并用 binding_state 表达"激活了但还不能连"。
        """
        payload = {
            "tenant_id": tenant_id,
            "product_key": product_key,
            "device_name": device_name,
            "identity_id": identity_id,
            "binding_state": binding_state,
            "bound_space_node_id": bound_space_node_id,
            "bootstrap_mode": BOOTSTRAP_PROVISIONED,
        }
        if connector_id:
            payload["connector_id"] = connector_id
        if credential_id:
            payload["credential_id"] = credential_id
        self._merge_state(payload)
        return self.load_or_create()

    def save_binding_state(
        self,
        *,
        binding_state: str,
        bound_space_node_id: str | None = None,
        connector_id: str | None = None,
        credential_id: str | None = None,
    ) -> ConnectorIdentity:
        payload: dict[str, Any] = {"binding_state": binding_state}
        if bound_space_node_id:
            payload["bound_space_node_id"] = bound_space_node_id
        if connector_id:
            payload["connector_id"] = connector_id
        if credential_id:
            payload["credential_id"] = credential_id
        self._merge_state(payload)
        return self.load_or_create()

    def _merge_state(self, changes: dict[str, Any]) -> None:
        """合并写入，不整体覆盖。

        整体覆盖会在新增字段时悄悄抹掉旧字段——比如激活后再写绑定状态，
        若覆盖就把 connector_id 清了，设备下次启动直接失去身份。
        """
        state = {**self._load_state(), **changes}
        self._write_private_json(self.state_path, state)

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
