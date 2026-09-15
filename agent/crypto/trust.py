from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:
    raise ImportError(
        "P11 uchun 'cryptography' paketi kerak. "
        "O'rnatish: .venv/Scripts/python.exe -m pip install cryptography"
    ) from exc


class CryptographicTrust:
    """
    CyberDefender P11 - Cryptographic Trust Layer.

    Prototype security boundary:

        Event data
            |
            v
        Canonical JSON
            |
            v
        Ed25519 signature
            |
            v
        Verification

    Muhim:
    - Private key faqat signing uchun ishlatiladi.
    - Verification public key bilan bajariladi.
    - Private key root trust hisoblanmaydi.
    - Bu prototype key store.
    - Production'da TPM/HSM/OS protected key storage kerak.
    """

    VERSION = "1.0"

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ):
        if private_key is None:
            raise ValueError("private_key kerak")

        if public_key is None:
            raise ValueError("public_key kerak")

        self._private_key = private_key
        self._public_key = public_key

    @staticmethod
    def generate() -> "CryptographicTrust":
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        return CryptographicTrust(
            private_key=private_key,
            public_key=public_key,
        )

    @staticmethod
    def canonicalize(data: dict[str, Any]) -> bytes:
        """
        Signature uchun deterministic representation.

        Signature'ning o'zi canonical payload tarkibiga kirmaydi.
        """

        if not isinstance(data, dict):
            raise TypeError("data dict bo'lishi kerak")

        canonical = dict(data)

        canonical.pop("signature", None)
        canonical.pop("public_key", None)

        return json.dumps(
            canonical,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sign(self, data: dict[str, Any]) -> str:
        payload = self.canonicalize(data)

        signature = self._private_key.sign(
            payload
        )

        return base64.b64encode(
            signature
        ).decode("ascii")

    def verify(
        self,
        data: dict[str, Any],
        signature: str,
    ) -> bool:
        if not isinstance(signature, str):
            return False

        try:
            raw_signature = base64.b64decode(
                signature.encode("ascii"),
                validate=True,
            )

            payload = self.canonicalize(data)

            self._public_key.verify(
                raw_signature,
                payload,
            )

            return True

        except Exception:
            return False

    def export_public_key(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return base64.b64encode(
            raw
        ).decode("ascii")

    @staticmethod
    def import_public_key(
        encoded: str,
    ) -> Ed25519PublicKey:
        if not isinstance(encoded, str):
            raise TypeError(
                "public key string bo'lishi kerak"
            )

        raw = base64.b64decode(
            encoded.encode("ascii"),
            validate=True,
        )

        return Ed25519PublicKey.from_public_bytes(
            raw
        )

    def export_private_key_pem(self) -> bytes:
        """
        Faqat development/test uchun.

        Production'da private key'ni oddiy PEM faylda saqlash
        yetarli emas.
        """

        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def import_private_key_pem(
        pem: bytes,
    ) -> Ed25519PrivateKey:
        key = serialization.load_pem_private_key(
            pem,
            password=None,
        )

        if not isinstance(
            key,
            Ed25519PrivateKey,
        ):
            raise TypeError(
                "Ed25519 private key kutilgan"
            )

        return key

    def health_check(self) -> dict:
        return {
            "component": "CryptographicTrust",
            "status": "HEALTHY",
            "version": self.VERSION,
            "algorithm": "Ed25519",
        }


class TrustedEventEnvelope:
    """
    SecurityEvent uchun cryptographically authenticated envelope.

    Bu klass mavjud SecurityEvent'ni o'zgartirmaydi.
    """

    VERSION = "1.0"

    def __init__(
        self,
        event: Any,
        trust: CryptographicTrust,
    ):
        if event is None:
            raise ValueError("event kerak")

        if trust is None:
            raise ValueError("trust kerak")

        if not hasattr(event, "to_dict"):
            raise TypeError(
                "event.to_dict() mavjud bo'lishi kerak"
            )

        self.event = event
        self.trust = trust

    def to_dict(self) -> dict:
        event_data = self.event.to_dict()

        signature = self.trust.sign(
            event_data
        )

        return {
            "schema_version": self.VERSION,
            "event": event_data,
            "signature": signature,
            "public_key": self.trust.export_public_key(),
        }

    @staticmethod
    def verify_envelope(
        envelope: dict,
    ) -> bool:
        if not isinstance(envelope, dict):
            return False

        event_data = envelope.get(
            "event"
        )

        signature = envelope.get(
            "signature"
        )

        public_key_encoded = envelope.get(
            "public_key"
        )

        if not isinstance(
            event_data,
            dict,
        ):
            return False

        if not isinstance(
            signature,
            str,
        ):
            return False

        if not isinstance(
            public_key_encoded,
            str,
        ):
            return False

        try:
            public_key = (
                CryptographicTrust.import_public_key(
                    public_key_encoded
                )
            )

            trust = CryptographicTrust(
                private_key=Ed25519PrivateKey.generate(),
                public_key=public_key,
            )

            return trust.verify(
                event_data,
                signature,
            )

        except Exception:
            return False
