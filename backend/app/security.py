"""
AES-256-GCM encryption for sensitive JSON blobs (behavioral biometrics,
device fingerprints, transaction feature vectors).

Why the fail-closed change: the original `encrypt_json` silently returned
the plaintext payload unchanged whenever `FG_AES_KEY` was unset. That meant
"encryption at rest" was true only if an operator remembered to set an env
var — the code itself never verified or enforced it. In production, this
module now raises rather than silently downgrading to plaintext, so a
missing key is a boot-time failure, not a silent data-handling regression
discovered later during a security review.

In non-production (local dev, CI), the no-op fallback is preserved so a
contributor can run the app without generating a key first.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


class EncryptionConfigurationError(RuntimeError):
    """Raised when encryption is required (production) but misconfigured."""


def _get_aes_key() -> Optional[bytes]:
    raw_key = settings.aes_key_b64
    if not raw_key:
        if settings.require_aes_key:
            raise EncryptionConfigurationError(
                "FG_AES_KEY must be set in production — refusing to store "
                "sensitive data unencrypted."
            )
        return None
    try:
        raw = base64.b64decode(raw_key)
    except Exception as exc:
        raise EncryptionConfigurationError("FG_AES_KEY is not valid base64") from exc
    if len(raw) != 32:
        raise EncryptionConfigurationError("FG_AES_KEY must decode to exactly 32 bytes (AES-256)")
    return raw


def encrypt_json(payload: dict) -> dict:
    key = _get_aes_key()
    if not key:
        return payload
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    data = json.dumps(payload).encode()
    ct = aesgcm.encrypt(nonce, data, None)
    return {
        "_enc": True,
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


def decrypt_json(payload: dict) -> dict:
    if not isinstance(payload, dict) or not payload.get("_enc"):
        return payload
    key = _get_aes_key()
    if not key:
        return payload
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ct"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode())
