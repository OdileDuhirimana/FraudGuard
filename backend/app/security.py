import base64
import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_aes_key() -> Optional[bytes]:
    # Expect base64-encoded 32-byte key in FG_AES_KEY
    k = os.getenv("FG_AES_KEY")
    if not k:
        return None
    try:
        raw = base64.b64decode(k)
        if len(raw) != 32:
            return None
        return raw
    except Exception:
        return None


def encrypt_json(payload: dict) -> dict:
    key = _get_aes_key()
    if not key:
        return payload
    import json, os
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    data = json.dumps(payload).encode()
    ct = aesgcm.encrypt(nonce, data, None)
    return {"_enc": True, "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}


def decrypt_json(payload: dict) -> dict:
    if not isinstance(payload, dict) or not payload.get("_enc"):
        return payload
    key = _get_aes_key()
    if not key:
        return payload
    import json
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ct"])
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode())
