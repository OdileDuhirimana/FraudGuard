"""
Unit tests for pure helper modules: services/darkweb.py and security.py.

security.py's fail-closed-in-production behavior (ADR 0002) is the
highest-value case here: it directly guards against the "AES encryption
silently no-ops" finding from the original audit.

Note on approach: `Settings` (app/config.py) is a frozen dataclass, so
individual attributes can't be monkeypatched in place. Instead, these tests
replace the module-level `security.settings` reference itself with a small
stand-in object exposing just the two attributes security.py reads
(`aes_key_b64`, `require_aes_key`) — this keeps the test focused on
security.py's branching logic without needing to fight dataclass
immutability or mutate global state other tests depend on.
"""
import base64
from dataclasses import dataclass
from typing import Optional

import pytest

from app import security
from app.services.darkweb import is_exposed


@dataclass
class _FakeSettings:
    aes_key_b64: Optional[str]
    require_aes_key: bool


def test_is_exposed_false_for_empty_or_none():
    assert is_exposed("") is False
    assert is_exposed(None) is False


def test_is_exposed_true_for_known_demo_hash():
    from hashlib import sha256

    known_hash = sha256(b"4111111111111111").hexdigest()
    assert is_exposed(known_hash) is True


def test_is_exposed_false_for_unknown_hash():
    assert is_exposed("not-a-real-hash") is False


def test_encrypt_decrypt_roundtrip_with_valid_key(monkeypatch):
    key = base64.b64encode(b"0" * 32).decode()
    monkeypatch.setattr(security, "settings", _FakeSettings(aes_key_b64=key, require_aes_key=False))

    payload = {"card_hash": "abc123", "amount": 42}
    encrypted = security.encrypt_json(payload)
    assert encrypted["_enc"] is True
    assert encrypted["ct"] != payload

    decrypted = security.decrypt_json(encrypted)
    assert decrypted == payload


def test_encrypt_json_noop_without_key_in_non_production(monkeypatch):
    monkeypatch.setattr(security, "settings", _FakeSettings(aes_key_b64=None, require_aes_key=False))

    payload = {"foo": "bar"}
    assert security.encrypt_json(payload) == payload


def test_encrypt_json_fails_closed_in_production_without_key(monkeypatch):
    monkeypatch.setattr(security, "settings", _FakeSettings(aes_key_b64=None, require_aes_key=True))

    with pytest.raises(security.EncryptionConfigurationError):
        security.encrypt_json({"foo": "bar"})


def test_encrypt_json_rejects_malformed_base64_key(monkeypatch):
    monkeypatch.setattr(
        security, "settings", _FakeSettings(aes_key_b64="not-valid-base64!!!", require_aes_key=False)
    )

    with pytest.raises(security.EncryptionConfigurationError):
        security.encrypt_json({"foo": "bar"})


def test_encrypt_json_rejects_wrong_length_key(monkeypatch):
    short_key = base64.b64encode(b"too-short").decode()
    monkeypatch.setattr(security, "settings", _FakeSettings(aes_key_b64=short_key, require_aes_key=False))

    with pytest.raises(security.EncryptionConfigurationError):
        security.encrypt_json({"foo": "bar"})


def test_decrypt_json_passthrough_for_unencrypted_payload():
    payload = {"plain": "data"}
    assert security.decrypt_json(payload) == payload
