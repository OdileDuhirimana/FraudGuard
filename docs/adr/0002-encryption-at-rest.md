# ADR 0002: Fail-closed encryption at rest for sensitive JSON blobs

## Status
Accepted

## Context
`app/security.py` encrypts sensitive JSON blobs (transaction feature
vectors, behavioral biometric events, device fingerprints) with AES-256-GCM
when `FG_AES_KEY` is set. The original implementation silently returned the
plaintext payload unchanged whenever the key was absent — meaning
"encryption at rest" was true only if an operator remembered to configure
it correctly. The code itself never verified this was the case, which is a
real security-posture gap: a misconfigured production deployment would
store plaintext sensitive data with no error, warning, or log line
indicating anything was wrong.

## Decision
`encrypt_json`/`decrypt_json` now consult `Settings.require_aes_key`
(`True` when `ENV=production`). In production, a missing or malformed
`FG_AES_KEY` raises `EncryptionConfigurationError` at the point of use,
which surfaces as a request failure rather than a silent plaintext write.
In non-production, the no-op fallback is preserved so a new contributor can
run the app locally without generating a key first.

## Consequences
- A production deployment with no `FG_AES_KEY` will fail requests that
  write sensitive data (score, behavior, device endpoints) instead of
  silently storing plaintext. This is intentional: failing loudly and
  immediately is preferable to a silent compliance gap discovered later.
- This does not implement key rotation, envelope encryption, or a KMS
  integration — it is a single static symmetric key read from an
  environment variable. That is an acceptable tradeoff for a portfolio-
  scale demo but would need to change (e.g. AWS KMS / HashiCorp Vault) for
  a genuine production fintech deployment. Documented as a known
  limitation in the README.
