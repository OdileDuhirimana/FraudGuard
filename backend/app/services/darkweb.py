from hashlib import sha256

BREACHED_HASHES = {
    # demo hash values
    sha256(b"4111111111111111").hexdigest(),
    sha256(b"5500000000000004").hexdigest(),
}


def is_exposed(card_hash: str) -> bool:
    if not card_hash:
        return False
    return card_hash in BREACHED_HASHES
