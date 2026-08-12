"""Key generation/derivation and per-value encryption for NPIMasker.

Keys are arbitrary user-supplied strings (a passphrase, or a random string
from `generate_passphrase`). They are run through PBKDF2 with a fixed,
application-level salt to produce a Fernet-compatible key. The fixed salt
is a deliberate simplicity trade-off for a local, single-user tool: it
means the same key string always derives the same encryption key without
needing to store/transmit a per-file salt. Per-value randomness still
comes from Fernet's own IV, so identical cells don't produce identical
ciphertext.
"""

import base64
import re
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_APP_SALT = b"npimasker-v1-fixed-salt"
_KDF_ITERATIONS = 480_000
_MARKER_RE = re.compile(r"\[\[ENC:([A-Za-z0-9_\-=]+)\]\]")


class WrongKeyError(Exception):
    """Raised when a value can't be decrypted with the given key."""


class AlreadyEncryptedError(Exception):
    """Raised when text to be encrypted already holds an [[ENC:...]] marker.

    Deliberately not a WrongKeyError: it is a fixable mistake about which
    file was chosen, not a key problem, and the two need different advice.
    """


def contains_marker(text: str) -> bool:
    """Whether text already holds a syntactically valid [[ENC:...]] marker.

    Matched with the same pattern the decrypter uses, so this is true for
    exactly the text that would later be fed to decrypt_value - no more.
    Marker-shaped but invalid text ("[[ENC:]]", "[[ENC: spaced ]]") passes
    through decryption untouched and must not be refused.
    """
    return _MARKER_RE.search(text) is not None


def generate_passphrase() -> str:
    """Generate a strong random key string for the user to save."""
    return secrets.token_urlsafe(32)


def derive_key(passphrase: str) -> bytes:
    """Derive a Fernet-compatible key from an arbitrary passphrase string."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_APP_SALT,
        iterations=_KDF_ITERATIONS,
    )
    derived = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


@lru_cache(maxsize=4)
def _fernet(key: bytes) -> Fernet:
    """Reuse the Fernet for a given key instead of rebuilding it per cell.

    Fernet.__init__ base64-decodes the key, splits it and sets up the
    cipher - about 1us, which is ~14% of the cost of encrypting a short
    value. It holds no per-message state: the IV comes from os.urandom
    and the timestamp from time.time(), both inside encrypt(), so reusing
    the object cannot make two ciphertexts repeat.
    """
    return Fernet(key)


def encrypt_value(value: str, key: bytes) -> str:
    """Encrypt a single cell value. Empty values pass through unchanged."""
    if value == "":
        return value
    return _fernet(key).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(token: str, key: bytes) -> str:
    """Decrypt a single cell value. Empty values pass through unchanged."""
    if token == "":
        return token
    try:
        return _fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise WrongKeyError(
            "Wrong key or corrupted file: could not decrypt a value."
        ) from exc


def encrypt_text_spans(text: str, spans: list[tuple[int, int]], key: bytes) -> str:
    """Encrypt only the given (start, end) substrings of text, replacing
    each with a `[[ENC:<token>]]` marker. Everything outside the spans is
    left untouched. Spans are applied right-to-left so earlier offsets
    stay valid as the string is rewritten.
    """
    for start, end in sorted(spans, reverse=True):
        token = encrypt_value(text[start:end], key)
        text = f"{text[:start]}[[ENC:{token}]]{text[end:]}"
    return text


def decrypt_text_spans(text: str, key: bytes) -> str:
    """Reverse encrypt_text_spans: replace every `[[ENC:<token>]]` marker
    with its decrypted plaintext. Text with no markers passes through
    unchanged.
    """

    def _replace(match: re.Match) -> str:
        return decrypt_value(match.group(1), key)

    return _MARKER_RE.sub(_replace, text)
