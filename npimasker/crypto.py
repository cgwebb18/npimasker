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
import binascii
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


# A Fernet token is 1 version byte + 8 timestamp + 16 IV + >=16 ciphertext
# + 32 HMAC, so 73 bytes at minimum, which base64 to 100 characters.
_MIN_TOKEN_BYTES = 73
_MIN_TOKEN_CHARS = 100
_FERNET_VERSION = 0x80


def looks_like_token(value: str) -> bool:
    """Whether the entire value is a Fernet token produced by this tool.

    Used by decryption to tell a whole-cell-encrypted value from one that
    holds [[ENC:...]] markers, without having to trust that the column
    header still reads the way it did when the file was encrypted.

    Decoding rather than pattern-matching the "gAAAAA" prefix: the prefix
    is an artefact of the version byte plus a timestamp whose high bytes
    happen to be zero, so it is only stable for as long as that stays
    true, whereas the version byte is part of the format. validate=True
    matters - without it base64 silently discards characters outside the
    alphabet, so ordinary prose could decode to something plausible.

    A false positive is possible in principle: any value that decodes to
    73+ bytes beginning 0x80 is indistinguishable from a token until the
    HMAC is checked. Such a value takes the whole-cell path and raises
    WrongKeyError. That is the right way round - the alternative is
    treating a real token as plaintext and returning ciphertext silently.
    """
    if len(value) < _MIN_TOKEN_CHARS:
        return False
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= _MIN_TOKEN_BYTES and raw[0] == _FERNET_VERSION


# Every Fernet token this tool emits starts with these characters: they are
# the base64 of the 0x80 version byte plus the five leading zero bytes of an
# 8-byte big-endian timestamp, which stay zero until roughly the year 36000.
_TOKEN_PREFIX = "gAAAAA"


def looks_like_damaged_token(value: str) -> bool:
    """Whether a value opens like a Fernet token but is not a valid one.

    Truncation is the realistic way an encrypted cell gets damaged - a
    spreadsheet clipping a long field, a bad export. Without this the
    damaged value matches neither shape and decryption returns it as
    "plaintext", which means handing back ciphertext with no error: the
    exact failure the content-based dispatch exists to remove.

    A prefix is a weaker signal than the decode looks_like_token does, and
    it is used only to escalate to a loud error - never to decide that
    something *is* a token. Wrong in one direction it reports a corrupt
    cell that was really prose beginning "gAAAAA"; wrong in the other it
    just stops catching a corruption it never caught before.
    """
    return value.startswith(_TOKEN_PREFIX) and not looks_like_token(value)


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
