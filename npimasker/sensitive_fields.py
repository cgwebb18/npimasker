"""Default keyword list used to detect sensitive CSV columns by header name.

Edit SENSITIVE_KEYWORDS to add/remove fields the tool should treat as
sensitive by default. Matching is case-insensitive and looks for whole
keyword phrases inside the (normalized) header text.
"""

import re

SENSITIVE_KEYWORDS = [
    # name
    "name", "first name", "last name", "full name", "middle name",
    "patient name", "provider name",
    # email
    "email", "e-mail",
    # phone
    "phone", "mobile", "fax", "contact number", "telephone",
    # address
    "address", "street", "city", "state", "zip", "zipcode", "postal",
    # ssn / tax id
    "ssn", "social security", "tax id", "ein",
    # date of birth
    "dob", "date of birth", "birth date", "birthdate",
    # npi / medical / insurance
    "npi", "medical record", "mrn", "insurance", "member id", "policy number",
]


# Headers in these categories are encrypted as a whole cell rather than
# scanned for embedded PII spans: phone/address formats are too varied to
# regex reliably, medical-record/insurance IDs have no fixed format, and
# name columns stay whole-cell so a dedicated Name column is never left
# unencrypted if NER misses a short, context-free name string. NER still
# catches names embedded in *other* (non-Name-headed) columns.
WHOLE_CELL_KEYWORDS = [
    # name
    "name", "first name", "last name", "full name", "middle name",
    "patient name", "provider name",
    # phone
    "phone", "mobile", "fax", "contact number", "telephone",
    # address
    "address", "street", "city", "state", "zip", "zipcode", "postal",
    # npi / medical / insurance
    "npi", "medical record", "mrn", "insurance", "member id", "policy number",
]


def _normalize(header: str) -> str:
    cleaned = re.sub(r"[^a-z0-9 ]", " ", header.strip().lower())
    return re.sub(r"\s+", " ", cleaned).strip()


def _matches_any(header: str, keywords: list[str]) -> bool:
    # Normalize the keywords too, not just the header. _normalize turns
    # every non-alphanumeric character into a space, so a keyword written
    # with punctuation ("e-mail") could never match any header - not even
    # a header spelled the same way. That silently disabled the "e-mail"
    # keyword entirely, leaving an "E-Mail" column unticked by default.
    normalized = f" {_normalize(header)} "
    return any(f" {_normalize(kw)} " in normalized for kw in keywords)


def is_sensitive_header(header: str) -> bool:
    return _matches_any(header, SENSITIVE_KEYWORDS)


def is_whole_cell_header(header: str) -> bool:
    """Whether this column should be encrypted as a whole cell rather than
    scanned for embedded PII spans (see WHOLE_CELL_KEYWORDS above)."""
    return _matches_any(header, WHOLE_CELL_KEYWORDS)


def detect_sensitive_columns(headers: list[str]) -> list[int]:
    """Return the indices of headers that look sensitive."""
    return [i for i, h in enumerate(headers) if is_sensitive_header(h)]
