"""Detect spans of PII within free text: regex for structured data,
spaCy NER for person names anywhere in a string (e.g. "...his name is
Kang Li").
"""

import logging
import re
import threading
import time

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
DATE_RE = re.compile(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\b")

_REGEX_DETECTORS = [EMAIL_RE, SSN_RE, DATE_RE]

_nlp = None
_nlp_lock = threading.Lock()
_cells_since_load = 0

# spaCy interns every new token string into nlp.vocab.strings and never
# releases it, so the model's memory grows with the number of *distinct*
# strings it has ever seen. Docs are freed; the vocabulary is not.
# Measured on unique free-text cells: ~3.5 KB of RSS per cell, growing
# linearly with no plateau (129 MB -> 269 MB over 40k cells), which is
# what puts a large CSV into MemoryError territory on an 8 GB machine.
# Reloading periodically returns the vocabulary to its baseline. The load
# costs ~0.3s, so amortized over this many cells it's free.
_RELOAD_EVERY_CELLS = 50_000


def _get_nlp():
    """Lazily load the spaCy model so app startup stays fast when this
    module's detection isn't needed for a given run."""
    global _nlp
    with _nlp_lock:
        if _nlp is None:
            import spacy

            logger.info("Loading spaCy model en_core_web_sm...")
            start = time.monotonic()
            _nlp = spacy.load("en_core_web_sm")
            logger.info("spaCy model loaded in %.2fs", time.monotonic() - start)
        return _nlp


def _recycle_nlp_if_stale():
    """Drop the model once it has seen enough cells, so the next call
    reloads it with a fresh vocabulary (see _RELOAD_EVERY_CELLS).

    Safe because find_pii_spans returns plain (int, int) tuples: no Doc,
    Span or Token outlives the call, so nothing can be invalidated by
    swapping the model out. An in-flight Doc keeps its own Vocab alive by
    reference until it is itself collected.
    """
    global _nlp, _cells_since_load
    _cells_since_load += 1
    if _cells_since_load < _RELOAD_EVERY_CELLS:
        return
    with _nlp_lock:
        if _nlp is not None:
            logger.info(
                "Recycling spaCy model after %d cells (vocab held %d strings)",
                _cells_since_load, len(_nlp.vocab.strings),
            )
            _nlp = None
        _cells_since_load = 0


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []
    spans = sorted(spans)
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


# ORG is included because the small NER model frequently mislabels unusual
# person names as organizations (e.g. "Lilly Petlock" -> ORG); leaking a
# name is worse than over-encrypting an organization name, and encryption
# is reversible either way.
_SENSITIVE_ENT_LABELS = {"PERSON", "ORG"}


def _extended_end(doc, ent) -> int:
    """Extend an entity rightward over adjacent unlabeled alphabetic
    noun-like tokens NER left out of the span — catches surnames the model
    didn't attach (e.g. only "Lilly" tagged in "Lilly petlock"). Tokens
    already inside another entity (like a DATE) block the extension.
    """
    end_tok = ent.end
    while end_tok < len(doc):
        tok = doc[end_tok]
        if (
            tok.ent_type_ == ""
            and tok.is_alpha
            and not tok.is_stop
            and tok.pos_ in ("PROPN", "NOUN", "X")
        ):
            end_tok += 1
        else:
            break
    last = doc[end_tok - 1]
    return last.idx + len(last)


def find_pii_spans(text: str) -> list[tuple[int, int]]:
    """Return non-overlapping (start, end) spans of detected PII in text."""
    if not text:
        return []

    spans = []
    for pattern in _REGEX_DETECTORS:
        for match in pattern.finditer(text):
            spans.append((match.start(), match.end()))

    doc = _get_nlp()(text)
    for ent in doc.ents:
        if ent.label_ in _SENSITIVE_ENT_LABELS:
            spans.append((ent.start_char, _extended_end(doc, ent)))

    _recycle_nlp_if_stale()
    return _merge_spans(spans)
