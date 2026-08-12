"""Tests for periodic spaCy model recycling in npimasker.pii_detect.

spaCy interns every new token string into nlp.vocab.strings and never
releases it, so memory grows with the number of distinct strings the
model has ever seen - linearly, with no plateau, which is what makes a
large CSV run out of memory. The model is dropped periodically so the
vocabulary returns to baseline.

The thing that must not change is which spans are detected.
"""

import logging

import pytest

from npimasker import pii_detect
from npimasker.pii_detect import find_pii_spans


@pytest.fixture(autouse=True)
def _restore_model_state():
    """_nlp and the cell counter are module globals shared with every
    other test file; put them back however we found them."""
    original_nlp = pii_detect._nlp
    original_count = pii_detect._cells_since_load
    original_every = pii_detect._RELOAD_EVERY_CELLS
    yield
    pii_detect._nlp = original_nlp
    pii_detect._cells_since_load = original_count
    pii_detect._RELOAD_EVERY_CELLS = original_every


# Distinct surface strings per cell - the case that grows the vocabulary.
def _cell(i):
    return f"note {i}: spoke with Kang{i} Li{i} about invoice INV{i:05d}"


def test_model_is_dropped_after_the_configured_number_of_cells(monkeypatch):
    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 5)
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0

    for i in range(4):
        find_pii_spans(_cell(i))
    assert pii_detect._nlp is not None, "should still be holding the model"
    assert pii_detect._cells_since_load == 4

    find_pii_spans(_cell(4))  # the 5th cell trips the threshold
    assert pii_detect._nlp is None, "model should have been released"
    assert pii_detect._cells_since_load == 0


def test_vocabulary_returns_to_baseline_after_a_recycle(monkeypatch):
    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 25)
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0

    find_pii_spans(_cell(0))
    baseline = len(pii_detect._nlp.vocab.strings)

    for i in range(1, 25):
        find_pii_spans(_cell(i))
    assert pii_detect._nlp is None  # recycled

    find_pii_spans(_cell(999))
    grown = len(pii_detect._nlp.vocab.strings)
    # A freshly loaded model knows only its own strings plus this one cell,
    # not the 25 cells' worth of names and invoice numbers seen before it.
    assert grown < baseline + 50


def test_detection_is_identical_with_and_without_recycling(monkeypatch):
    corpus = [
        "a person have walked in and his name is Kang Li",
        "working on case for Lilly petlock",
        "spoke with Kang Li yesterday",
        "Patient seen today. Jane Doe called about the invoice.",
        "Contact jane.doe@example.com re: SSN 123-45-6789, DOB 03/14/1990",
        "no sensitive content here",
        "   ",
        "",
        "Jane Doe met John Smith on 2024-01-15",
    ] * 6

    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 10**9)
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0
    baseline = [find_pii_spans(t) for t in corpus]

    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 7)  # recycles repeatedly
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0
    recycled = [find_pii_spans(t) for t in corpus]

    assert recycled == baseline
    assert any(baseline), "corpus should actually detect something"


def test_spans_are_correct_across_a_recycle_boundary(monkeypatch):
    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 1)  # recycle every cell
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0

    text = "a person have walked in and his name is Kang Li"
    for _ in range(3):
        spans = find_pii_spans(text)
        assert "Kang Li" in [text[s:e] for s, e in spans]


def test_recycling_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 2)
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0

    with caplog.at_level(logging.INFO, logger="npimasker.pii_detect"):
        find_pii_spans(_cell(1))
        find_pii_spans(_cell(2))

    messages = [r.getMessage() for r in caplog.records]
    assert any("Recycling spaCy model" in m for m in messages), messages


def test_empty_text_does_not_count_toward_the_recycle_budget(monkeypatch):
    """find_pii_spans short-circuits on empty text without touching the
    model, so those calls must not advance the counter either."""
    monkeypatch.setattr(pii_detect, "_RELOAD_EVERY_CELLS", 3)
    pii_detect._nlp = None
    pii_detect._cells_since_load = 0

    for _ in range(10):
        find_pii_spans("")
    assert pii_detect._cells_since_load == 0


def test_reload_threshold_is_at_the_measured_sweet_spot():
    """A tripwire against drift, paired with the one in test_batching.

    This is a memory-vs-time dial: the threshold is how much vocabulary
    growth is tolerated before a reset, at ~0.3s per reload. 10k is about
    35 MB of amplitude for ~2% overhead. Set it too high and a mid-size
    run pays for batching's buffers without ever reaching a reset, which
    is what made 50k worse than no recycling at all.
    """
    assert pii_detect._RELOAD_EVERY_CELLS == 10_000
