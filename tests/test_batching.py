"""Tests for batched NER (find_pii_spans_batch) and the buffered row loop.

process_csv buffers rows so every scanned cell in a chunk goes through
nlp.pipe together instead of one nlp() call per cell. That reorders when
the model runs relative to when rows are written, so the things to pin
down are: identical spans, identical output, and error/progress behaviour
that still refers to the right row.
"""

import csv
import re

import pytest

from npimasker import csv_processor
from npimasker.crypto import WrongKeyError, derive_key
from npimasker.csv_processor import process_csv
from npimasker.pii_detect import find_pii_spans, find_pii_spans_batch

KEY = derive_key("batch-key")

CORPUS = [
    "a person have walked in and his name is Kang Li",
    "working on case for Lilly petlock",
    "",
    "spoke with Kang Li yesterday",
    "   ",
    "Contact jane.doe@example.com re: SSN 123-45-6789, DOB 03/14/1990",
    "no sensitive content here",
    "Jane Doe met John Smith on 2024-01-15",
]


def test_batch_matches_per_cell_detection():
    assert find_pii_spans_batch(CORPUS) == [find_pii_spans(t) for t in CORPUS]


def test_batch_preserves_order_and_length():
    result = find_pii_spans_batch(CORPUS)
    assert len(result) == len(CORPUS)
    # The entry for a known text is the one for that text, not a neighbour.
    i = CORPUS.index("a person have walked in and his name is Kang Li")
    assert [CORPUS[i][s:e] for s, e in result[i]] == ["Kang Li"]


def test_batch_handles_empty_input():
    assert find_pii_spans_batch([]) == []
    assert find_pii_spans_batch(["", "", ""]) == [[], [], []]


def test_all_empty_batch_never_touches_the_model(monkeypatch):
    """Blank cells are filtered out before nlp.pipe, so a chunk of nothing
    but blanks must not load or invoke the model at all."""
    from npimasker import pii_detect

    def _boom():
        raise AssertionError("the model should not have been needed")

    monkeypatch.setattr(pii_detect, "_get_nlp", _boom)
    assert find_pii_spans_batch(["", "", ""]) == [[], [], []]


def _write(path, rows, headers=("ID", "Notes")):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def test_output_is_identical_regardless_of_batch_size(tmp_path, monkeypatch):
    """Chunking is an implementation detail: where the boundaries fall must
    not change which spans get encrypted, nor the round trip."""
    rows = [[str(i), CORPUS[i % len(CORPUS)]] for i in range(20)]
    src = tmp_path / "in.csv"
    _write(src, rows)
    original = src.read_text(encoding="utf-8")

    structures = {}
    for batch_rows in (1, 2, 3, 7, 500):
        monkeypatch.setattr(csv_processor, "_BATCH_ROWS", batch_rows)
        out = tmp_path / f"out_{batch_rows}.csv"
        process_csv(str(src), str(out), KEY, "encrypt", [1])

        back = tmp_path / f"back_{batch_rows}.csv"
        process_csv(str(out), str(back), KEY, "decrypt", [1])
        assert back.read_text(encoding="utf-8") == original, batch_rows

        # Ciphertext differs every run (random IV); compare the plaintext
        # left around the markers, which is what reveals the chosen spans.
        structures[batch_rows] = re.sub(
            r"\[\[ENC:[A-Za-z0-9_\-=]+\]\]", "[[ENC]]", out.read_text(encoding="utf-8")
        )

    assert len(set(structures.values())) == 1, structures
    assert "[[ENC]]" in next(iter(structures.values())), "nothing was encrypted at all"


def test_wrong_key_error_names_the_right_row_across_batches(tmp_path, monkeypatch):
    """Row numbering must survive buffering: the failing row is row 12 of
    the file, not row 2 of its chunk."""
    monkeypatch.setattr(csv_processor, "_BATCH_ROWS", 5)
    src = tmp_path / "enc.csv"
    good = tmp_path / "good.csv"
    _write(src, [[str(i), "Kang Li called"] for i in range(20)])
    process_csv(str(src), str(good), KEY, "encrypt", [1])

    # Corrupt the marker on file row 12 (data row 11).
    lines = good.read_text(encoding="utf-8").splitlines()
    lines[11] = lines[11].replace("[[ENC:", "[[ENC:zz")
    broken = tmp_path / "broken.csv"
    broken.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(WrongKeyError) as excinfo:
        process_csv(str(broken), str(tmp_path / "out.csv"), KEY, "decrypt", [1])
    assert "row 12" in str(excinfo.value)
    assert "'Notes'" in str(excinfo.value)


def test_progress_still_reports_across_chunk_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(csv_processor, "_BATCH_ROWS", 4)
    src = tmp_path / "in.csv"
    _write(src, [[str(i), "Full Name here"] for i in range(30)], headers=("ID", "Full Name"))

    seen = []
    process_csv(
        str(src), str(tmp_path / "out.csv"), KEY, "encrypt", [1],
        progress_callback=seen.append,
        progress_interval_rows=10,
        progress_interval_seconds=10_000,
    )
    assert seen == [10, 20, 30]


def test_ragged_rows_survive_buffering(tmp_path, monkeypatch):
    """A short row inside a chunk must not shift the cells of its
    neighbours - the batch is indexed by (position, column)."""
    monkeypatch.setattr(csv_processor, "_BATCH_ROWS", 2)
    src = tmp_path / "in.csv"
    with open(src, "w", newline="", encoding="utf-8") as f:
        f.write("ID,Notes\n")
        f.write("1,Kang Li called\n")
        f.write("2\n")  # no Notes column at all
        f.write("3,working on case for Lilly petlock\n")

    out = tmp_path / "out.csv"
    process_csv(str(src), str(out), KEY, "encrypt", [1])
    rows = list(csv.reader(out.open(newline="", encoding="utf-8")))
    assert rows[2] == ["2"]
    # The short row must not shift its neighbours' cells into the wrong slot.
    assert "Kang Li" not in rows[1][1] and rows[1][1].startswith("[[ENC:")
    assert "petlock" not in rows[3][1]
    assert rows[3][1].startswith("working on case for [[ENC:")

    back = tmp_path / "back.csv"
    process_csv(str(out), str(back), KEY, "decrypt", [1])
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_batch_size_is_at_the_measured_sweet_spot():
    """A tripwire, not a memory assertion (those are flaky).

    Throughput saturates at 64 while peak memory keeps climbing roughly
    linearly past it, because that many Doc objects are alive at once.
    Measured over 6,000 free-text cells: 64 -> 2.21 ms/cell at +48 MB,
    256 -> 2.19 ms/cell at +118 MB. Raising this back up buys under 1%
    and costs ~70 MB, so re-read the table in pii_detect before changing
    it.
    """
    from npimasker import pii_detect

    assert pii_detect._BATCH_SIZE == 64
