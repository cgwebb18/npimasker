"""process_csv accepts an explicit per-column treatment.

Until now the header alone decided whether a selected column was encrypted
whole or scanned for embedded PII. That is a good default and stays the
default, but it is only a guess about what a column contains, and it is
not always the guess the user wants:

  - a free-text column that is entirely sensitive ("Clinical Note") is
    better encrypted whole than partially scanned, and scanning it is
    also where all the runtime goes - forcing whole-cell is the escape
    hatch for a file that would otherwise take half an hour
  - a column headed "Name" that actually holds a sentence is better
    scanned than encrypted whole

whole_cell_overrides maps a column index to True (whole) or False
(scanned). Absent indices, and whole_cell_overrides=None, fall back to
the header heuristic, so every existing caller behaves exactly as before.
"""

import csv

import pytest

from npimasker.crypto import contains_marker, derive_key, looks_like_token
from npimasker.csv_processor import process_csv
from npimasker.sensitive_fields import is_whole_cell_header

KEY = derive_key("column-treatments-key")

SENTENCE = "a person walked in, his name is Kang Li"


def _write(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def _read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _round_trip(tmp_path, headers, rows, selected, overrides):
    """Encrypt with the given overrides, then decrypt with none at all.

    Decryption deliberately gets no overrides: it infers treatment from
    content, so a user who picks a non-default treatment on the way in
    does not have to remember it on the way out.
    """
    src, enc, dec = tmp_path / "in.csv", tmp_path / "enc.csv", tmp_path / "dec.csv"
    _write(src, headers, rows)
    process_csv(str(src), str(enc), KEY, "encrypt", selected,
                whole_cell_overrides=overrides)
    process_csv(str(enc), str(dec), KEY, "decrypt", selected)
    return _read(enc), _read(dec), _read(src)


# -- forcing whole-cell on a column the heuristic would scan ---------------


def test_forcing_whole_cell_on_a_free_text_column(tmp_path):
    enc, dec, src = _round_trip(
        tmp_path, ["ID", "Notes"], [["1", SENTENCE]], [1], {1: True}
    )
    assert looks_like_token(enc[1][1])
    assert not contains_marker(enc[1][1])
    assert dec == src


def test_forcing_whole_cell_protects_text_the_scanner_would_miss(tmp_path):
    """The reason a user would reach for this: NER is best-effort, and an
    all-lowercase name is a documented miss. Whole-cell has no such gap."""
    missed = "spoke to lilly petlock about the referral"
    enc, dec, src = _round_trip(
        tmp_path, ["ID", "Notes"], [["1", missed]], [1], {1: True}
    )
    assert missed not in enc[1][1]
    assert dec == src


def test_forcing_whole_cell_skips_the_model_entirely(tmp_path, monkeypatch):
    """The performance escape hatch. If a forced column still reached the
    NER model the feature would not buy the user anything on a large file,
    so assert the model is never even loaded."""
    import npimasker.pii_detect as pii_detect

    def _boom():
        raise AssertionError("NER model loaded for a forced whole-cell column")

    monkeypatch.setattr(pii_detect, "_get_nlp", _boom)

    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, ["ID", "Notes"], [[str(i), SENTENCE] for i in range(50)])
    process_csv(str(src), str(out), KEY, "encrypt", [1], whole_cell_overrides={1: True})

    assert all(looks_like_token(r[1]) for r in _read(out)[1:])


# -- forcing scanned on a column the heuristic would encrypt whole ---------


def test_forcing_scanned_on_a_name_column(tmp_path):
    text = "Kang Li (see chart)"
    enc, dec, src = _round_trip(
        tmp_path, ["ID", "Full Name"], [["1", text]], [1], {1: False}
    )
    assert contains_marker(enc[1][1])
    assert not looks_like_token(enc[1][1])
    assert enc[1][1].endswith("(see chart)")  # non-PII text left in place
    assert dec == src


def test_forcing_scanned_applies_the_already_encrypted_guard(tmp_path):
    """The guard exempts whole-cell columns, where a marker is just bytes.
    Forcing a column to scanned has to bring the guard with it."""
    from npimasker.crypto import AlreadyEncryptedError

    src = tmp_path / "in.csv"
    marker = "[[ENC:gAAAAABmZmZmZmZmZmZm_-==]]"
    _write(src, ["ID", "Full Name"], [["1", f"Jane {marker} Doe"]])

    # Default (whole-cell header): allowed.
    process_csv(str(src), str(tmp_path / "a.csv"), KEY, "encrypt", [1])

    # Forced to scanned: refused.
    with pytest.raises(AlreadyEncryptedError):
        process_csv(str(src), str(tmp_path / "b.csv"), KEY, "encrypt", [1],
                    whole_cell_overrides={1: False})


# -- the default must not move ---------------------------------------------


@pytest.mark.parametrize("overrides", [None, {}])
def test_no_overrides_reproduces_the_header_heuristic(tmp_path, overrides):
    headers = ["ID", "Full Name", "E-Mail", "Phone Number", "Notes", "Comments"]
    selected = [1, 2, 3, 4, 5]
    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, headers, [["1"] + [SENTENCE] * 5])

    process_csv(str(src), str(out), KEY, "encrypt", selected,
                whole_cell_overrides=overrides)

    row = _read(out)[1]
    for idx in selected:
        if is_whole_cell_header(headers[idx]):
            assert looks_like_token(row[idx]), headers[idx]
        else:
            assert contains_marker(row[idx]), headers[idx]


def test_a_partial_override_leaves_other_columns_on_the_heuristic(tmp_path):
    headers = ["ID", "Full Name", "Notes", "Comments"]
    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, headers, [["1", SENTENCE, SENTENCE, SENTENCE]])

    process_csv(str(src), str(out), KEY, "encrypt", [1, 2, 3],
                whole_cell_overrides={2: True})

    row = _read(out)[1]
    assert looks_like_token(row[1])   # Full Name  - heuristic, whole
    assert looks_like_token(row[2])   # Notes      - overridden to whole
    assert contains_marker(row[3])    # Comments   - heuristic, scanned


def test_an_override_on_an_unselected_column_does_nothing(tmp_path):
    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, ["ID", "Notes", "Other"], [["1", SENTENCE, SENTENCE]])

    process_csv(str(src), str(out), KEY, "encrypt", [1],
                whole_cell_overrides={2: True, 1: True})

    row = _read(out)[1]
    assert looks_like_token(row[1])
    assert row[2] == SENTENCE  # not selected, so untouched


def test_an_override_on_an_out_of_range_column_is_ignored(tmp_path):
    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, ["ID", "Notes"], [["1", SENTENCE]])

    process_csv(str(src), str(out), KEY, "encrypt", [1],
                whole_cell_overrides={99: True})

    assert contains_marker(_read(out)[1][1])


# -- interaction with buffering --------------------------------------------


def test_overrides_hold_across_chunk_boundaries(tmp_path):
    """Rows are buffered in chunks of 500 and scanned cells batched through
    the model per chunk, so a mixed selection has to stay correct either
    side of the boundary."""
    rows = [[str(i), SENTENCE, SENTENCE] for i in range(1200)]
    enc, dec, src = _round_trip(
        tmp_path, ["ID", "Whole", "Scanned"], rows, [1, 2], {1: True, 2: False}
    )
    assert len(enc) == 1201
    for row in enc[1:]:
        assert looks_like_token(row[1])
        assert contains_marker(row[2])
    assert dec == src


def test_every_column_forced_whole_needs_no_model(tmp_path, monkeypatch):
    """The whole point of the escape hatch on a big file: with nothing left
    to scan, the run must not touch NER at all."""
    import npimasker.pii_detect as pii_detect

    monkeypatch.setattr(
        pii_detect, "_get_nlp",
        lambda: (_ for _ in ()).throw(AssertionError("model loaded")),
    )

    rows = [[str(i), SENTENCE, SENTENCE] for i in range(1200)]
    src, out = tmp_path / "in.csv", tmp_path / "out.csv"
    _write(src, ["ID", "Notes", "Comments"], rows)

    process_csv(str(src), str(out), KEY, "encrypt", [1, 2],
                whole_cell_overrides={1: True, 2: True})

    assert len(_read(out)) == 1201


# -- decrypt --------------------------------------------------------------


def test_decrypt_ignores_overrides_entirely(tmp_path):
    """Decryption infers treatment from content, so an override there is
    meaningless - and must not be able to break a correct file."""
    src, enc = tmp_path / "in.csv", tmp_path / "enc.csv"
    dec_a, dec_b = tmp_path / "a.csv", tmp_path / "b.csv"
    _write(src, ["ID", "Full Name", "Notes"], [["1", SENTENCE, SENTENCE]])
    process_csv(str(src), str(enc), KEY, "encrypt", [1, 2])

    process_csv(str(enc), str(dec_a), KEY, "decrypt", [1, 2])
    process_csv(str(enc), str(dec_b), KEY, "decrypt", [1, 2],
                whole_cell_overrides={1: False, 2: True})

    assert _read(dec_a) == _read(dec_b) == _read(src)
