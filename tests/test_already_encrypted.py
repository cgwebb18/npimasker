"""Tests for the guard that refuses to encrypt text already holding markers.

Two failure modes share one root cause - the tool cannot tell its own
[[ENC:...]] markers from text that merely looks like them:

1. Free text containing a literal "[[ENC:<base64ish>]]" survives encryption
   untouched, and decrypting it later raises "wrong key or corrupted file"
   with the *correct* key, aborting the whole run.

2. Re-encrypting an already-encrypted file nests markers, because the NER
   model finds entities inside base64 Fernet tokens. A single decrypt then
   silently returns partially-encrypted output with no error at all -
   measured at 4 of 200 rows on a realistic corpus.

process_csv now refuses at the point the bad file would be created, which
covers both. Whole-cell columns are exempt: the marker is just bytes there.
"""

import csv
import os

import pytest

from npimasker.crypto import (
    AlreadyEncryptedError,
    WrongKeyError,
    contains_marker,
    derive_key,
)
from npimasker.csv_processor import process_csv

KEY = derive_key("already-encrypted-key")

MARKER = "[[ENC:gAAAAABmZmZmZmZmZmZm_-==]]"


def _write(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def _read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


# -- contains_marker -------------------------------------------------------


def test_contains_marker_matches_what_the_decrypter_would_try():
    assert contains_marker(MARKER)
    assert contains_marker(f"see {MARKER} here")
    assert contains_marker("[[ENC:a]]")


def test_contains_marker_ignores_marker_shaped_but_invalid_text():
    """These pass through decryption untouched, so refusing them would be a
    false positive - the guard has to be exactly as strict as the decrypter."""
    for text in ["[[ENC:]]", "[[ENC: spaced ]]", "[[ENC:a.b]]", "[[enc:abc]]",
                 "[[ENC:abc", "ENC:abc]]", "plain text"]:
        assert not contains_marker(text), text


# -- the guard -------------------------------------------------------------


def test_encrypting_a_scanned_cell_with_a_marker_is_refused(tmp_path):
    src = tmp_path / "in.csv"
    _write(src, ["ID", "Notes"], [["1", "ok"], ["2", f"see {MARKER} here"]])

    with pytest.raises(AlreadyEncryptedError) as excinfo:
        process_csv(str(src), str(tmp_path / "out.csv"), KEY, "encrypt", [1])

    message = str(excinfo.value)
    assert "Row 3" in message          # file line 3, i.e. the second data row
    assert "'Notes'" in message
    assert "already been encrypted" in message


def test_re_encrypting_an_encrypted_file_is_refused(tmp_path):
    """The realistic trigger: a user runs encrypt twice by mistake."""
    src = tmp_path / "in.csv"
    once = tmp_path / "once.csv"
    _write(src, ["ID", "Notes"],
           [[str(i), f"a person have walked in and his name is Person{i} Name{i}"]
            for i in range(20)])

    process_csv(str(src), str(once), KEY, "encrypt", [1])
    assert "[[ENC:" in once.read_text(encoding="utf-8")

    with pytest.raises(AlreadyEncryptedError):
        process_csv(str(once), str(tmp_path / "twice.csv"), KEY, "encrypt", [1])


def test_refusal_reports_the_first_offending_row(tmp_path):
    src = tmp_path / "in.csv"
    rows = [[str(i), "clean text"] for i in range(10)]
    rows[4][1] = f"first offender {MARKER}"
    rows[7][1] = f"second offender {MARKER}"
    _write(src, ["ID", "Notes"], rows)

    with pytest.raises(AlreadyEncryptedError) as excinfo:
        process_csv(str(src), str(tmp_path / "out.csv"), KEY, "encrypt", [1])
    assert "Row 6" in str(excinfo.value)  # data row 5 -> file line 6


def test_marker_shaped_but_invalid_text_still_encrypts(tmp_path):
    src = tmp_path / "in.csv"
    back = tmp_path / "back.csv"
    out = tmp_path / "out.csv"
    _write(src, ["ID", "Notes"],
           [["1", "see [[ENC:]] and [[ENC: spaced ]] near Kang Li"]])

    process_csv(str(src), str(out), KEY, "encrypt", [1])
    process_csv(str(out), str(back), KEY, "decrypt", [1])
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_marker_in_a_whole_cell_column_is_allowed(tmp_path):
    """Whole-cell columns encrypt the entire value, so a marker inside one is
    just bytes and round-trips fine - refusing it would be a false positive."""
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    back = tmp_path / "back.csv"
    _write(src, ["ID", "Full Name"], [["1", f"Jane {MARKER} Doe"]])

    process_csv(str(src), str(out), KEY, "encrypt", [1])
    process_csv(str(out), str(back), KEY, "decrypt", [1])
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_marker_in_an_unselected_column_is_ignored(tmp_path):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, ["ID", "Notes", "Other"], [["1", "Kang Li called", f"{MARKER}"]])

    process_csv(str(src), str(out), KEY, "encrypt", [1])  # column 2 not selected
    rows = _read(out)
    assert rows[1][2] == MARKER  # copied through verbatim


def test_decrypt_mode_is_unaffected(tmp_path):
    """Markers are expected input when decrypting; the guard is encrypt-only."""
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", "Notes"], [["1", "a person walked in, his name is Kang Li"]])

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])  # must not raise
    assert dec.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


# -- interaction with the atomic write -------------------------------------


def test_a_refused_run_leaves_no_output_and_no_temp_file(tmp_path):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    rows = [[str(i), "clean text"] for i in range(600)]
    rows[550][1] = f"offender {MARKER}"  # in the second buffered chunk
    _write(src, ["ID", "Notes"], rows)

    before = sorted(os.listdir(tmp_path))
    with pytest.raises(AlreadyEncryptedError):
        process_csv(str(src), str(out), KEY, "encrypt", [1])

    assert not out.exists()
    assert sorted(os.listdir(tmp_path)) == before


def test_a_refused_run_does_not_clobber_an_existing_output(tmp_path):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, ["ID", "Notes"], [["1", f"offender {MARKER}"]])
    out.write_text("PREVIOUS GOOD RESULT", encoding="utf-8")

    with pytest.raises(AlreadyEncryptedError):
        process_csv(str(src), str(out), KEY, "encrypt", [1])
    assert out.read_text(encoding="utf-8") == "PREVIOUS GOOD RESULT"


# -- the regression this exists to prevent ---------------------------------


def test_double_encrypt_no_longer_silently_partially_decrypts(tmp_path):
    """Before the guard: re-encrypting nested markers in ~2% of rows, and a
    single decrypt returned 196/200 correct cells with no error raised. The
    remaining 4 still held ciphertext and nothing said so."""
    src = tmp_path / "in.csv"
    once = tmp_path / "once.csv"
    _write(src, ["ID", "Notes"],
           [[str(i), f"a person have walked in and his name is Person{i} Name{i}"]
            for i in range(200)])

    process_csv(str(src), str(once), KEY, "encrypt", [1])
    with pytest.raises(AlreadyEncryptedError):
        process_csv(str(once), str(tmp_path / "twice.csv"), KEY, "encrypt", [1])

    # The correct path still works and recovers every row in one pass.
    back = tmp_path / "back.csv"
    process_csv(str(once), str(back), KEY, "decrypt", [1])
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_already_encrypted_is_not_a_wrong_key_error():
    """The GUI branches on these separately - one is a fixable wrong-file
    mistake, the other is a key problem."""
    assert not issubclass(AlreadyEncryptedError, WrongKeyError)
    assert not issubclass(WrongKeyError, AlreadyEncryptedError)
