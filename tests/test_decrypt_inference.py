"""Decryption infers a cell's treatment from its content, not its header.

Encrypting is header-driven: a "Full Name" column is encrypted whole, a
"Notes" column is scanned and only the detected spans are encrypted.
Decryption used to make the *same* header-driven decision independently,
which meant the two runs had to agree - and nothing enforced that they
did. Rename a column between the two runs (or select it differently) and
decryption picks the wrong path:

  whole-cell encrypted, decrypted as scanned  -> no markers found, the
      cell is returned unchanged: **ciphertext, silently, no error**
  span-encrypted, decrypted as whole-cell     -> decrypt_value on a cell
      full of markers -> WrongKeyError with the correct key

The first is the dangerous one. A user renames a column, decrypts, sees a
"Decryption complete" dialog, and ships a file that still holds encrypted
values.

The fix: decryption reads the data. The two encrypted shapes are provably
disjoint - a Fernet token is urlsafe-base64, whose alphabet cannot contain
"[" - so a cell is unambiguously one of three things:

  contains [[ENC:...]]  -> span-decrypt
  is a whole Fernet token -> whole-cell decrypt
  neither                 -> plaintext, pass through

This is a decode-time change only. Nothing about the file format moves,
so files written by earlier versions decrypt correctly: what is on disk
was always self-describing, the reader just wasn't reading it.
"""

import base64
import csv
import os

import pytest

from npimasker.crypto import (
    WrongKeyError,
    derive_key,
    encrypt_value,
    looks_like_damaged_token,
    looks_like_token,
)
from npimasker.csv_processor import process_csv

KEY = derive_key("decrypt-inference-key")
OTHER_KEY = derive_key("a-completely-different-key")

# Reliably yields at least one detected span, so the "scanned" arms of the
# matrix below really do produce markers rather than passing through.
SENTENCE = "a person walked in, his name is Kang Li"


def _write(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def _read(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _rename_header(path, index, new_name):
    """Rewrite one header cell in place, leaving every data row alone."""
    rows = _read(path)
    rows[0][index] = new_name
    _write(path, rows[0], rows[1:])


# -- looks_like_token ------------------------------------------------------


def test_real_tokens_are_recognised():
    assert looks_like_token(encrypt_value("Jane Doe", KEY))
    assert looks_like_token(encrypt_value("x", KEY))
    assert looks_like_token(encrypt_value("a much longer value " * 50, KEY))


def test_every_token_encrypt_value_emits_is_recognised():
    """Pins the detector to the producer. Fernet's own output is the only
    thing this has to recognise; if encrypt_value ever changes shape, this
    fails rather than the detector silently starting to return False and
    decryption silently starting to pass ciphertext through."""
    for i in range(100):
        assert looks_like_token(encrypt_value(f"value {i}", KEY))


def test_plaintext_is_not_a_token():
    for text in [
        "",
        " ",
        "Jane Doe",
        "a person walked in, his name is Kang Li",
        "jane.doe@example.com",
        "555-0101",
        "no sensitive content in this note",
    ]:
        assert not looks_like_token(text), text


def test_marker_text_is_not_a_token():
    """The disjointness the dispatch relies on: '[' is not in the base64
    alphabet, so a cell can never be both shapes at once."""
    token = encrypt_value("Jane Doe", KEY)
    assert not looks_like_token(f"[[ENC:{token}]]")
    assert not looks_like_token(f"see [[ENC:{token}]] here")


def test_truncated_or_padded_tokens_are_not_recognised():
    token = encrypt_value("Jane Doe", KEY)
    assert not looks_like_token(token[:40])          # too short
    assert not looks_like_token(token[:-1])          # broken padding
    assert not looks_like_token(token + " ")         # trailing space
    assert not looks_like_token(f" {token}")         # leading space
    assert not looks_like_token(f"{token} {token}")  # two, not one


def test_base64_of_something_else_is_not_recognised():
    """Long, validly-padded base64 that is not a Fernet token: the version
    byte check is what rejects it, not the length."""
    other = base64.urlsafe_b64encode(b"not a fernet token, just bytes" * 8).decode()
    assert len(other) > 100
    assert not looks_like_token(other)


def test_non_ascii_is_not_a_token():
    assert not looks_like_token("José García " * 20)


# -- the round-trip matrix -------------------------------------------------


@pytest.mark.parametrize(
    "encrypt_header,decrypt_header,expect_marker",
    [
        ("Full Name", "Full Name", False),   # whole -> whole   (worked before)
        ("Full Name", "Comments", False),    # whole -> scanned (silent ciphertext)
        ("Notes", "Notes", True),            # scanned -> scanned (worked before)
        ("Notes", "Patient Name", True),     # scanned -> whole (WrongKeyError)
    ],
)
def test_round_trip_survives_a_renamed_header(
    tmp_path, encrypt_header, decrypt_header, expect_marker
):
    """Every combination of how a cell was encrypted and how the header
    later reads must recover the original. Two of the four are the bug."""
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", encrypt_header], [["1", SENTENCE]])

    process_csv(str(src), str(enc), KEY, "encrypt", [1])

    # The cell really is in the shape this arm of the matrix claims.
    cell = _read(enc)[1][1]
    assert cell != SENTENCE
    if expect_marker:
        assert "[[ENC:" in cell
        assert not looks_like_token(cell)
    else:
        assert looks_like_token(cell)
        assert "[[ENC:" not in cell

    _rename_header(enc, 1, decrypt_header)
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])

    assert _read(dec)[1][1] == SENTENCE


def test_the_reported_reproducer(tmp_path):
    """The exact case that returned ciphertext with no error: a whole-cell
    column renamed to something the header heuristic reads as free text."""
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", "Full Name"], [["1", "Jane Doe"], ["2", "Omar Ahmed"]])

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    _rename_header(enc, 1, "Comments")
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])

    assert _read(dec) == [["ID", "Comments"], ["1", "Jane Doe"], ["2", "Omar Ahmed"]]


def test_a_column_can_hold_both_shapes_at_once(tmp_path):
    """Nothing forces a column to be uniform - two files concatenated, or a
    treatment changed between runs. Each cell is decided on its own."""
    src = tmp_path / "in.csv"
    dec = tmp_path / "dec.csv"
    whole = encrypt_value("Jane Doe", KEY)
    spans = f"call [[ENC:{encrypt_value('Omar Ahmed', KEY)}]] back"
    _write(src, ["ID", "Mixed"], [["1", whole], ["2", spans], ["3", "plain text"]])

    process_csv(str(src), str(dec), KEY, "decrypt", [1])

    assert _read(dec)[1:] == [
        ["1", "Jane Doe"],
        ["2", "call Omar Ahmed back"],
        ["3", "plain text"],
    ]


# -- passthrough -----------------------------------------------------------


@pytest.mark.parametrize("header", ["Full Name", "Notes"])
def test_plaintext_in_a_selected_column_passes_through(tmp_path, header):
    """Decrypting a cell that was never encrypted returns it unchanged
    under either header. Previously a whole-cell header raised
    WrongKeyError here, blaming the key for what was never a key problem."""
    src = tmp_path / "in.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", header], [["1", "Jane Doe"], ["2", ""], ["3", "   "]])

    process_csv(str(src), str(dec), KEY, "decrypt", [1])

    assert _read(dec)[1:] == [["1", "Jane Doe"], ["2", ""], ["3", "   "]]


def test_a_marker_spanning_the_whole_cell_is_span_decrypted(tmp_path):
    """The one place the shapes come closest: the marker covers the entire
    value, so the cell is *only* a token wrapped in brackets. contains_marker
    is checked first, so this can never take the whole-cell path."""
    src = tmp_path / "in.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", "Notes"], [["1", f"[[ENC:{encrypt_value('Kang Li', KEY)}]]"]])

    process_csv(str(src), str(dec), KEY, "decrypt", [1])

    assert _read(dec)[1][1] == "Kang Li"


# -- the loud failures have to survive -------------------------------------


@pytest.mark.parametrize("header", ["Full Name", "Notes"])
def test_wrong_key_against_a_whole_cell_token_still_raises(tmp_path, header):
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    _write(src, ["ID", "Full Name"], [["1", "Jane Doe"]])
    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    _rename_header(enc, 1, header)

    with pytest.raises(WrongKeyError) as excinfo:
        process_csv(str(enc), str(tmp_path / "dec.csv"), OTHER_KEY, "decrypt", [1])
    assert f"column '{header}'" in str(excinfo.value)


@pytest.mark.parametrize("header", ["Full Name", "Notes"])
def test_wrong_key_against_markers_still_raises(tmp_path, header):
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    _write(src, ["ID", "Notes"], [["1", SENTENCE]])
    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    _rename_header(enc, 1, header)

    with pytest.raises(WrongKeyError):
        process_csv(str(enc), str(tmp_path / "dec.csv"), OTHER_KEY, "decrypt", [1])


def test_a_token_shaped_value_that_is_not_ours_fails_loudly(tmp_path):
    """The accepted false positive. A value that decodes to >=73 bytes
    starting with Fernet's 0x80 version byte is indistinguishable from a
    token until the HMAC is checked - so it takes the whole-cell path and
    raises, rather than being passed through as plaintext. Loud, not
    silent, which is the side to err on."""
    impostor = base64.urlsafe_b64encode(b"\x80" + b"\xab" * 80).decode()
    assert looks_like_token(impostor)

    src = tmp_path / "in.csv"
    out = tmp_path / "dec.csv"
    _write(src, ["ID", "Notes"], [["1", impostor]])

    with pytest.raises(WrongKeyError):
        process_csv(str(src), str(out), KEY, "decrypt", [1])
    assert not out.exists()


def test_a_truncated_token_is_reported_not_passed_through(tmp_path):
    """Corruption is the one case where "not either shape" must not mean
    "plaintext": a clipped token matches neither, and passing it through
    would hand back ciphertext silently - the very failure this change is
    here to remove. Truncation is the realistic form, e.g. a spreadsheet
    clipping a long field."""
    token = encrypt_value("Jane Doe", KEY)
    src = tmp_path / "in.csv"
    out = tmp_path / "dec.csv"
    _write(src, ["ID", "Notes"], [["1", token[:80]]])

    with pytest.raises(WrongKeyError) as excinfo:
        process_csv(str(src), str(out), KEY, "decrypt", [1])
    assert "truncated or corrupted" in str(excinfo.value)
    assert "column 'Notes'" in str(excinfo.value)
    assert not out.exists()


def test_damaged_token_detection():
    token = encrypt_value("Jane Doe", KEY)
    assert looks_like_damaged_token(token[:80])       # truncated
    assert looks_like_damaged_token(token[:-1])       # one char lost
    assert looks_like_damaged_token(token + "!")      # junk appended
    assert not looks_like_damaged_token(token)        # intact
    assert not looks_like_damaged_token("Jane Doe")   # ordinary text
    assert not looks_like_damaged_token("")
    assert not looks_like_damaged_token(f"[[ENC:{token}]]")


def test_the_guard_never_fires_on_an_intact_file(tmp_path):
    """The guard sits on the plaintext path, so the risk it introduces is
    false positives on real data. Nothing a normal round trip produces may
    trip it."""
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", "Full Name", "Notes"],
           [[str(i), f"Person{i} Name{i}", SENTENCE] for i in range(50)])

    process_csv(str(src), str(enc), KEY, "encrypt", [1, 2])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1, 2])
    assert dec.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_a_failed_decrypt_still_writes_no_output(tmp_path):
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, ["ID", "Full Name"], [["1", "Jane Doe"]])
    process_csv(str(src), str(enc), KEY, "encrypt", [1])

    before = sorted(os.listdir(tmp_path))
    with pytest.raises(WrongKeyError):
        process_csv(str(enc), str(dec), OTHER_KEY, "decrypt", [1])
    assert not dec.exists()
    assert sorted(os.listdir(tmp_path)) == before


# -- unchanged behaviour ---------------------------------------------------


def test_unselected_columns_are_still_copied_through(tmp_path):
    src = tmp_path / "in.csv"
    dec = tmp_path / "dec.csv"
    token = encrypt_value("Jane Doe", KEY)
    _write(src, ["ID", "Full Name", "Other"], [["1", token, token]])

    process_csv(str(src), str(dec), KEY, "decrypt", [1])

    rows = _read(dec)
    assert rows[1][1] == "Jane Doe"
    assert rows[1][2] == token  # not selected, so not touched


def test_encrypt_is_still_header_driven(tmp_path):
    """Phase 1 changes decryption only. Encryption still has to be told
    what to do, because a plaintext cell carries no hint."""
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, ["ID", "Full Name", "Notes"], [["1", SENTENCE, SENTENCE]])

    process_csv(str(src), str(out), KEY, "encrypt", [1, 2])

    row = _read(out)[1]
    assert looks_like_token(row[1])   # whole-cell header
    assert "[[ENC:" in row[2]         # scanned header
