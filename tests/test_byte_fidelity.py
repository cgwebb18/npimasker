"""Records we don't change come out byte-for-byte as they went in.

Re-serialising through csv.writer can never be byte-faithful in general.
It writes what the dialect says, not what the file said: `"1","Zoe"`
becomes `1,Zoe`, a missing trailing newline gets added, and chasing that
with dialect sniffing is guesswork on top of guesswork.

So we don't re-serialise records we didn't touch. Each record's exact
source text is captured alongside its parsed fields, and if no selected
cell actually changed, the original text is written straight back out.
Only modified records go through the writer.

The guarantee that buys, stated exactly:

  - a record with no changed cell is byte-identical, including quoting,
    whitespace, and its own line terminator
  - in a record that *did* change, the changed cells are ciphertext and
    the rest may be re-quoted - `"Zoe"` can become `Zoe` - but always
    parses back to identical values

The second half is the honest limit. Making it byte-exact would mean
splicing at character offsets inside a record, which costs far more
complexity than it buys.
"""

import csv

import pytest

from npimasker.crypto import derive_key, looks_like_token
from npimasker.csv_processor import process_csv

KEY = derive_key("fidelity-key")

# Every shape here was measured against the pre-Phase-1 code; the ones
# marked below are the five it altered with nothing selected at all.
SHAPES = {
    "utf8-bom":            b'\xef\xbb\xbfID,Name\r\n1,Zoe\r\n',
    "cp1252-accents":      b'ID,Name\r\n1,Jos\xe9 \x92smart\x93\r\n',
    "unnecessary-quotes":  b'ID,"Name"\r\n"1","Zoe"\r\n',
    "lf-only":             b'ID,Name\n1,Zoe\n',
    "no-trailing-newline": b'ID,Name\r\n1,Zoe',
    "cr-only":             b'ID,Name\r1,Zoe\r',
    "ragged":              b'ID,Name,Extra\r\n1,Zoe\r\n2,Ann,x,y\r\n',
    "blank-line":          b'ID,Name\r\n\r\n1,Zoe\r\n',
    "leading-zero":        b'ID,Zip\r\n1,01234\r\n',
    "whitespace":          b'ID, Name \r\n1, Zoe \r\n',
    "embedded-quote":      b'ID,Name\r\n1,"say ""hi"""\r\n',
    "embedded-newline":    b'ID,Notes\r\n1,"line one\r\nline two"\r\n',
    "embedded-comma":      b'ID,Name\r\n1,"Doe, Jane"\r\n',
    "formula-looking":     b'ID,Calc\r\n1,=SUM(A1:A9)\r\n',
    "semicolon-delim":     b'ID;Name\r\n1;Zoe\r\n',
    "utf-16-le":           '﻿ID,Name\r\n1,Zoe\r\n'.encode("utf-16-le"),
    "empty-fields":        b'ID,A,B\r\n1,,\r\n',
    "quoted-empty":        b'ID,A,B\r\n1,"",""\r\n',
}


def _run(tmp_path, raw, selected, mode="encrypt", name="f.csv"):
    src = tmp_path / name
    out = tmp_path / f"out-{name}"
    src.write_bytes(raw)
    process_csv(str(src), str(out), KEY, mode, selected)
    return out.read_bytes()


# -- nothing selected: the file must come back untouched -------------------


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_nothing_selected_changes_nothing(tmp_path, name):
    raw = SHAPES[name]
    assert _run(tmp_path, raw, []) == raw


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_a_decrypt_pass_over_plaintext_changes_nothing(tmp_path, name):
    """Decryption infers treatment from content, so a plaintext cell in a
    selected column passes through - and must do so verbatim, not
    re-serialised."""
    raw = SHAPES[name]
    assert _run(tmp_path, raw, [0, 1], mode="decrypt") == raw


# -- selected, but the value didn't actually change ------------------------


def test_an_unchanged_record_keeps_its_exact_bytes(tmp_path):
    """Row 2's selected cell is empty, so encryption leaves it alone. That
    record must survive with its redundant quotes and spacing intact, even
    though its neighbours were rewritten."""
    raw = (b'ID,Full Name\r\n'
           b'1,Jane Doe\r\n'
           b'"2"," "\r\n'          # quoted, and a space is not empty...
           b'3,\r\n'               # ...but this one is
           b'4,Omar Ahmed\r\n')
    out = _run(tmp_path, raw, [1])

    assert b'3,\r\n' in out            # untouched record, verbatim
    assert b'1,Jane Doe' not in out    # neighbours really were encrypted
    assert b'4,Omar Ahmed' not in out


def test_the_header_is_never_reserialised(tmp_path):
    raw = b'"ID","Full Name","Notes"\r\n1,Jane Doe,hello\r\n'
    out = _run(tmp_path, raw, [1])
    assert out.startswith(b'"ID","Full Name","Notes"\r\n')


# -- records that did change ----------------------------------------------


def test_a_changed_record_round_trips_exactly(tmp_path):
    raw = (b'ID,Notes,Full Name\r\n'
           b'1,"quoted, comma",Jane Doe\r\n'
           b'2,"line\r\ntwo",Omar Ahmed\r\n')
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(enc), KEY, "encrypt", [2])
    process_csv(str(enc), str(dec), KEY, "decrypt", [2])

    # Byte-exact after a full round trip, embedded newline and all.
    assert dec.read_bytes() == raw


def test_a_changed_records_other_cells_parse_identically(tmp_path):
    """The documented limit: within a modified record, untouched cells may
    lose redundant quoting. They must still parse to the same values."""
    raw = b'ID,"Name","Notes"\r\n"1","Jane Doe","plain"\r\n'
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(out), KEY, "encrypt", [1])

    rows = list(csv.reader(out.read_text(encoding="utf-8").splitlines()))
    assert rows[0] == ["ID", "Name", "Notes"]
    assert rows[1][0] == "1"
    assert rows[1][2] == "plain"
    assert looks_like_token(rows[1][1])


def test_a_changed_record_uses_the_files_line_terminator(tmp_path):
    raw = b'ID,Full Name\n1,Jane Doe\n'
    out = _run(tmp_path, raw, [1])
    assert b'\r\n' not in out
    assert out.endswith(b'\n')


# -- trailing newline ------------------------------------------------------


@pytest.mark.parametrize("selected", [[], [1]])
def test_a_missing_trailing_newline_is_not_invented(tmp_path, selected):
    """csv.writer terminates every row, so a file that didn't end with a
    newline would silently grow one. True whether or not the last record
    was modified."""
    raw = b'ID,Full Name\r\n1,Jane Doe'
    out = _run(tmp_path, raw, selected)
    assert not out.endswith(b'\r\n')


@pytest.mark.parametrize("selected", [[], [1]])
def test_a_present_trailing_newline_is_kept(tmp_path, selected):
    raw = b'ID,Full Name\r\n1,Jane Doe\r\n'
    out = _run(tmp_path, raw, selected)
    assert out.endswith(b'\r\n')
    assert not out.endswith(b'\r\n\r\n')


def test_trailing_newline_handling_survives_utf16(tmp_path):
    """The terminator is two bytes per character here, so truncating a
    fixed number of bytes would corrupt the last character."""
    raw = '﻿ID,Name\r\n1,Zoe'.encode("utf-16-le")
    assert _run(tmp_path, raw, []) == raw


# -- the parser must not lose track ---------------------------------------


def test_records_spanning_many_lines_are_captured_whole(tmp_path):
    """The source-capture tee has to stay in step with csv.reader when a
    single record spans several physical lines."""
    raw = (b'ID,Notes\r\n'
           b'1,"a\r\nb\r\nc\r\nd"\r\n'
           b'2,plain\r\n'
           b'3,"e\r\nf"\r\n')
    assert _run(tmp_path, raw, []) == raw


def test_a_large_file_of_mixed_records_is_stable(tmp_path):
    """Crosses the 500-row batching boundary with a mix of changed and
    unchanged records, so buffering can't scramble which is which."""
    rows = [b'ID,Full Name\r\n']
    for i in range(1200):
        rows.append(b'%d,\r\n' % i if i % 3 == 0 else b'%d,Person %d\r\n' % (i, i))
    raw = b"".join(rows)
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    # Every third record had nothing to encrypt and is verbatim.
    assert b'\r\n999,\r\n' in enc.read_bytes()

    process_csv(str(enc), str(dec), KEY, "decrypt", [1])
    assert dec.read_bytes() == raw


def test_an_empty_input_is_still_rejected(tmp_path):
    src = tmp_path / "in.csv"
    src.write_bytes(b"")
    with pytest.raises(ValueError):
        process_csv(str(src), str(tmp_path / "out.csv"), KEY, "encrypt", [])
