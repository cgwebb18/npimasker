"""Every run re-reads what it wrote and proves it before committing it.

The fidelity work in the two preceding commits fixed the alterations I
could find by inspection. This is the part that covers the ones I could
not: rather than trusting the write path, the output is read back and
checked cell by cell against the input.

  - a column the user did not select must be byte-identical
  - an encrypted cell must decrypt back to exactly what was there
  - a decrypted cell must hold no leftover marker or token
  - row counts, field counts and the header must all line up

Verification runs after the writer closes and *before* the temp file is
renamed into place, so a failure means no output at all - the atomic
write already guarantees that, this just supplies another reason to
abort. An existing file from a previous run is left alone.

What it is worth is different in the two directions, and worth being
plain about. Encrypting, the check is a genuinely independent inverse:
decryption is a separate code path, so it catches real logic errors.
Decrypting, it re-runs the same computation, so it verifies structure,
alignment and I/O rather than logic - there the "nothing encrypted left
behind" check is the part that carries weight, and it is aimed squarely
at the silent-ciphertext class of bug.
"""

import csv
import os

import pytest

from npimasker import csv_processor
from npimasker.crypto import derive_key, encrypt_value
from npimasker.csv_processor import (
    VerificationError,
    _verify_output,
    detect_encoding_info,
    process_csv,
)

KEY = derive_key("verification-key")
OTHER = derive_key("other-key")


def _write(path, rows, encoding="utf-8", newline="\r\n"):
    with open(path, "w", newline="", encoding=encoding) as f:
        w = csv.writer(f, lineterminator=newline)
        w.writerows(rows)
    return str(path)


def _check(tmp_path, src_rows, out_rows, mode="encrypt", selected=(1,), key=KEY):
    src = _write(tmp_path / "in.csv", src_rows)
    out = _write(tmp_path / "out.csv", out_rows)
    _verify_output(src, out, key, mode, set(selected), detect_encoding_info(src))


# -- the verifier itself ---------------------------------------------------


def test_a_matching_pair_passes(tmp_path):
    token = encrypt_value("Jane Doe", KEY)
    _check(tmp_path,
           [["ID", "Full Name"], ["1", "Jane Doe"]],
           [["ID", "Full Name"], ["1", token]])


def test_an_unencrypted_cell_that_did_not_need_changing_passes(tmp_path):
    """An empty cell, or a scanned cell where nothing was detected, comes
    out identical. That is correct, not a mismatch."""
    _check(tmp_path,
           [["ID", "Notes"], ["1", ""], ["2", "nothing sensitive here"]],
           [["ID", "Notes"], ["1", ""], ["2", "nothing sensitive here"]])


def test_a_changed_cell_that_does_not_decrypt_back_is_caught(tmp_path):
    wrong = encrypt_value("SOMETHING ELSE", KEY)
    with pytest.raises(VerificationError) as excinfo:
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane Doe"]],
               [["ID", "Full Name"], ["1", wrong]])
    assert "row 2" in str(excinfo.value).lower()
    assert "Full Name" in str(excinfo.value)


def test_a_cell_encrypted_with_the_wrong_key_is_caught(tmp_path):
    with pytest.raises(VerificationError):
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane Doe"]],
               [["ID", "Full Name"], ["1", encrypt_value("Jane Doe", OTHER)]])


def test_a_modified_unselected_cell_is_caught(tmp_path):
    """The column the user did not tick is the one they are most entitled
    to assume nobody touched."""
    with pytest.raises(VerificationError) as excinfo:
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane Doe"]],
               [["ID", "Full Name"], ["9", encrypt_value("Jane Doe", KEY)]])
    assert "ID" in str(excinfo.value)


def test_a_changed_header_is_caught(tmp_path):
    with pytest.raises(VerificationError):
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane Doe"]],
               [["ID", "Name"], ["1", encrypt_value("Jane Doe", KEY)]])


def test_a_dropped_row_is_caught(tmp_path):
    with pytest.raises(VerificationError) as excinfo:
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane"], ["2", "Omar"]],
               [["ID", "Full Name"], ["1", encrypt_value("Jane", KEY)]])
    assert "row" in str(excinfo.value).lower()


def test_an_extra_row_is_caught(tmp_path):
    with pytest.raises(VerificationError):
        _check(tmp_path,
               [["ID", "Full Name"], ["1", "Jane"]],
               [["ID", "Full Name"],
                ["1", encrypt_value("Jane", KEY)],
                ["2", encrypt_value("Omar", KEY)]])


def test_a_dropped_field_is_caught(tmp_path):
    with pytest.raises(VerificationError):
        _check(tmp_path,
               [["ID", "Full Name", "Notes"], ["1", "Jane", "hi"]],
               [["ID", "Full Name"], ["1", encrypt_value("Jane", KEY)]])


def test_decrypt_leaving_a_marker_behind_is_caught(tmp_path):
    """The silent-ciphertext failure, caught at the last possible moment
    even if every earlier guard were to miss it."""
    inner = encrypt_value("Kang Li", KEY)
    with pytest.raises(VerificationError) as excinfo:
        _check(tmp_path,
               [["ID", "Notes"], ["1", f"met [[ENC:{inner}]] today"]],
               [["ID", "Notes"], ["1", f"met [[ENC:{inner}]] today"]],
               mode="decrypt")
    assert "still" in str(excinfo.value).lower()


def test_decrypt_leaving_a_bare_token_behind_is_caught(tmp_path):
    token = encrypt_value("Jane Doe", KEY)
    with pytest.raises(VerificationError):
        _check(tmp_path,
               [["ID", "Full Name"], ["1", token]],
               [["ID", "Full Name"], ["1", token]],
               mode="decrypt")


def test_marker_shaped_junk_in_plaintext_is_not_a_leftover(tmp_path):
    """The leftover check has to be exactly as strict as the decrypter.

    "[[ENC:notarealtoken]]" passes through decryption untouched, so it is
    legitimate plaintext output - flagging it would fail a correct run.
    Only a marker whose payload is a real token means something was
    genuinely left encrypted.
    """
    junk = "[[ENC:gAAAAABmZmZmZmZmZmZm_-==]]"
    token = encrypt_value(f"Jane {junk} Doe", KEY)
    _check(tmp_path,
           [["ID", "Full Name"], ["1", token]],
           [["ID", "Full Name"], ["1", f"Jane {junk} Doe"]],
           mode="decrypt")


def test_a_correct_decrypt_passes(tmp_path):
    token = encrypt_value("Jane Doe", KEY)
    _check(tmp_path,
           [["ID", "Full Name"], ["1", token]],
           [["ID", "Full Name"], ["1", "Jane Doe"]],
           mode="decrypt")


# -- wired into process_csv ------------------------------------------------


def test_an_injected_encryption_bug_is_caught_and_no_file_is_written(tmp_path, monkeypatch):
    """The point of the whole exercise: a wrong value reaches the output
    and nothing else notices. Verification is the thing that does."""
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, [["ID", "Full Name"], ["1", "Jane Doe"], ["2", "Omar Ahmed"]])

    real = csv_processor.encrypt_value
    monkeypatch.setattr(csv_processor, "encrypt_value",
                        lambda value, key: real("WRONG", key))

    before = sorted(os.listdir(tmp_path))
    with pytest.raises(VerificationError):
        process_csv(str(src), str(out), KEY, "encrypt", [1])

    assert not out.exists()
    assert sorted(os.listdir(tmp_path)) == before


def test_a_failed_verification_does_not_clobber_a_previous_output(tmp_path, monkeypatch):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, [["ID", "Full Name"], ["1", "Jane Doe"]])
    out.write_text("PREVIOUS GOOD RESULT", encoding="utf-8")

    real = csv_processor.encrypt_value
    monkeypatch.setattr(csv_processor, "encrypt_value",
                        lambda value, key: real("WRONG", key))

    with pytest.raises(VerificationError):
        process_csv(str(src), str(out), KEY, "encrypt", [1])
    assert out.read_text(encoding="utf-8") == "PREVIOUS GOOD RESULT"


def test_verify_false_skips_the_check_entirely(tmp_path, monkeypatch):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, [["ID", "Full Name"], ["1", "Jane Doe"]])

    def _boom(*args, **kwargs):
        raise AssertionError("verification ran despite verify=False")

    monkeypatch.setattr(csv_processor, "_verify_output", _boom)
    process_csv(str(src), str(out), KEY, "encrypt", [1], verify=False)
    assert out.exists()


def test_verification_is_on_by_default(tmp_path, monkeypatch):
    src = tmp_path / "in.csv"
    out = tmp_path / "out.csv"
    _write(src, [["ID", "Full Name"], ["1", "Jane Doe"]])

    calls = []
    real = csv_processor._verify_output
    monkeypatch.setattr(csv_processor, "_verify_output",
                        lambda *a, **k: (calls.append(1), real(*a, **k))[1])

    process_csv(str(src), str(out), KEY, "encrypt", [1])
    assert calls == [1]


def _read_rows(path):
    info = detect_encoding_info(str(path))
    with open(path, newline="", encoding=info.read_codec) as f:
        return list(csv.reader(f))


@pytest.mark.parametrize("raw", [
    b'ID,Full Name\r\n1,Jane Doe\r\n',
    b'ID,Full Name\r\n1,Jos\xe9 Garc\xeda\r\n',                      # cp1252
    b'\xef\xbb\xbfID,Full Name\r\n1,Jane Doe\r\n',                   # utf-8 BOM
    '﻿ID,Full Name\r\n1,Jane Doe\r\n'.encode("utf-16-le"),           # utf-16
    b'ID,Full Name\n1,Jane Doe',                                     # LF, no final NL
    b'ID,"Full Name"\r\n"1","Doe, Jane"\r\n',                        # quoting
])
def test_real_runs_verify_across_encodings_and_shapes(tmp_path, raw):
    """Verification must not become a source of false alarms on exactly
    the files the fidelity work was written for.

    Values, not bytes: every row here has its selected cell changed, so
    the record is re-serialised and may lose redundant quoting. Byte
    fidelity for untouched records is covered in test_byte_fidelity.
    """
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])
    assert _read_rows(dec) == _read_rows(src)


def test_encrypting_every_non_ascii_value_can_lose_the_source_encoding(tmp_path):
    """A real limit, recorded rather than hidden.

    Ciphertext is pure ASCII. If every non-ASCII byte in a file sits in an
    encrypted column, the encrypted file carries no evidence of the
    original codec - it is indistinguishable from UTF-8 - so a later
    decrypt writes UTF-8. The text is recovered exactly; the bytes are
    not. UTF-8 is the right choice for that fallback because it can encode
    anything a decrypted value might contain, where cp1252 could fail.

    Nothing is lost when any unencrypted column still carries a non-ASCII
    byte, which is the common case - see the test below.
    """
    raw = b'ID,Full Name\r\n1,Jos\xe9 Garc\xeda\r\n'
    src, enc, dec = tmp_path / "in.csv", tmp_path / "enc.csv", tmp_path / "dec.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])

    assert _read_rows(dec) == _read_rows(src)            # text recovered exactly
    assert dec.read_bytes() != raw                       # but re-encoded
    assert dec.read_bytes() == 'ID,Full Name\r\n1,José García\r\n'.encode("utf-8")


def test_an_untouched_non_ascii_column_preserves_the_encoding(tmp_path):
    """The common case, and why the limit above rarely bites: one cp1252
    byte anywhere outside the encrypted columns keeps the file's identity."""
    raw = b'ID,Full Name,Notes\r\n1,Jos\xe9 Garc\xeda,caf\xe9 \xb7 visit\r\n'
    src, enc, dec = tmp_path / "in.csv", tmp_path / "enc.csv", tmp_path / "dec.csv"
    src.write_bytes(raw)

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])
    assert dec.read_bytes() == raw


def test_verification_survives_a_scanned_column(tmp_path):
    src = tmp_path / "in.csv"
    enc = tmp_path / "enc.csv"
    dec = tmp_path / "dec.csv"
    _write(src, [["ID", "Notes"],
                 ["1", "a person walked in, his name is Kang Li"],
                 ["2", "nothing sensitive at all"]])

    process_csv(str(src), str(enc), KEY, "encrypt", [1])
    process_csv(str(enc), str(dec), KEY, "decrypt", [1])
    assert dec.read_bytes() == src.read_bytes()


def test_verification_cost_is_not_pathological(tmp_path):
    """Deliberately loose - this exists to catch an accidental O(n^2), not
    to police a few percent on a loaded machine."""
    import time

    src = tmp_path / "in.csv"
    _write(src, [["ID", "Full Name"]] + [[str(i), f"Person {i}"] for i in range(5000)])

    t = time.monotonic()
    process_csv(str(src), str(tmp_path / "a.csv"), KEY, "encrypt", [1], verify=False)
    without = time.monotonic() - t

    t = time.monotonic()
    process_csv(str(src), str(tmp_path / "b.csv"), KEY, "encrypt", [1], verify=True)
    with_verify = time.monotonic() - t

    assert with_verify < without * 3 + 1.0, f"{without:.2f}s -> {with_verify:.2f}s"
