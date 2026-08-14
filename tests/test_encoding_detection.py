"""Encoding is detected from the file, and preserved on the way out.

Partners on Windows saw blank column names on large exports. The cause:
detection only ever tried utf-8-sig, cp1252, latin-1 - and never looked for
a UTF-16 BOM. UTF-16 is mostly ASCII interleaved with NUL bytes, which
cp1252 accepts happily, so a UTF-16 file was decoded as cp1252 and every
header after the first came out beginning with a NUL:

    ['ÿþI\\x00D\\x00', '\\x00F\\x00u\\x00l\\x00l\\x00 \\x00N\\x00a\\x00m\\x00e']

Windows Tk renders a leading NUL as an empty string, hence blank columns.
Worse, the run then "succeeded" and wrote a mangled file with no error.
Large files land here because they don't come from Excel (which caps near
a million rows) - they come from PowerShell, where Out-File and `>`
default to UTF-16LE.

Two rules follow, and both are tested here:

  1. A BOM is authoritative and is checked first. Failing that, NUL bytes
     mean this is not an 8-bit encoding - guess the endianness from NUL
     parity, and if that isn't decisive, refuse. Guessing is what caused
     the bug; the fallback for "don't know" is an error, never latin-1.

  2. Output is written in the input's codec, with the input's BOM and line
     terminator. Previously everything was written as UTF-8 regardless,
     which silently turned a cp1252 file into mojibake the moment Excel
     reopened it.
"""

import codecs

import pytest

from npimasker.crypto import derive_key
from npimasker.csv_processor import (
    EncodingInfo,
    UnsupportedEncodingError,
    detect_csv_encoding,
    detect_encoding_info,
    process_csv,
    read_headers,
)

KEY = derive_key("encoding-key")

HEADER = "ID,Full Name,E-Mail"
BODY = "1,Zoe Ng,z@x.com"
SAMPLE = f"{HEADER}\r\n{BODY}\r\n"


def _write(tmp_path, name, raw: bytes):
    path = tmp_path / name
    path.write_bytes(raw)
    return str(path)


# -- BOM detection ---------------------------------------------------------


@pytest.mark.parametrize(
    "name,raw,read_codec,write_codec,bom",
    [
        ("utf-8", SAMPLE.encode("utf-8"), "utf-8-sig", "utf-8", b""),
        ("utf-8-bom", SAMPLE.encode("utf-8-sig"), "utf-8-sig", "utf-8", codecs.BOM_UTF8),
        # Needs a byte that is not valid UTF-8, or the file is genuinely
        # ambiguous: pure ASCII is identical under both codecs.
        ("cp1252", b"ID,Notes\r\n1,caf\xe9 \xb7 dot\r\n", "cp1252", "cp1252", b""),
        ("utf-16-le", codecs.BOM_UTF16_LE + SAMPLE.encode("utf-16-le"),
         "utf-16", "utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-16-be", codecs.BOM_UTF16_BE + SAMPLE.encode("utf-16-be"),
         "utf-16", "utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-32-le", codecs.BOM_UTF32_LE + SAMPLE.encode("utf-32-le"),
         "utf-32", "utf-32-le", codecs.BOM_UTF32_LE),
        ("utf-32-be", codecs.BOM_UTF32_BE + SAMPLE.encode("utf-32-be"),
         "utf-32", "utf-32-be", codecs.BOM_UTF32_BE),
    ],
)
def test_encoding_is_identified_and_the_bom_recorded_separately(
    tmp_path, name, raw, read_codec, write_codec, bom
):
    """The codec and whether there was a BOM are two different facts.

    Conflating them is how a BOM-less UTF-8 file (detected as utf-8-sig)
    would acquire a BOM it never had the moment we wrote it back out.
    """
    info = detect_encoding_info(_write(tmp_path, f"{name}.csv", raw))
    assert info.read_codec == read_codec
    assert info.write_codec == write_codec
    assert info.bom == bom


def test_utf32_is_not_mistaken_for_utf16(tmp_path):
    """BOM_UTF32_LE is b'\\xff\\xfe\\x00\\x00' and starts with BOM_UTF16_LE,
    so checking UTF-16 first silently misreads every UTF-32 file."""
    raw = codecs.BOM_UTF32_LE + SAMPLE.encode("utf-32-le")
    info = detect_encoding_info(_write(tmp_path, "u32.csv", raw))
    assert info.write_codec == "utf-32-le"
    assert read_headers(_write(tmp_path, "u32b.csv", raw)) == ["ID", "Full Name", "E-Mail"]


def test_a_bomless_utf8_file_does_not_acquire_a_bom(tmp_path):
    info = detect_encoding_info(_write(tmp_path, "plain.csv", SAMPLE.encode("utf-8")))
    assert info.bom == b""


# -- BOM-less UTF-16 -------------------------------------------------------


@pytest.mark.parametrize("codec,expected", [("utf-16-le", "utf-16-le"),
                                            ("utf-16-be", "utf-16-be")])
def test_bomless_utf16_is_found_by_nul_parity(tmp_path, codec, expected):
    """ASCII in UTF-16LE puts its NULs on odd offsets, BE on even ones.

    read_codec must name the endianness explicitly here: Python's plain
    "utf-16" assumes *native* byte order when there is no BOM, which would
    decode a BE file as LE on every machine we ship to.
    """
    raw = (SAMPLE * 20).encode(codec)
    info = detect_encoding_info(_write(tmp_path, "bomless.csv", raw))
    assert info.read_codec == expected
    assert info.write_codec == expected
    assert info.bom == b""


def test_nul_bytes_are_never_decoded_as_latin1(tmp_path):
    """latin-1 maps all 256 bytes, so it accepts anything - which is why it
    is the fallback, and exactly why it must not swallow a NUL-bearing file
    and call the result success."""
    raw = b"\x00\x01\x02\x00\xff\xfe\x00\x99" * 200
    with pytest.raises(UnsupportedEncodingError) as excinfo:
        detect_encoding_info(_write(tmp_path, "binary.csv", raw))
    assert "text" in str(excinfo.value).lower()


def test_the_refusal_names_a_next_step(tmp_path):
    raw = b"\x00\x01\x02\x00\xff\xfe\x00\x99" * 200
    with pytest.raises(UnsupportedEncodingError) as excinfo:
        detect_encoding_info(_write(tmp_path, "binary.csv", raw))
    assert "UTF-8" in str(excinfo.value)


# -- line terminator and trailing newline ----------------------------------


@pytest.mark.parametrize("newline", ["\r\n", "\n", "\r"])
def test_line_terminator_is_detected(tmp_path, newline):
    raw = f"{HEADER}{newline}{BODY}{newline}".encode("utf-8")
    assert detect_encoding_info(_write(tmp_path, "nl.csv", raw)).newline == newline


def test_mixed_line_terminators_take_the_first(tmp_path):
    raw = f"{HEADER}\r\n{BODY}\n{BODY}\n".encode("utf-8")
    assert detect_encoding_info(_write(tmp_path, "mixed.csv", raw)).newline == "\r\n"


def test_line_terminator_is_detected_through_utf16(tmp_path):
    """The terminator is two bytes per character here, so a byte-level
    search for b'\\n' would find the wrong thing."""
    raw = codecs.BOM_UTF16_LE + f"{HEADER}\r\n{BODY}\r\n".encode("utf-16-le")
    assert detect_encoding_info(_write(tmp_path, "u16nl.csv", raw)).newline == "\r\n"


@pytest.mark.parametrize("tail,expected", [("\r\n", True), ("", False)])
def test_trailing_newline_is_recorded(tmp_path, tail, expected):
    raw = f"{HEADER}\r\n{BODY}{tail}".encode("utf-8")
    assert detect_encoding_info(_write(tmp_path, "tail.csv", raw)).final_newline is expected


def test_an_empty_file_does_not_crash_detection(tmp_path):
    info = detect_encoding_info(_write(tmp_path, "empty.csv", b""))
    assert isinstance(info, EncodingInfo)
    assert info.bom == b""


# -- the reported bug ------------------------------------------------------


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_headers_from_a_utf16_file_are_clean(tmp_path, codec):
    """The bug as partners saw it. Every header used to arrive with an
    embedded NUL, which Windows Tk renders as an empty string."""
    headers = read_headers(_write(tmp_path, "x.csv", SAMPLE.encode(codec)))
    assert headers == ["ID", "Full Name", "E-Mail"]
    assert not any("\x00" in h for h in headers)
    assert not any("﻿" in h for h in headers)


# -- output preserves the input's encoding ---------------------------------


@pytest.mark.parametrize("codec,bom", [
    ("utf-8", b""),
    ("utf-8-sig", codecs.BOM_UTF8),
    ("cp1252", b""),
    ("utf-16", codecs.BOM_UTF16_LE),
    ("utf-16-be", b""),
])
def test_output_is_written_in_the_inputs_encoding(tmp_path, codec, bom):
    src = _write(tmp_path, "in.csv", SAMPLE.encode(codec))
    out = str(tmp_path / "out.csv")

    process_csv(src, out, KEY, "encrypt", [])   # nothing selected

    raw = (tmp_path / "out.csv").read_bytes()
    assert raw.startswith(bom) if bom else not raw.startswith(codecs.BOM_UTF8)
    assert detect_encoding_info(out).write_codec == detect_encoding_info(src).write_codec


def test_a_cp1252_file_survives_a_round_trip_byte_for_byte(tmp_path):
    """The alteration partners would actually notice: accents and smart
    quotes turning to mojibake because the file came back as UTF-8."""
    raw = b"ID,Notes\r\n1,Jos\xe9 \x92smart\x93 caf\xe9 \xb7 dot\r\n"
    src = _write(tmp_path, "in.csv", raw)
    out = str(tmp_path / "out.csv")

    process_csv(src, out, KEY, "encrypt", [])

    assert (tmp_path / "out.csv").read_bytes() == raw


def test_a_utf16_file_survives_a_round_trip(tmp_path):
    raw = codecs.BOM_UTF16_LE + SAMPLE.encode("utf-16-le")
    src = _write(tmp_path, "in.csv", raw)
    out = str(tmp_path / "out.csv")

    process_csv(src, out, KEY, "encrypt", [])

    assert (tmp_path / "out.csv").read_bytes() == raw


def test_a_bom_is_neither_added_nor_dropped(tmp_path):
    for name, raw in [("with.csv", SAMPLE.encode("utf-8-sig")),
                      ("without.csv", SAMPLE.encode("utf-8"))]:
        src = _write(tmp_path, name, raw)
        out = str(tmp_path / f"out-{name}")
        process_csv(src, out, KEY, "encrypt", [])
        written = (tmp_path / f"out-{name}").read_bytes()
        assert written.startswith(codecs.BOM_UTF8) == raw.startswith(codecs.BOM_UTF8)


@pytest.mark.parametrize("newline", ["\r\n", "\n"])
def test_line_terminators_are_preserved(tmp_path, newline):
    raw = f"{HEADER}{newline}{BODY}{newline}".encode("utf-8")
    src = _write(tmp_path, "in.csv", raw)
    out = str(tmp_path / "out.csv")

    process_csv(src, out, KEY, "encrypt", [])

    assert (tmp_path / "out.csv").read_bytes() == raw


def test_encrypted_output_still_round_trips_in_a_non_utf8_encoding(tmp_path):
    """Preserving cp1252 must not break the actual job: ciphertext is
    base64 so it always encodes, but the surrounding text has to survive
    both directions."""
    raw = b"ID,Full Name,Notes\r\n1,Jos\xe9 Garc\xeda,caf\xe9 \xb7 visit\r\n"
    src = _write(tmp_path, "in.csv", raw)
    enc = str(tmp_path / "enc.csv")
    dec = str(tmp_path / "dec.csv")

    process_csv(src, enc, KEY, "encrypt", [1])
    assert detect_encoding_info(enc).write_codec == "cp1252"

    process_csv(enc, dec, KEY, "decrypt", [1])
    assert (tmp_path / "dec.csv").read_bytes() == raw


def test_a_character_the_output_codec_cannot_hold_fails_loudly(tmp_path):
    """Decrypting into a cp1252 file could produce a character cp1252 has
    no room for. errors='strict' plus a clear message - never a silent '?'
    substitution, which would be data loss disguised as success."""
    # cp1252 input, and a whole-cell column so the value goes through
    # encrypt_value rather than the span encoder.
    src = _write(tmp_path, "in.csv", b"ID,Full Name\r\n1,Jos\xe9 Garc\xeda\r\n")
    out = str(tmp_path / "out.csv")

    def _explode(value, key):
        return "emoji \U0001f642"

    import npimasker.csv_processor as mod
    original = mod.encrypt_value
    mod.encrypt_value = _explode
    try:
        with pytest.raises(UnicodeEncodeError):
            process_csv(src, out, KEY, "encrypt", [1])
    finally:
        mod.encrypt_value = original
    assert not (tmp_path / "out.csv").exists()


# -- the old entry point is unchanged --------------------------------------


@pytest.mark.parametrize("raw,expected", [
    (b"ID,Name\n1,Zoe\n", "utf-8-sig"),
    (b"\xef\xbb\xbfID,Name\n1,Zoe\n", "utf-8-sig"),
    (b"ID,Name\n1,caf\xe9\n", "cp1252"),
    (b"ID,No\x81tes\n1,x\n", "latin-1"),
])
def test_detect_csv_encoding_keeps_its_old_answers(tmp_path, raw, expected):
    """104 existing tests pin this function's return values. It stays a
    thin wrapper so none of them have to change."""
    assert detect_csv_encoding(_write(tmp_path, "f.csv", raw)) == expected
