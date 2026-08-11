"""Tests for chunked encoding detection in npimasker.csv_processor.

detect_csv_encoding used to read the entire file into memory and decode
it whole, costing several times the file size in peak RSS. It now feeds
chunks to an incremental decoder. The risk that buys is a chunk boundary
landing inside a multi-byte sequence and changing the answer, so that is
what these tests hammer.
"""

import pytest

from npimasker import csv_processor
from npimasker.csv_processor import detect_csv_encoding, read_headers


def _whole_file_reference(path):
    """The original implementation, kept here as the oracle."""
    with open(path, "rb") as f:
        raw = f.read()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            raw.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _write(tmp_path, data, name="f.csv"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


# Chunk sizes small enough to split multi-byte sequences constantly.
@pytest.fixture(params=[1, 2, 3, 5, 64, 1 << 20])
def chunk_size(request, monkeypatch):
    monkeypatch.setattr(csv_processor, "_SNIFF_CHUNK_BYTES", request.param)
    return request.param


CASES = {
    "empty": b"",
    "ascii": b"id,name\n1,Jane\n",
    "utf8_bom": b"\xef\xbb\xbfid,name\n1,Jane\n",
    "utf8_accents": "id,name\n1,café naïve\n".encode("utf-8"),
    "utf8_cjk": "id,name\n1,中文\n".encode("utf-8"),
    "utf8_emoji": "id,name\n1,\U0001f642\n".encode("utf-8"),
    "cp1252_middot": b"id,name\n1,caf\xe9 \xb7 dot\n",
    "cp1252_smart_quotes": b"id,name\n1,\x92quoted\x93\n",
    "latin1_only": b"id,name\n1,\x81\x8d\x8f\x90\x9d\n",
    "truncated_utf8_at_eof": b"id,name\n1,\xe4\xb8",
    "bare_bom": b"\xef\xbb\xbf",
    "truncated_bom_1": b"\xef",
    "truncated_bom_2": b"\xef\xbb",
    "bom_then_ascii": b"\xef\xbbX",
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_matches_whole_file_decoding(tmp_path, chunk_size, name):
    path = _write(tmp_path, CASES[name])
    assert detect_csv_encoding(str(path)) == _whole_file_reference(str(path))


def test_multibyte_sequence_split_across_every_boundary(tmp_path, chunk_size):
    """A chunk boundary inside a multi-byte character must not change the
    verdict - the incremental decoder has to carry the partial sequence."""
    blob = ("h\xe9llo w\xf6rld 中文 \U0001f642 " * 40).encode("utf-8")
    for cut in range(0, len(blob), 11):
        path = _write(tmp_path, blob[:cut])
        assert detect_csv_encoding(str(path)) == _whole_file_reference(str(path)), cut


def test_tiny_files_take_the_whole_buffer_path(tmp_path):
    """Under 3 bytes a file can be nothing but a truncated BOM, where an
    incremental utf-8-sig decoder accepts what a one-shot decode rejects.
    Those sizes are handled by decoding outright instead."""
    for data in (b"", b"\xef", b"\xef\xbb", b"a", b"ab"):
        path = _write(tmp_path, data)
        assert detect_csv_encoding(str(path)) == _whole_file_reference(str(path)), data


def test_late_invalid_byte_is_still_found(tmp_path):
    """The sniffer must scan the whole file: a cp1252-only byte a long way
    in has to demote the answer, or process_csv would blow up mid-run."""
    data = b"id,name\n" + (b"1,plain ascii row\n" * 50_000) + b"2,caf\xe9 \xb7\n"
    path = _write(tmp_path, data)
    assert detect_csv_encoding(str(path)) == "cp1252"


def test_headers_round_trip_through_each_encoding(tmp_path, chunk_size):
    utf8 = _write(tmp_path, "id,café\n".encode("utf-8"), "u.csv")
    assert read_headers(str(utf8)) == ["id", "café"]

    # 0xe9 is é and 0xb7 is a middot in cp1252 - the byte that motivated
    # the cp1252 fallback in the first place (commit 5de6657).
    cp = _write(tmp_path, b"id,caf\xe9 \xb7\n", "c.csv")
    assert read_headers(str(cp)) == ["id", "café ·"]


def test_bom_is_stripped_from_the_first_header(tmp_path, chunk_size):
    path = _write(tmp_path, b"\xef\xbb\xbfid,name\n1,Jane\n")
    assert read_headers(str(path))[0] == "id"
