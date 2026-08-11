"""Unit-level coverage of existing behavior in crypto, sensitive_fields and
csv_processor. These document what the code does today; anything surprising
is called out in a comment rather than asserted as an aspiration.
"""

import csv

import pytest

from cryptography.fernet import Fernet

from npimasker.crypto import (
    WrongKeyError,
    decrypt_text_spans,
    decrypt_value,
    derive_key,
    encrypt_text_spans,
    encrypt_value,
    generate_passphrase,
)
from npimasker.csv_processor import detect_csv_encoding, process_csv, read_headers
from npimasker.sensitive_fields import (
    SENSITIVE_KEYWORDS,
    WHOLE_CELL_KEYWORDS,
    detect_sensitive_columns,
    is_sensitive_header,
    is_whole_cell_header,
)

# derive_key() runs 480k PBKDF2 iterations (~0.3s), so derive once and share.
KEY = derive_key("unit-test-key")
OTHER_KEY = derive_key("a-different-unit-test-key")


def _write_csv(path, rows, encoding="utf-8"):
    with open(path, "w", newline="", encoding=encoding) as f:
        csv.writer(f).writerows(rows)


def _read_csv(path, encoding="utf-8"):
    with open(path, newline="", encoding=encoding) as f:
        return list(csv.reader(f))


# --------------------------------------------------------------------------
# crypto: encrypt_value / decrypt_value
# --------------------------------------------------------------------------


def test_empty_string_passes_through_both_directions():
    assert encrypt_value("", KEY) == ""
    assert decrypt_value("", KEY) == ""


def test_unicode_values_round_trip_exactly():
    values = [
        "José Muñoz-Álvarez",
        "北京市朝阳区",
        "patient 🙂 emoji 👨‍👩‍👧 zwj",
        "mixed: café ‒ 東京 ‒ 😀",
    ]
    for value in values:
        assert decrypt_value(encrypt_value(value, KEY), KEY) == value


def test_very_long_value_round_trips():
    value = "Jane Doe, 12 Elm St. " * 5000
    token = encrypt_value(value, KEY)
    assert token != value
    assert decrypt_value(token, KEY) == value


def test_whitespace_only_value_is_encrypted_not_passed_through():
    # Only the exact empty string short-circuits; "   " is real content.
    for value in [" ", "   ", "\t", "\n"]:
        token = encrypt_value(value, KEY)
        assert token != value
        assert decrypt_value(token, KEY) == value


def test_ciphertext_is_non_deterministic_but_both_decrypt():
    plaintext = "Jane Doe"
    first = encrypt_value(plaintext, KEY)
    second = encrypt_value(plaintext, KEY)
    assert first != second  # Fernet IV makes identical cells look different
    assert decrypt_value(first, KEY) == plaintext
    assert decrypt_value(second, KEY) == plaintext


def test_decrypt_value_with_wrong_key_raises_wrong_key_error():
    token = encrypt_value("Jane Doe", KEY)
    with pytest.raises(WrongKeyError):
        decrypt_value(token, OTHER_KEY)


def test_decrypt_value_wraps_malformed_input_as_wrong_key_error():
    # Never a raw InvalidToken/ValueError leaking out of the crypto layer.
    token = encrypt_value("Jane Doe", KEY)
    bad_inputs = [
        "not a valid token!!!",          # malformed base64
        token[:20],                      # truncated token
        token[:-4],                      # tail chopped off
        "   ",                           # whitespace garbage
        "=",                             # base64 padding only
        "aaaaaaaaaaaaaaaa",              # decodable base64, wrong version byte
    ]
    for bad in bad_inputs:
        with pytest.raises(WrongKeyError):
            decrypt_value(bad, KEY)


def test_wrong_key_error_message_is_user_facing():
    with pytest.raises(WrongKeyError) as excinfo:
        decrypt_value("garbage!!", KEY)
    assert "could not decrypt" in str(excinfo.value)


# --------------------------------------------------------------------------
# crypto: derive_key / generate_passphrase
# --------------------------------------------------------------------------


def test_derive_key_output_is_accepted_by_fernet():
    # Fernet raises if the key isn't 32 url-safe-base64-encoded bytes.
    fernet = Fernet(KEY)
    assert fernet.decrypt(fernet.encrypt(b"x")) == b"x"
    assert len(KEY) == 44


def test_derive_key_handles_unicode_passphrases():
    unicode_key = derive_key("contraseña-café-🔑")
    assert unicode_key == derive_key("contraseña-café-🔑")
    assert unicode_key != KEY
    assert decrypt_value(encrypt_value("Jane Doe", unicode_key), unicode_key) == "Jane Doe"


def test_derive_key_is_sensitive_to_small_passphrase_changes():
    assert derive_key("unit-test-key") == KEY
    assert derive_key("unit-test-keY") != KEY
    assert derive_key("unit-test-key ") != KEY


def test_generate_passphrase_values_are_distinct_and_nontrivial():
    passphrases = [generate_passphrase() for _ in range(50)]
    assert len(set(passphrases)) == 50
    for passphrase in passphrases:
        assert len(passphrase) >= 32
        assert passphrase.strip() == passphrase


# --------------------------------------------------------------------------
# crypto: encrypt_text_spans / decrypt_text_spans
# --------------------------------------------------------------------------


def test_multiple_non_adjacent_spans_round_trip():
    text = "Jane Doe met John Smith about Kang Li"
    spans = [
        (text.index("Jane Doe"), text.index("Jane Doe") + len("Jane Doe")),
        (text.index("John Smith"), text.index("John Smith") + len("John Smith")),
        (text.index("Kang Li"), text.index("Kang Li") + len("Kang Li")),
    ]
    encrypted = encrypt_text_spans(text, spans, KEY)
    assert encrypted.count("[[ENC:") == 3
    for name in ("Jane Doe", "John Smith", "Kang Li"):
        assert name not in encrypted
    assert " met " in encrypted and " about " in encrypted
    assert decrypt_text_spans(encrypted, KEY) == text


def test_spans_at_the_very_start_and_very_end_round_trip():
    text = "Jane in the middle Doe"
    spans = [(0, 4), (len(text) - 3, len(text))]
    encrypted = encrypt_text_spans(text, spans, KEY)
    assert encrypted.startswith("[[ENC:")
    assert encrypted.endswith("]]")
    assert " in the middle " in encrypted
    assert decrypt_text_spans(encrypted, KEY) == text


def test_span_covering_the_whole_string_round_trips():
    text = "Jane Doe"
    encrypted = encrypt_text_spans(text, [(0, len(text))], KEY)
    assert encrypted.startswith("[[ENC:") and encrypted.endswith("]]")
    assert decrypt_text_spans(encrypted, KEY) == text


def test_adjacent_touching_spans_round_trip():
    text = "JaneDoe"
    encrypted = encrypt_text_spans(text, [(0, 4), (4, 7)], KEY)
    assert encrypted.count("[[ENC:") == 2
    assert "]][[ENC:" in encrypted  # markers sit flush against each other
    assert decrypt_text_spans(encrypted, KEY) == text


def test_decrypt_text_spans_handles_many_markers_in_one_string():
    text = " and ".join(f"name{i}" for i in range(6))
    spans = []
    for i in range(6):
        start = text.index(f"name{i}")
        spans.append((start, start + len(f"name{i}")))
    encrypted = encrypt_text_spans(text, spans, KEY)
    assert encrypted.count("[[ENC:") == 6
    assert decrypt_text_spans(encrypted, KEY) == text


def test_marker_like_text_that_is_not_a_valid_token_raises_on_decrypt():
    # ROUGH EDGE (documented, not fixed): decrypt_text_spans trusts anything
    # shaped like [[ENC:<base64ish>]]. Free text that happens to contain such
    # a string is treated as a real token and blows up the whole decrypt run
    # with "wrong key or corrupted file", which is a misleading message.
    text = "see ticket [[ENC:notarealtoken]] for details"
    with pytest.raises(WrongKeyError):
        decrypt_text_spans(text, KEY)


def test_marker_like_text_outside_the_token_charset_is_left_alone():
    # The marker regex only accepts [A-Za-z0-9_-=], so these pass through.
    for text in ["see [[ENC:]] here", "see [[ENC: spaced ]] here", "[[ENC:a.b]]"]:
        assert decrypt_text_spans(text, KEY) == text


def test_encrypting_a_span_inside_marker_like_text_still_round_trips():
    text = "note [[ENC:notarealtoken]] about Jane Doe"
    start = text.index("Jane Doe")
    encrypted = encrypt_text_spans(text, [(start, start + len("Jane Doe"))], KEY)
    assert "Jane Doe" not in encrypted
    # The pre-existing literal marker is still there, and it is what makes
    # the decrypt of this cell fail (same rough edge as above).
    assert "[[ENC:notarealtoken]]" in encrypted
    with pytest.raises(WrongKeyError):
        decrypt_text_spans(encrypted, KEY)


def test_text_spans_with_unicode_offsets_round_trip():
    text = "患者 José Muñoz を担当"
    start = text.index("José Muñoz")
    encrypted = encrypt_text_spans(text, [(start, start + len("José Muñoz"))], KEY)
    assert "José" not in encrypted
    assert encrypted.startswith("患者 ")
    assert decrypt_text_spans(encrypted, KEY) == text


# --------------------------------------------------------------------------
# sensitive_fields: normalization and matching
# --------------------------------------------------------------------------


def test_header_matching_is_case_insensitive():
    for header in ["patient name", "Patient Name", "PATIENT NAME", "pAtIeNt NaMe"]:
        assert is_sensitive_header(header)
        assert is_whole_cell_header(header)


def test_punctuation_and_underscores_are_treated_as_separators():
    for header in ["patient_name", "Patient-Name", "patient.name", "patient/name", "(Patient Name)"]:
        assert is_sensitive_header(header), header
        assert is_whole_cell_header(header), header


def test_extra_whitespace_is_collapsed_and_stripped():
    for header in ["  Email  ", "first   name", "\tPhone Number\n", " ZIP "]:
        assert is_sensitive_header(header), header


def test_keyword_matching_is_whole_word_not_substring():
    # Headers that merely *contain* a keyword's letters must not match.
    for header in ["Nickname", "Renamed", "Namespace", "Filename", "Statement",
                   "Zipper", "Estate", "Citywide", "Streetlight"]:
        assert not is_sensitive_header(header), header
        assert not is_whole_cell_header(header), header


def test_obviously_non_sensitive_headers_are_not_flagged():
    for header in ["ID", "Notes", "Amount", "Visit Count", "Status", "Quantity", ""]:
        assert not is_sensitive_header(header), header


def test_every_whole_cell_keyword_is_also_sensitive():
    assert set(WHOLE_CELL_KEYWORDS) <= set(SENSITIVE_KEYWORDS)
    for keyword in WHOLE_CELL_KEYWORDS:
        assert is_whole_cell_header(keyword), keyword
        assert is_sensitive_header(keyword), keyword


def test_scanning_path_headers_are_sensitive_but_not_whole_cell():
    # These take the find_pii_spans path instead of whole-cell encryption.
    for header in ["Email", "EMail", "SSN", "DOB", "Date of Birth", "Social Security"]:
        assert is_sensitive_header(header), header
        assert not is_whole_cell_header(header), header


def test_hyphenated_email_header_is_not_detected():
    # BUG (documented, not fixed): _normalize() rewrites every non-alphanumeric
    # character to a space, so a header "E-Mail" normalizes to "e mail" and can
    # never match the "e-mail" keyword -- which still has its hyphen and is
    # therefore dead. A column literally headed "E-Mail"/"E_Mail" is missed.
    assert not is_sensitive_header("E-Mail")
    assert not is_sensitive_header("E_Mail")
    assert not is_sensitive_header("E Mail")
    # The keyword doesn't even match itself, which is the tell.
    assert not is_sensitive_header("e-mail")
    assert [kw for kw in SENSITIVE_KEYWORDS if not is_sensitive_header(kw)] == ["e-mail"]
    # It only gets picked up when some *other* keyword happens to be present.
    assert is_sensitive_header("E-Mail Address")


def test_surname_style_name_headers_are_not_detected():
    # Documented gap: the keyword list has no "surname"/"lastname" entry, and
    # whole-word matching means these single-token headers never match "name".
    assert not is_sensitive_header("Surname")
    assert not is_sensitive_header("Lastname")
    assert not is_sensitive_header("Firstname")
    # The spaced spellings do match.
    assert is_sensitive_header("Last Name")
    assert is_sensitive_header("First Name")


def test_detect_sensitive_columns_on_empty_header_list():
    assert detect_sensitive_columns([]) == []


def test_detect_sensitive_columns_reports_every_duplicate_header():
    headers = ["Email", "ID", "Email", "Email"]
    assert detect_sensitive_columns(headers) == [0, 2, 3]


def test_detect_sensitive_columns_tolerates_surrounding_whitespace():
    headers = ["  ID  ", " Full Name ", "\tEmail\t", " Notes "]
    assert detect_sensitive_columns(headers) == [1, 2]


# --------------------------------------------------------------------------
# csv_processor: detect_csv_encoding / read_headers
# --------------------------------------------------------------------------


def test_utf8_bom_is_detected_and_stripped_from_first_header(tmp_path):
    path = tmp_path / "bom.csv"
    path.write_bytes("ID,Full Name\n1,Jane Doe\n".encode("utf-8-sig"))
    assert detect_csv_encoding(str(path)) == "utf-8-sig"
    headers = read_headers(str(path))
    assert headers == ["ID", "Full Name"]
    assert not headers[0].startswith("﻿")


def test_cp1252_only_bytes_are_detected_and_decoded(tmp_path):
    path = tmp_path / "cp1252.csv"
    # 0xb7 middot, 0x92 smart quote, 0xe9 e-acute: 0xb7/0x92 are invalid utf-8.
    path.write_bytes(b"ID,Caf\xe9 \xb7 don\x92t\n1,x\n")
    assert detect_csv_encoding(str(path)) == "cp1252"
    assert read_headers(str(path)) == ["ID", "Café · don’t"]


def test_bytes_invalid_in_utf8_and_cp1252_fall_back_to_latin1(tmp_path):
    path = tmp_path / "latin1.csv"
    # 0x81 is one of cp1252's five undefined bytes and is not valid utf-8.
    path.write_bytes(b"ID,No\x81tes\n1,x\n")
    assert detect_csv_encoding(str(path)) == "latin-1"
    assert read_headers(str(path)) == ["ID", "No\x81tes"]


def test_plain_ascii_file_detects_as_utf8_sig(tmp_path):
    path = tmp_path / "ascii.csv"
    path.write_bytes(b"ID,Full Name\n1,Jane Doe\n")
    assert detect_csv_encoding(str(path)) == "utf-8-sig"


def test_empty_file_reads_no_headers_and_cannot_be_processed(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_bytes(b"")
    assert detect_csv_encoding(str(path)) == "utf-8-sig"
    assert read_headers(str(path)) == []
    with pytest.raises(ValueError) as excinfo:
        process_csv(str(path), str(tmp_path / "out.csv"), KEY, "encrypt", [0])
    assert str(excinfo.value) == "Input CSV is empty."


def test_read_headers_on_single_column_file(tmp_path):
    path = tmp_path / "one.csv"
    path.write_text("Full Name\nJane Doe\n", encoding="utf-8")
    assert read_headers(str(path)) == ["Full Name"]


def test_read_headers_keeps_commas_inside_quoted_headers(tmp_path):
    path = tmp_path / "quoted.csv"
    path.write_text('"Last, First","Notes ""x""",Amount\na,b,c\n', encoding="utf-8")
    assert read_headers(str(path)) == ["Last, First", 'Notes "x"', "Amount"]


# --------------------------------------------------------------------------
# csv_processor: process_csv structural behavior
#
# These deliberately select only whole-cell columns (Full Name / Address /
# Phone) so no test here has to pay the ~15s spaCy model load.
# --------------------------------------------------------------------------


def test_short_row_is_copied_through_when_selected_index_is_missing(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [
        ["ID", "Full Name", "Address"],
        ["1", "Jane Doe", "12 Elm St"],
        ["2"],                       # far short of the header
        ["3", "John Smith"],         # short of the Address column
    ])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1, 2])

    rows = _read_csv(output_path)
    assert rows[2] == ["2"]
    assert len(rows[3]) == 2
    assert rows[3][0] == "3"
    assert rows[3][1] != "John Smith"


def test_row_with_extra_fields_keeps_them(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [
        ["ID", "Full Name"],
        ["1", "Jane Doe", "extra1", "extra2"],
    ])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1])

    rows = _read_csv(output_path)
    assert len(rows[1]) == 4
    assert rows[1][2:] == ["extra1", "extra2"]
    assert decrypt_value(rows[1][1], KEY) == "Jane Doe"


def test_unselected_columns_are_byte_identical(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    unselected = ["1", "vip / follow-up", "  padded  ", "0012", "-", ""]
    _write_csv(input_path, [
        ["ID", "Notes", "Padded", "Code", "Dash", "Blank", "Full Name"],
        unselected + ["Jane Doe"],
    ])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [6])

    rows = _read_csv(output_path)
    assert rows[1][:6] == unselected
    assert rows[1][6] != "Jane Doe"


def test_out_of_range_selected_index_is_ignored(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [
        ["ID", "Full Name"],
        ["1", "Jane Doe"],
    ])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1, 7, 99])

    rows = _read_csv(output_path)
    assert rows[0] == ["ID", "Full Name"]
    assert len(rows[1]) == 2
    assert decrypt_value(rows[1][1], KEY) == "Jane Doe"


def test_invalid_mode_raises_value_error(tmp_path):
    input_path = tmp_path / "in.csv"
    _write_csv(input_path, [["ID", "Full Name"], ["1", "Jane Doe"]])

    for mode in ["ENCRYPT", "scramble", "", None]:
        with pytest.raises(ValueError):
            process_csv(str(input_path), str(tmp_path / "out.csv"), KEY, mode, [1])


def test_invalid_mode_is_rejected_before_the_output_file_is_written(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [["ID", "Full Name"], ["1", "Jane Doe"]])

    with pytest.raises(ValueError):
        process_csv(str(input_path), str(output_path), KEY, "nope", [1])
    assert not output_path.exists()


def test_embedded_commas_quotes_and_newlines_survive_a_round_trip(tmp_path):
    input_path = tmp_path / "in.csv"
    encrypted_path = tmp_path / "enc.csv"
    decrypted_path = tmp_path / "dec.csv"

    tricky_notes = 'line one,\nline "two", still one field'
    tricky_address = '12 "Elm" St, Apt 3\nSpringfield, ST'
    rows = [
        ["Notes", "Address"],
        [tricky_notes, tricky_address],
    ]
    _write_csv(input_path, rows)

    process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", [1])
    enc_rows = _read_csv(encrypted_path)
    assert enc_rows[1][0] == tricky_notes  # unselected, quoting preserved
    assert enc_rows[1][1] != tricky_address

    process_csv(str(encrypted_path), str(decrypted_path), KEY, "decrypt", [1])
    assert _read_csv(decrypted_path) == rows


def test_output_is_written_as_utf8_whatever_the_input_encoding(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    # cp1252 source: 0xb7 middot and 0xe9 e-acute in an *unselected* column.
    input_path.write_bytes(b"Notes,Full Name\ncaf\xe9 \xb7 visit,Jane Doe\n")
    assert detect_csv_encoding(str(input_path)) == "cp1252"

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1])

    # Reads cleanly as utf-8 (a cp1252 re-encode would raise here).
    rows = _read_csv(output_path, encoding="utf-8")
    assert rows[0] == ["Notes", "Full Name"]
    assert rows[1][0] == "café · visit"
    assert decrypt_value(rows[1][1], KEY) == "Jane Doe"
    assert detect_csv_encoding(str(output_path)) == "utf-8-sig"


def test_unicode_cells_survive_a_whole_cell_round_trip_through_csv(tmp_path):
    input_path = tmp_path / "in.csv"
    encrypted_path = tmp_path / "enc.csv"
    decrypted_path = tmp_path / "dec.csv"
    rows = [
        ["ID", "Full Name", "Address"],
        ["1", "José Muñoz", "北京市朝阳区 12号"],
        ["2", "🙂 Emoji Name", "12 Elm St"],
    ]
    _write_csv(input_path, rows)

    process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", [1, 2])
    process_csv(str(encrypted_path), str(decrypted_path), KEY, "decrypt", [1, 2])
    assert _read_csv(decrypted_path) == rows


def test_empty_cells_in_selected_columns_stay_empty(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [
        ["ID", "Full Name", "Address"],
        ["1", "", ""],
    ])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1, 2])

    assert _read_csv(output_path)[1] == ["1", "", ""]


def test_header_only_file_produces_a_header_only_output(tmp_path):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, [["ID", "Full Name"]])

    process_csv(str(input_path), str(output_path), KEY, "encrypt", [1])

    assert _read_csv(output_path) == [["ID", "Full Name"]]
