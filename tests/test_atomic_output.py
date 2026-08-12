"""Atomic output writes for process_csv -- plan item (d).

process_csv must stage its output in a temporary file in the SAME directory
as output_path and os.replace() it into place only after the whole run
succeeds. A run that dies partway (wrong key, or the GUI's daemon thread
being killed when the window closes) must leave output_path untouched
rather than a silently truncated file the user may mistake for a finished
encrypt.

Tests marked xfail(strict=True) are the spec for behavior that does not
exist yet; they should start XPASSing (and lose their markers) once atomic
writes land. The unmarked tests cover behavior that already holds and must
keep holding.
"""

import csv
import os

import pytest

from npimasker import csv_processor
from npimasker.crypto import WrongKeyError, derive_key
from npimasker.csv_processor import process_csv

# derive_key runs 480k PBKDF2 iterations (~0.3s), so derive once per module
# and share the keys across every test.
KEY = derive_key("atomic-output-key")
WRONG_KEY = derive_key("not-the-same-key")

# Whole-cell headers only. A header like "Email" or "Notes" takes the PII
# span path, which loads spaCy and costs ~15s on a cold start.
HEADERS = ["ID", "Full Name", "Phone Number"]
ROWS = [
    ["1", "Jane Doe", "555-1234"],
    ["2", "John Smith", "555-9876"],
    ["3", "Ada Lovelace", "555-0000"],
]
COLUMNS = [1, 2]

SENTINEL = b"previous,output,contents\nkeep,me,intact\n"


def _write_csv(path, headers, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _interrupt_after(monkeypatch, n_cells):
    """Make the row loop raise KeyboardInterrupt after n_cells encryptions.

    KeyboardInterrupt is a BaseException, so a bare `except Exception:`
    around the write would not clean up after it -- this stands in for the
    GUI's daemon thread being killed when the window closes mid-run.
    """
    real_encrypt_value = csv_processor.encrypt_value
    calls = []

    def interrupting_encrypt_value(value, key):
        calls.append(value)
        if len(calls) > n_cells:
            raise KeyboardInterrupt("window closed mid-run")
        return real_encrypt_value(value, key)

    monkeypatch.setattr(csv_processor, "encrypt_value", interrupting_encrypt_value)


def _make_encrypted_csv(tmp_path, name="encrypted.csv", rows=ROWS):
    """Build a real encrypted CSV (under KEY) to feed the decrypt tests."""
    plain_path = tmp_path / f"plain-for-{name}"
    encrypted_path = tmp_path / name
    _write_csv(plain_path, HEADERS, rows)
    process_csv(str(plain_path), str(encrypted_path), KEY, "encrypt", COLUMNS)
    return encrypted_path


# --- existing behavior that must keep passing ------------------------------


def test_encrypt_decrypt_round_trip_through_process_csv(tmp_path):
    input_path = tmp_path / "in.csv"
    encrypted_path = tmp_path / "encrypted.csv"
    decrypted_path = tmp_path / "decrypted.csv"
    _write_csv(input_path, HEADERS, ROWS)

    process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", COLUMNS)
    enc_rows = _read_csv(encrypted_path)
    assert enc_rows[0] == HEADERS
    assert enc_rows[1][1] != "Jane Doe"
    assert enc_rows[1][0] == "1"  # unselected column copied through

    process_csv(str(encrypted_path), str(decrypted_path), KEY, "decrypt", COLUMNS)
    dec_rows = _read_csv(decrypted_path)
    assert dec_rows[0] == HEADERS
    assert dec_rows[1:] == ROWS


def test_wrong_key_decrypt_still_raises(tmp_path):
    encrypted_path = _make_encrypted_csv(tmp_path)
    output_path = tmp_path / "out.csv"

    with pytest.raises(WrongKeyError):
        process_csv(str(encrypted_path), str(output_path), WRONG_KEY, "decrypt", COLUMNS)


def test_success_leaves_exactly_the_expected_files(tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    input_path = work_dir / "in.csv"
    output_path = work_dir / "out.csv"
    _write_csv(input_path, HEADERS, ROWS)

    before = sorted(os.listdir(work_dir))
    assert before == ["in.csv"]

    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    # No .part/.tmp staging file survives a successful run.
    assert sorted(os.listdir(work_dir)) == ["in.csv", "out.csv"]
    assert _read_csv(output_path)[0] == HEADERS
    assert len(_read_csv(output_path)) == len(ROWS) + 1


def test_awkward_output_paths_round_trip(tmp_path):
    input_path = tmp_path / "in.csv"
    _write_csv(input_path, HEADERS, ROWS)

    names = ["out with spaces.csv", "sortie unicode éü中.csv", "out.csv.part"]
    for name in names:
        encrypted_path = tmp_path / f"enc {name}"
        decrypted_path = tmp_path / f"dec {name}"

        process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", COLUMNS)
        assert _read_csv(encrypted_path)[1][1] != "Jane Doe"

        process_csv(str(encrypted_path), str(decrypted_path), KEY, "decrypt", COLUMNS)
        assert _read_csv(decrypted_path)[1:] == ROWS


# --- plan item (d): atomic output write ------------------------------------


def test_failure_leaves_no_output_file(tmp_path):
    encrypted_path = _make_encrypted_csv(tmp_path)
    output_path = tmp_path / "out.csv"

    with pytest.raises(WrongKeyError):
        process_csv(str(encrypted_path), str(output_path), WRONG_KEY, "decrypt", COLUMNS)

    assert not output_path.exists()


def test_failure_preserves_existing_output_file(tmp_path):
    encrypted_path = _make_encrypted_csv(tmp_path)
    output_path = tmp_path / "out.csv"
    output_path.write_bytes(SENTINEL)

    with pytest.raises(WrongKeyError):
        process_csv(str(encrypted_path), str(output_path), WRONG_KEY, "decrypt", COLUMNS)

    # A naive open(output_path, "w") truncates this to zero bytes on open.
    assert output_path.read_bytes() == SENTINEL


def test_failure_leaves_no_temp_artifacts(tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    encrypted_path = work_dir / "encrypted.csv"
    plain_path = work_dir / "plain.csv"
    _write_csv(plain_path, HEADERS, ROWS)
    process_csv(str(plain_path), str(encrypted_path), KEY, "encrypt", COLUMNS)
    output_path = work_dir / "out.csv"

    before = sorted(os.listdir(work_dir))
    assert before == ["encrypted.csv", "plain.csv"]

    with pytest.raises(WrongKeyError):
        process_csv(str(encrypted_path), str(output_path), WRONG_KEY, "decrypt", COLUMNS)

    assert sorted(os.listdir(work_dir)) == before


def test_late_failure_in_large_file_leaves_no_output(tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    rows = [[str(i), f"Person {i}", f"555-{i:04d}"] for i in range(1, 2001)]
    encrypted_path = _make_encrypted_csv(work_dir, name="encrypted.csv", rows=rows)

    # Corrupt one late cell so ~1900 rows decrypt cleanly before the error.
    enc_rows = _read_csv(encrypted_path)
    assert len(enc_rows) == 2001
    enc_rows[1900][1] = "definitely-not-a-fernet-token"
    _write_csv(encrypted_path, enc_rows[0], enc_rows[1:])

    output_path = work_dir / "out.csv"
    output_path.write_bytes(SENTINEL)
    before = sorted(os.listdir(work_dir))

    with pytest.raises(WrongKeyError) as excinfo:
        process_csv(str(encrypted_path), str(output_path), KEY, "decrypt", COLUMNS)
    assert "row 1901" in str(excinfo.value)

    assert output_path.read_bytes() == SENTINEL
    assert sorted(os.listdir(work_dir)) == before


def test_keyboard_interrupt_mid_run_leaves_no_output(tmp_path, monkeypatch):
    # Models the GUI window being closed mid-run: the daemon thread dies via
    # a BaseException, which a bare `except Exception:` would not catch, so
    # temp cleanup has to happen in a finally block.
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, HEADERS, ROWS)
    _interrupt_after(monkeypatch, 3)

    with pytest.raises(KeyboardInterrupt):
        process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert not output_path.exists()
    assert sorted(os.listdir(tmp_path)) == ["in.csv"]


def test_keyboard_interrupt_mid_run_preserves_existing_output(tmp_path, monkeypatch):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, HEADERS, ROWS)
    output_path.write_bytes(SENTINEL)
    _interrupt_after(monkeypatch, 3)

    with pytest.raises(KeyboardInterrupt):
        process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert output_path.read_bytes() == SENTINEL
    assert sorted(os.listdir(tmp_path)) == ["in.csv", "out.csv"]


def test_temp_file_lives_in_the_output_directory(tmp_path, monkeypatch):
    # The temp file must share a filesystem with output_path, or os.replace
    # fails cross-device. Same directory is the guarantee we can check.
    input_path = tmp_path / "in.csv"
    output_dir = tmp_path / "output dir"
    output_dir.mkdir()
    output_path = output_dir / "out.csv"
    _write_csv(input_path, HEADERS, ROWS)

    real_replace = os.replace
    replacements = []

    def spy_replace(src, dst, *args, **kwargs):
        replacements.append((str(src), str(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", spy_replace)

    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert replacements, "process_csv never os.replace()d a temp file into place"
    src, dst = replacements[-1]
    assert os.path.dirname(os.path.abspath(src)) == str(output_dir)
    assert os.path.abspath(dst) == str(output_path)
    assert _read_csv(output_path)[1][1] != "Jane Doe"


def test_inflight_temp_is_tracked_during_the_run_and_released_after(tmp_path):
    """The GUI's worker is a daemon thread, so quitting mid-run kills it
    without unwinding _atomic_output's finally. An atexit hook cleans up
    whatever was still in flight, which only works if the set is accurate."""
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, HEADERS, ROWS)

    seen = []
    original = csv_processor.encrypt_value

    def _spy(value, key):
        seen.append(set(csv_processor._inflight_temps))
        return original(value, key)

    csv_processor.encrypt_value = _spy
    try:
        process_csv(str(input_path), str(output_path), KEY, "encrypt", [1])
    finally:
        csv_processor.encrypt_value = original

    # Exactly one temp file was registered while the run was in progress...
    assert seen and all(len(s) == 1 for s in seen)
    # ...and it lived in the output directory, not the system temp dir.
    (temp_path,) = seen[0]
    assert os.path.dirname(temp_path) == str(tmp_path)
    # ...and nothing is left registered once the run completes.
    assert csv_processor._inflight_temps == set()


def test_atexit_hook_removes_an_abandoned_temp_file(tmp_path):
    abandoned = tmp_path / ".npimasker-abandoned.tmp"
    abandoned.write_text("half a csv", encoding="utf-8")
    csv_processor._inflight_temps.add(str(abandoned))
    try:
        csv_processor._remove_inflight_temps()
        assert not abandoned.exists()
    finally:
        csv_processor._inflight_temps.discard(str(abandoned))


def test_atexit_hook_tolerates_an_already_deleted_temp_file(tmp_path):
    csv_processor._inflight_temps.add(str(tmp_path / "gone.tmp"))
    try:
        csv_processor._remove_inflight_temps()  # must not raise
    finally:
        csv_processor._inflight_temps.discard(str(tmp_path / "gone.tmp"))
