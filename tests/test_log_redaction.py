r"""Log redaction contract for process_csv (plan item (b)).

The branch that added `npimasker/logging_setup.py` also added a README
instruction telling partners to email us `npimasker.log` when something
breaks. That makes the log an outbound channel, so it must not carry PII.
In healthcare, the *directory* and *file name* of a CSV routinely embed
identifiers (`\\share\patients\Smith_John_DOB1970.csv`), and cell values
obviously do.

Contract these tests pin down:
  - process_csv logs the BASENAME of the input and output only; the parent
    directory never appears in any record.
  - Selected columns are logged as header NAMES, not bare indices.
  - No record from any `npimasker.*` logger contains the absolute input or
    output path.
  - Cell values are never logged, including on the error path.

Tests marked xfail(strict=True) describe behavior that is not implemented
yet; they will XPASS (and fail loudly) once it is, prompting removal of
the marker.
"""

import csv
import logging

import pytest

from npimasker.crypto import WrongKeyError, derive_key
from npimasker.csv_processor import process_csv

# derive_key() is ~0.3s of PBKDF2; derive once for the whole module.
KEY = derive_key("log-redaction-test-key")
WRONG_KEY = derive_key("log-redaction-wrong-key")

# All selected columns are whole-cell categories (name/phone/address), so
# no run in this file loads the spaCy NER model.
HEADERS = ["ID", "Full Name", "Phone Number", "Address"]
COLUMNS = [1, 2, 3]

# Mirrors logging_setup.setup_logging()'s formatter, so what we assert on is
# what actually lands in the file partners email us.
_FORMATTER = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")


def _write_csv(path, value="Jane Doe", rows=4):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for i in range(1, rows + 1):
            writer.writerow([str(i), value, value, value])


def _log_blob(caplog):
    """Every record emitted by an `npimasker.*` logger, as one string.

    Includes both the lazily-interpolated message and the fully formatted
    record (which appends any exception traceback), so assertions cover
    what a reader of npimasker.log would actually see. Calling
    getMessage()/format() here also means a record whose args can't be
    interpolated raises out of the test instead of being swallowed by
    logging's internal error handling.
    """
    parts = []
    for record in caplog.records:
        if not record.name.startswith("npimasker"):
            continue
        parts.append(record.getMessage())
        parts.append(_FORMATTER.format(record))
    return "\n".join(parts)


def test_input_directory_never_appears_in_log(tmp_path, caplog):
    secret_dir = tmp_path / "PATIENT_Jane_Doe_DOB1970"
    secret_dir.mkdir()
    input_path = secret_dir / "records.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    blob = _log_blob(caplog)
    # Assert on the directory portion specifically: the basename is
    # legitimately logged, so asserting on the whole path would pass for
    # the wrong reason.
    assert "PATIENT_Jane_Doe_DOB1970" not in blob
    assert str(input_path.parent) not in blob
    assert str(input_path) not in blob


def test_input_basename_is_logged(tmp_path, caplog):
    """Redaction must not gut the log: the file is still identifiable."""
    input_path = tmp_path / "DISTINCTIVE_INPUT_NAME.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert "DISTINCTIVE_INPUT_NAME.csv" in _log_blob(caplog)


def test_output_directory_never_appears_in_log(tmp_path, caplog):
    input_dir = tmp_path / "plain_in"
    input_dir.mkdir()
    output_dir = tmp_path / "OUTBOX_Jane_Doe_DOB1970"
    output_dir.mkdir()
    input_path = input_dir / "records.csv"
    output_path = output_dir / "out.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    blob = _log_blob(caplog)
    assert "OUTBOX_Jane_Doe_DOB1970" not in blob
    assert str(output_path.parent) not in blob
    assert str(output_path) not in blob


def test_output_basename_is_logged(tmp_path, caplog):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "DISTINCTIVE_OUTPUT_NAME.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert "DISTINCTIVE_OUTPUT_NAME.csv" in _log_blob(caplog)


def test_selected_columns_logged_as_header_names_not_indices(tmp_path, caplog):
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    blob = _log_blob(caplog)
    # Header names are not PII and are far more useful for triage than
    # "columns=[1, 2, 3]", which means nothing without the file.
    assert "Full Name" in blob
    assert "Phone Number" in blob
    assert "Address" in blob
    assert "[1, 2, 3]" not in blob


def test_cell_values_never_logged_on_encrypt(tmp_path, caplog):
    sentinel = "ZZSENTINELVALUEZZ"
    input_path = tmp_path / "in.csv"
    output_path = tmp_path / "out.csv"
    _write_csv(input_path, value=sentinel)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    assert sentinel not in _log_blob(caplog)


def test_cell_values_never_logged_on_decrypt(tmp_path, caplog):
    sentinel = "ZZSENTINELVALUEZZ"
    input_path = tmp_path / "in.csv"
    encrypted_path = tmp_path / "encrypted.csv"
    decrypted_path = tmp_path / "decrypted.csv"
    _write_csv(input_path, value=sentinel)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", COLUMNS)
    caplog.clear()
    process_csv(str(encrypted_path), str(decrypted_path), KEY, "decrypt", COLUMNS)

    # Decrypt holds plaintext in memory again; it must not reach the log.
    assert sentinel not in _log_blob(caplog)
    with open(decrypted_path, newline="", encoding="utf-8") as f:
        assert sentinel in list(csv.reader(f))[1][1]


def test_error_path_logs_column_name_but_not_path_or_values(tmp_path, caplog):
    sentinel = "ZZSENTINELVALUEZZ"
    secret_dir = tmp_path / "PATIENT_Jane_Doe_DOB1970"
    secret_dir.mkdir()
    input_path = secret_dir / "records.csv"
    encrypted_path = secret_dir / "encrypted.csv"
    decrypted_path = secret_dir / "decrypted.csv"
    _write_csv(input_path, value=sentinel)

    process_csv(str(input_path), str(encrypted_path), KEY, "encrypt", COLUMNS)

    caplog.set_level(logging.INFO)
    # Mirror gui.py's _process_worker, which logs the failure with a full
    # traceback via logger.exception.
    with pytest.raises(WrongKeyError):
        try:
            process_csv(
                str(encrypted_path), str(decrypted_path), WRONG_KEY, "decrypt", COLUMNS
            )
        except Exception:
            logging.getLogger("npimasker.gui").exception("process_csv failed")
            raise

    blob = _log_blob(caplog)
    # The column name in WrongKeyError's message is useful triage context
    # and is not PII, so it should stay.
    assert "Full Name" in blob
    # The directory and the cell values must not ride along on the error path.
    assert "PATIENT_Jane_Doe_DOB1970" not in blob
    assert str(input_path.parent) not in blob
    assert sentinel not in blob


def test_percent_and_brace_in_path_do_not_break_lazy_formatting(tmp_path, caplog):
    """A file name containing %s / {} must not corrupt or crash formatting.

    Logging interpolates lazily with %-args; a redaction implemented by
    pre-formatting the message would blow up (or mangle output) on these.
    """
    odd_dir = tmp_path / "dir_%s_{}"
    odd_dir.mkdir()
    input_path = odd_dir / "report_%s_%d_{name}_100%.csv"
    output_path = odd_dir / "out_{}_%s.csv"
    _write_csv(input_path)

    caplog.set_level(logging.INFO)
    process_csv(str(input_path), str(output_path), KEY, "encrypt", COLUMNS)

    # _log_blob() calls getMessage()/format() on every record, so a broken
    # interpolation raises here rather than being swallowed by logging.
    blob = _log_blob(caplog)
    assert "report_%s_%d_{name}_100%.csv" in blob
