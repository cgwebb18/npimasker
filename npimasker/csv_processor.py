"""CSV reading/writing and encrypt/decrypt orchestration for NPIMasker."""

import csv
import logging
import os
import time

from npimasker.crypto import (
    WrongKeyError,
    decrypt_text_spans,
    decrypt_value,
    encrypt_text_spans,
    encrypt_value,
)
from npimasker.pii_detect import find_pii_spans
from npimasker.sensitive_fields import is_whole_cell_header

logger = logging.getLogger(__name__)

_PROGRESS_INTERVAL_ROWS = 500
_PROGRESS_INTERVAL_SECONDS = 2.0


def detect_csv_encoding(input_path: str) -> str:
    """Best-effort detection of a CSV's text encoding.

    Many CSVs handed to this tool are Excel-on-Windows exports saved as
    Windows-1252 rather than UTF-8, which trips UnicodeDecodeError on bytes
    like 0xb7. Fall back through cp1252 to latin-1, which never fails since
    it maps every byte 0-255 to a codepoint.
    """
    with open(input_path, "rb") as f:
        raw = f.read()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            raw.decode(encoding)
            logger.info("Detected input encoding: %s", encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    logger.info("Detected input encoding: latin-1 (fallback)")
    return "latin-1"


def read_headers(input_path: str) -> list[str]:
    """Read just the header row of a CSV, for building a column checklist."""
    with open(input_path, newline="", encoding=detect_csv_encoding(input_path)) as f:
        reader = csv.reader(f)
        return next(reader, [])


def _transform_cell(value: str, key: bytes, mode: str, whole_cell: bool) -> str:
    if whole_cell:
        return encrypt_value(value, key) if mode == "encrypt" else decrypt_value(value, key)
    if mode == "encrypt":
        return encrypt_text_spans(value, find_pii_spans(value), key)
    return decrypt_text_spans(value, key)


def process_csv(
    input_path: str,
    output_path: str,
    key: bytes,
    mode: str,
    selected_columns: list[int],
    progress_callback=None,
    progress_interval_rows: int = _PROGRESS_INTERVAL_ROWS,
    progress_interval_seconds: float = _PROGRESS_INTERVAL_SECONDS,
) -> None:
    """Encrypt or decrypt the selected columns of a CSV, row by row.

    Columns whose header names a whole-cell category (name, phone, address,
    NPI/medical record/insurance) are encrypted/decrypted as a whole cell.
    Other selected columns are scanned for PII spans (emails, SSNs, dates,
    and person names via NER) and only those spans are encrypted/decrypted,
    leaving the rest of the cell's text untouched.

    Columns not in `selected_columns` are copied through unchanged.
    Raises WrongKeyError (with row/column context) if a decrypt fails.

    If given, `progress_callback(rows_done)` reports the number of data
    rows processed so far - the same unit as the `rows=N` completion log
    line - so a caller (e.g. a GUI polling from a background thread) can
    show liveness during long runs.

    Progress fires whenever EITHER `progress_interval_rows` rows or
    `progress_interval_seconds` have passed since the last report. The
    time trigger matters because the expensive work is per-cell, not
    per-row: a 100-row file of long free-text cells can take minutes
    inside NER, and a purely row-counted trigger would report nothing at
    all for the entire run.
    """
    if mode not in ("encrypt", "decrypt"):
        raise ValueError(f"Unknown mode: {mode!r}")
    selected = set(selected_columns)

    # Log basenames only: this log is written for partners to send back to
    # us, and in healthcare a full path routinely embeds patient
    # identifiers ("Smith_John_DOB1970.csv", \\share\patients\...). Cell
    # values are never logged.
    logger.info(
        "process_csv start: mode=%s, input=%s, output=%s",
        mode, os.path.basename(input_path), os.path.basename(output_path),
    )
    start = time.monotonic()
    row_num = 1
    last_reported_rows = 0
    last_reported_at = start

    with open(input_path, newline="", encoding=detect_csv_encoding(input_path)) as infile, open(
        output_path, "w", newline="", encoding="utf-8"
    ) as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        headers = next(reader, None)
        if headers is None:
            raise ValueError("Input CSV is empty.")
        writer.writerow(headers)

        whole_cell = {
            idx: is_whole_cell_header(headers[idx]) for idx in selected if idx < len(headers)
        }
        # Header names, not indices: they're not PII, and "which columns
        # did they actually pick" is the first thing we need when triaging.
        logger.info(
            "Selected columns: whole-cell=%s, scanned=%s",
            [headers[i] for i in sorted(whole_cell) if whole_cell[i]],
            [headers[i] for i in sorted(whole_cell) if not whole_cell[i]],
        )

        for row_num, row in enumerate(reader, start=2):
            new_row = list(row)
            for idx in selected:
                if idx >= len(new_row):
                    continue
                try:
                    new_row[idx] = _transform_cell(
                        new_row[idx], key, mode, whole_cell.get(idx, True)
                    )
                except WrongKeyError as exc:
                    column_name = headers[idx] if idx < len(headers) else str(idx)
                    raise WrongKeyError(
                        f"{exc} (row {row_num}, column '{column_name}')"
                    ) from exc
            writer.writerow(new_row)

            rows_done = row_num - 1
            now = time.monotonic()
            if (
                rows_done - last_reported_rows >= progress_interval_rows
                or now - last_reported_at >= progress_interval_seconds
            ):
                last_reported_rows, last_reported_at = rows_done, now
                logger.info(
                    "process_csv progress: rows=%d, elapsed=%.1fs", rows_done, now - start
                )
                if progress_callback is not None:
                    progress_callback(rows_done)

    logger.info(
        "process_csv done: rows=%d, elapsed=%.1fs", row_num - 1, time.monotonic() - start
    )
