"""CSV reading/writing and encrypt/decrypt orchestration for NPIMasker."""

import csv

from npimasker.crypto import (
    WrongKeyError,
    decrypt_text_spans,
    decrypt_value,
    encrypt_text_spans,
    encrypt_value,
)
from npimasker.pii_detect import find_pii_spans
from npimasker.sensitive_fields import is_whole_cell_header


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
            return encoding
        except UnicodeDecodeError:
            continue
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
) -> None:
    """Encrypt or decrypt the selected columns of a CSV, row by row.

    Columns whose header names a whole-cell category (name, phone, address,
    NPI/medical record/insurance) are encrypted/decrypted as a whole cell.
    Other selected columns are scanned for PII spans (emails, SSNs, dates,
    and person names via NER) and only those spans are encrypted/decrypted,
    leaving the rest of the cell's text untouched.

    Columns not in `selected_columns` are copied through unchanged.
    Raises WrongKeyError (with row/column context) if a decrypt fails.
    """
    if mode not in ("encrypt", "decrypt"):
        raise ValueError(f"Unknown mode: {mode!r}")
    selected = set(selected_columns)

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
