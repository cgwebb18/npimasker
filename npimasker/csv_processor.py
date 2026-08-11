"""CSV reading/writing and encrypt/decrypt orchestration for NPIMasker."""

import atexit
import codecs
import contextlib
import csv
import logging
import os
import tempfile
import threading
import time

from npimasker.crypto import (
    WrongKeyError,
    decrypt_text_spans,
    decrypt_value,
    encrypt_text_spans,
    encrypt_value,
)
from npimasker.pii_detect import find_pii_spans, find_pii_spans_batch
from npimasker.sensitive_fields import is_whole_cell_header

logger = logging.getLogger(__name__)

_PROGRESS_INTERVAL_ROWS = 500
_PROGRESS_INTERVAL_SECONDS = 2.0

# Rows buffered before flushing, so scanned cells batch through the NER
# model together. Small enough that progress still ticks regularly:
# nothing is reported until a chunk finishes.
_BATCH_ROWS = 500

_SNIFF_CHUNK_BYTES = 1 << 20


def _decodes_cleanly(input_path: str, encoding: str) -> bool:
    """Whether the whole file decodes as `encoding`, read in chunks.

    An incremental decoder buffers a multi-byte sequence split across a
    chunk boundary, so this gives the same answer as decoding the entire
    file at once without ever holding it in memory. The closing
    decode(b"", final=True) is what makes a sequence truncated at EOF
    still raise, matching bytes.decode().
    """
    decoder = codecs.getincrementaldecoder(encoding)()
    try:
        with open(input_path, "rb") as f:
            while chunk := f.read(_SNIFF_CHUNK_BYTES):
                decoder.decode(chunk, False)
            decoder.decode(b"", True)
    except UnicodeDecodeError:
        return False
    return True


def detect_csv_encoding(input_path: str) -> str:
    """Best-effort detection of a CSV's text encoding.

    Many CSVs handed to this tool are Excel-on-Windows exports saved as
    Windows-1252 rather than UTF-8, which trips UnicodeDecodeError on bytes
    like 0xb7. Fall back through cp1252 to latin-1, which never fails since
    it maps every byte 0-255 to a codepoint.

    Reads in chunks rather than slurping the file: the whole-file version
    cost ~2-3x the file size in peak memory (the bytes, plus a str that is
    thrown away immediately), on top of everything else this tool holds.
    """
    for encoding in ("utf-8-sig", "cp1252"):
        # Under 3 bytes the file could be nothing but a truncated BOM,
        # where an incremental utf-8-sig decoder accepts what a one-shot
        # decode rejects. Tiny by definition, so just decode it outright.
        if os.path.getsize(input_path) < 3:
            with open(input_path, "rb") as f:
                raw = f.read()
            try:
                raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        elif not _decodes_cleanly(input_path, encoding):
            continue
        logger.info("Detected input encoding: %s", encoding)
        return encoding
    logger.info("Detected input encoding: latin-1 (fallback)")
    return "latin-1"


_inflight_temps: set[str] = set()
_inflight_lock = threading.Lock()


@atexit.register
def _remove_inflight_temps():
    """Delete temp files still in flight at interpreter exit.

    The GUI runs process_csv on a daemon thread, so quitting mid-run kills
    the worker outright and _atomic_output's finally never executes. Left
    alone, every abandoned run would drop a hidden part-written CSV in the
    user's output folder. This runs on the main thread during shutdown,
    after daemon threads have stopped.
    """
    with _inflight_lock:
        paths = list(_inflight_temps)
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass


@contextlib.contextmanager
def _atomic_output(output_path: str):
    """Yield a writable handle whose contents only appear at output_path
    if the caller finishes without raising.

    Writing straight to output_path leaves a truncated file behind when a
    run dies partway: the GUI runs this on a daemon thread, so closing the
    window mid-run silently produces a short file that looks like a
    finished encryption. Keeping the original intact matters even more -
    open(path, "w") empties an existing output the moment it's called, so
    a failed re-run would destroy the previous good result.

    The temp file is created in the destination directory so the rename is
    a same-filesystem, atomic operation. It inherits mkstemp's 0600 mode
    rather than the umask default; on POSIX that means the output is
    owner-only, which is the safer default for a file full of PII (and is
    moot on Windows, the deployment target).
    """
    out_dir = os.path.dirname(os.path.abspath(output_path))
    fd, temp_path = tempfile.mkstemp(dir=out_dir, prefix=".npimasker-", suffix=".tmp")
    created = temp_path
    with _inflight_lock:
        _inflight_temps.add(created)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            yield handle
        os.replace(temp_path, output_path)
        temp_path = None  # ownership handed to output_path
    finally:
        with _inflight_lock:
            _inflight_temps.discard(created)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


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

    with _atomic_output(output_path) as outfile, open(
        input_path, newline="", encoding=detect_csv_encoding(input_path)
    ) as infile:
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

        # Columns scanned for embedded PII rather than encrypted whole.
        # Only these reach the NER model, and only when encrypting.
        scanned = [idx for idx in sorted(selected) if not whole_cell.get(idx, True)]

        def _flush(buffered):
            """Transform and write a chunk of rows.

            Rows are buffered so every scanned cell in the chunk can go
            through the model in one batch - one nlp.pipe call instead of
            one nlp() call per cell.
            """
            nonlocal last_reported_rows, last_reported_at

            precomputed = {}
            if mode == "encrypt" and scanned:
                cells = [
                    (position, idx)
                    for position, (_, row) in enumerate(buffered)
                    for idx in scanned
                    if idx < len(row) and row[idx]
                ]
                if cells:
                    spans = find_pii_spans_batch(
                        [buffered[position][1][idx] for position, idx in cells]
                    )
                    precomputed = dict(zip(cells, spans))

            for position, (number, row) in enumerate(buffered):
                for idx in selected:
                    if idx >= len(row):
                        continue
                    try:
                        spans = precomputed.get((position, idx))
                        if spans is None:
                            row[idx] = _transform_cell(
                                row[idx], key, mode, whole_cell.get(idx, True)
                            )
                        else:
                            row[idx] = encrypt_text_spans(row[idx], spans, key)
                    except WrongKeyError as exc:
                        column_name = headers[idx] if idx < len(headers) else str(idx)
                        raise WrongKeyError(
                            f"{exc} (row {number}, column '{column_name}')"
                        ) from exc
                writer.writerow(row)

                rows_done = number - 1
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

        buffered = []
        for row_num, row in enumerate(reader, start=2):
            buffered.append((row_num, list(row)))
            if len(buffered) >= _BATCH_ROWS:
                _flush(buffered)
                buffered = []
        if buffered:
            _flush(buffered)

    logger.info(
        "process_csv done: rows=%d, elapsed=%.1fs", row_num - 1, time.monotonic() - start
    )
