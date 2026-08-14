"""CSV reading/writing and encrypt/decrypt orchestration for NPIMasker."""

import atexit
import codecs
import contextlib
import csv
import io
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass

from npimasker.crypto import (
    AlreadyEncryptedError,
    WrongKeyError,
    contains_marker,
    decrypt_text_spans,
    decrypt_value,
    encrypt_text_spans,
    encrypt_value,
    looks_like_damaged_token,
    looks_like_token,
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


class UnsupportedEncodingError(ValueError):
    """Raised when a file is not text in any encoding we can safely read."""


@dataclass(frozen=True)
class EncodingInfo:
    """Everything about a file's byte-level shape that output must match.

    read_codec and write_codec differ because Python's BOM handling is
    asymmetric: "utf-8-sig" strips a BOM on read but *adds* one on write,
    and "utf-16" detects endianness on read but always writes little-endian.
    So reading uses the BOM-aware codec and writing uses an explicit,
    BOM-free one, with the exact BOM bytes re-emitted by hand.

    Keeping `bom` as data rather than folding it into the codec is what
    stops a BOM-less UTF-8 file from silently acquiring a BOM on the way
    out - the two facts are genuinely independent.
    """

    read_codec: str
    write_codec: str
    bom: bytes = b""
    newline: str = "\r\n"
    final_newline: bool = True

    @classmethod
    def default(cls) -> "EncodingInfo":
        return cls(read_codec="utf-8", write_codec="utf-8")


# A BOM is authoritative, so it is checked before anything else. UTF-32LE
# must be tested before UTF-16LE: BOM_UTF32_LE is b"\xff\xfe\x00\x00", which
# starts with BOM_UTF16_LE, so the other order silently misreads UTF-32.
_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32", "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32", "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig", "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16", "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16", "utf-16-be"),
)

# A BOM-less UTF-16 file is ASCII interleaved with NULs, so nearly every NUL
# sits on one parity of byte offset. Require both a decisive parity split and
# enough NULs to be meaningful, or refuse - guessing here is what produced
# blank column names in the first place.
_NUL_PARITY_RATIO = 0.9
_NUL_DENSITY = 0.1


def _bomless_utf16_codec(head: bytes) -> str:
    even = sum(1 for i in range(0, len(head), 2) if head[i] == 0)
    odd = sum(1 for i in range(1, len(head), 2) if head[i] == 0)
    total = even + odd
    if total >= len(head) * _NUL_DENSITY:
        if odd >= total * _NUL_PARITY_RATIO:
            return "utf-16-le"
        if even >= total * _NUL_PARITY_RATIO:
            return "utf-16-be"
    raise UnsupportedEncodingError(
        "This file contains NUL bytes, so it is not plain text, but it has "
        "no byte-order mark and does not look like UTF-16 either. If it is a "
        "spreadsheet or a compressed file, export it as CSV first; if it is "
        "text, re-save it as UTF-8."
    )


def _line_terminator(head: bytes, info_codec: str, bom: bytes) -> str:
    """First line ending in the file, searched in decoded text.

    Decoded, not raw: in UTF-16 a newline is two bytes, so scanning for
    b"\\n" would match the low half of an unrelated character.
    """
    text = head[len(bom):].decode(info_codec, errors="ignore")
    found = [(text.find(nl), nl) for nl in ("\r\n", "\n", "\r")]
    found = [(at, nl) for at, nl in found if at >= 0]
    if not found:
        return "\r\n"
    # Earliest wins; on a tie prefer the longer match so "\r\n" beats "\r".
    return min(found, key=lambda item: (item[0], -len(item[1])))[1]


def _ends_with_newline(input_path: str, newline: str, write_codec: str) -> bool:
    suffix = newline.encode(write_codec)
    size = os.path.getsize(input_path)
    if size < len(suffix):
        return False
    with open(input_path, "rb") as f:
        f.seek(size - len(suffix))
        return f.read() == suffix


def detect_encoding_info(input_path: str) -> EncodingInfo:
    """Detect the codec, BOM, and line terminator of a CSV.

    Order matters and is the whole fix: a BOM is checked first, then NUL
    bytes are taken as proof this is not an 8-bit encoding, and only then
    do we fall through to the utf-8/cp1252/latin-1 ladder. Previously the
    ladder came first, and cp1252 - which accepts any byte - swallowed
    UTF-16 files whole, yielding headers full of embedded NULs.
    """
    with open(input_path, "rb") as f:
        head = f.read(_SNIFF_CHUNK_BYTES)

    for bom, read_codec, write_codec in _BOMS:
        if head.startswith(bom):
            return _complete(input_path, read_codec, write_codec, bom)

    if b"\x00" in head:
        codec = _bomless_utf16_codec(head)
        return _complete(input_path, codec, codec, b"")

    for codec in ("utf-8-sig", "cp1252"):
        if _decodes_as(input_path, codec):
            write_codec = "utf-8" if codec == "utf-8-sig" else codec
            return _complete(input_path, codec, write_codec, b"")
    return _complete(input_path, "latin-1", "latin-1", b"")


def _complete(input_path: str, read_codec: str, write_codec: str, bom: bytes) -> EncodingInfo:
    with open(input_path, "rb") as f:
        head = f.read(_SNIFF_CHUNK_BYTES)
    newline = _line_terminator(head, write_codec, bom)
    return EncodingInfo(
        read_codec=read_codec,
        write_codec=write_codec,
        bom=bom,
        newline=newline,
        final_newline=_ends_with_newline(input_path, newline, write_codec),
    )


def _decodes_as(input_path: str, encoding: str) -> bool:
    """The pre-existing 8-bit ladder test, unchanged.

    Under 3 bytes the file could be nothing but a truncated BOM, where an
    incremental utf-8-sig decoder accepts what a one-shot decode rejects.
    Tiny by definition, so just decode it outright.
    """
    if os.path.getsize(input_path) < 3:
        with open(input_path, "rb") as f:
            raw = f.read()
        try:
            raw.decode(encoding)
        except UnicodeDecodeError:
            return False
        return True
    return _decodes_cleanly(input_path, encoding)


def detect_csv_encoding(input_path: str) -> str:
    """Best-effort detection of a CSV's text encoding.

    Many CSVs handed to this tool are Excel-on-Windows exports saved as
    Windows-1252 rather than UTF-8, which trips UnicodeDecodeError on bytes
    like 0xb7. Fall back through cp1252 to latin-1, which never fails since
    it maps every byte 0-255 to a codepoint.

    Kept as a thin wrapper over detect_encoding_info so its long-standing
    return values ("utf-8-sig" / "cp1252" / "latin-1") stay exactly as they
    were. Callers that need to *write* a file want detect_encoding_info
    instead: this name cannot distinguish "UTF-8 with a BOM" from "UTF-8
    without one", and writing with utf-8-sig would add a BOM that was
    never in the input.
    """
    encoding = detect_encoding_info(input_path).read_codec
    logger.info("Detected input encoding: %s", encoding)
    return encoding


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
def _atomic_output(output_path: str, info: EncodingInfo | None = None):
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

    The output is written in the input's codec, with the input's BOM, so a
    cp1252 or UTF-16 file comes back in the encoding it arrived in. The BOM
    goes out as raw bytes before the text wrapper is attached, because the
    BOM-writing codecs cannot express "UTF-16 big-endian" or "UTF-8 without
    a BOM" - see EncodingInfo.
    """
    info = info or EncodingInfo.default()
    out_dir = os.path.dirname(os.path.abspath(output_path))
    fd, temp_path = tempfile.mkstemp(dir=out_dir, prefix=".npimasker-", suffix=".tmp")
    created = temp_path
    with _inflight_lock:
        _inflight_temps.add(created)
    handle = None
    try:
        raw = os.fdopen(fd, "wb")
        if info.bom:
            raw.write(info.bom)
        # errors="strict": a character the output codec cannot hold must
        # fail the run, never be silently replaced with "?".
        handle = io.TextIOWrapper(
            raw, encoding=info.write_codec, newline="", errors="strict"
        )
        yield handle
        handle.close()  # flushes the encoder; may raise UnicodeEncodeError
        handle = None
        os.replace(temp_path, output_path)
        temp_path = None  # ownership handed to output_path
    finally:
        if handle is not None:
            # Already unwinding from an error; a second one here would mask it.
            with contextlib.suppress(Exception):
                handle.close()
        with _inflight_lock:
            _inflight_temps.discard(created)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def read_headers(input_path: str) -> list[str]:
    """Read just the header row of a CSV, for building a column checklist."""
    with open(input_path, newline="", encoding=detect_encoding_info(input_path).read_codec) as f:
        reader = csv.reader(f)
        return next(reader, [])


def _decrypt_cell(value: str, key: bytes) -> str:
    """Decrypt a cell, inferring how it was encrypted from its content.

    Encryption is header-driven, but decryption must not be: nothing stops
    a column being renamed, or selected differently, between the two runs.
    When it is, a header-driven decrypt takes the wrong path - and the
    whole-cell-encrypted-then-scanned direction finds no markers and
    returns the cell untouched, i.e. hands back ciphertext with no error
    at all.

    The data already says which it is, unambiguously: a Fernet token is
    urlsafe-base64 and so cannot contain "[", meaning the two encrypted
    shapes are disjoint. Markers are checked first, since a marker wraps a
    token and only the outer shape is the right one to act on.
    """
    if contains_marker(value):
        return decrypt_text_spans(value, key)
    if looks_like_token(value):
        return decrypt_value(value, key)
    if looks_like_damaged_token(value):
        raise WrongKeyError(
            "A value starts like an encrypted value but is truncated or "
            "corrupted, so it cannot be decrypted."
        )
    return value  # never encrypted, or already decrypted


def _transform_cell(value: str, key: bytes, mode: str, whole_cell: bool) -> str:
    if mode == "decrypt":
        return _decrypt_cell(value, key)
    if whole_cell:
        return encrypt_value(value, key)
    return encrypt_text_spans(value, find_pii_spans(value), key)


def process_csv(
    input_path: str,
    output_path: str,
    key: bytes,
    mode: str,
    selected_columns: list[int],
    whole_cell_overrides: dict[int, bool] | None = None,
    progress_callback=None,
    progress_interval_rows: int = _PROGRESS_INTERVAL_ROWS,
    progress_interval_seconds: float = _PROGRESS_INTERVAL_SECONDS,
) -> None:
    """Encrypt or decrypt the selected columns of a CSV, row by row.

    When encrypting, columns whose header names a whole-cell category
    (name, phone, address, NPI/medical record/insurance) are encrypted as a
    whole cell. Other selected columns are scanned for PII spans (emails,
    SSNs, dates, and person names via NER) and only those spans are
    encrypted, leaving the rest of the cell's text untouched.

    `whole_cell_overrides` maps a column index to True (encrypt whole) or
    False (scan), overriding that header heuristic. Indices it does not
    mention - and the default of None - keep the heuristic, so callers that
    do not pass it behave exactly as before. Forcing a column whole is also
    the way to keep a large free-text column away from the NER model, which
    is where essentially all the runtime goes.

    When decrypting, both are ignored: each cell's treatment is inferred
    from its own content (see _decrypt_cell), so a file still decrypts
    correctly after a column has been renamed or selected differently.

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

    info = detect_encoding_info(input_path)
    logger.info(
        "Input encoding: %s, bom=%s, newline=%r",
        info.read_codec, bool(info.bom), info.newline,
    )
    with _atomic_output(output_path, info) as outfile, open(
        input_path, newline="", encoding=info.read_codec
    ) as infile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile, lineterminator=info.newline)

        headers = next(reader, None)
        if headers is None:
            raise ValueError("Input CSV is empty.")
        writer.writerow(headers)

        overrides = whole_cell_overrides or {}
        whole_cell = {
            idx: overrides.get(idx, is_whole_cell_header(headers[idx]))
            for idx in selected
            if idx < len(headers)
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
                for position, idx in cells:
                    if contains_marker(buffered[position][1][idx]):
                        raise AlreadyEncryptedError(
                            f"Row {buffered[position][0]}, column "
                            f"'{headers[idx]}' already contains NPIMasker "
                            f"encryption markers. This file looks like it has "
                            f"already been encrypted - decrypt it first, or "
                            f"choose a different input file."
                        )
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
