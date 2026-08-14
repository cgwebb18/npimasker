"""Progress reporting contract for `process_csv` (plan item (c)).

`process_csv` must give a caller (the GUI, polling from a background
thread) liveness during long runs. The contract these tests pin down:

    process_csv(input_path, output_path, key, mode, selected_columns,
                progress_callback=None,
                progress_interval_rows=500,
                progress_interval_seconds=2.0)

* `progress_callback(rows_done)` receives a count of DATA rows processed
  so far (header excluded) -- the same unit as the `rows=N` completion
  log line, not the CSV line number.
* It fires when EITHER `progress_interval_rows` rows OR
  `progress_interval_seconds` seconds have elapsed since the last
  emission, so a 100-row file whose cells take minutes still reports.
* `progress_interval_seconds=0` fires every row: a deterministic test
  hook that needs no sleeps.

Tests marked xfail describe behavior that is not implemented yet.

Speed notes: the key is derived once at module scope (PBKDF2 is ~0.3s),
and the CSVs use whole-cell column headers ("Full Name") so the spaCy
NER path -- and its ~15s model load -- stays out of all but the one test
that is specifically about the spaCy load heartbeat.
"""

import csv
import logging

import pytest

from npimasker.crypto import derive_key
from npimasker.csv_processor import process_csv

KEY = derive_key("progress-test-key")

# "Full Name" is a whole-cell header, so these rows never reach spaCy.
HEADERS = ["ID", "Full Name"]
NAME_COLUMN = [1]

PROCESSOR_LOGGER = "npimasker.csv_processor"
DETECT_LOGGER = "npimasker.pii_detect"


def _write_csv(path, data_rows, headers=HEADERS):
    """Write a CSV with `data_rows` data rows under `headers`."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i in range(data_rows):
            writer.writerow([str(i), f"Person {i}"])
    return str(path)


def _count_data_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return max(len(list(csv.reader(f))) - 1, 0)


def _messages(caplog, logger_name):
    return [r.getMessage() for r in caplog.records if r.name == logger_name]


def test_progress_callback_is_invoked_on_a_large_file(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 1000)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
    )

    assert calls, "a 1000-row file must report progress at least once"


def test_progress_reports_data_row_counts_at_the_default_interval(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 1000)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
    )

    # Data rows, header excluded: the 500th and the 1000th.
    assert calls == [500, 1000]


def test_progress_never_reports_more_rows_than_the_file_contains(tmp_path):
    # 499 data rows occupy lines 2..500, so the line-number-based
    # implementation reports 500 -- one more row than exists.
    input_path = _write_csv(tmp_path / "in.csv", 499)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
    )

    data_rows = _count_data_rows(input_path)
    assert data_rows == 499
    assert all(reported <= data_rows for reported in calls), calls


def test_zero_second_interval_reports_every_row_on_a_small_file(tmp_path):
    # The regression this whole contract exists for: a small file whose
    # rows are individually slow currently emits no progress at all.
    input_path = _write_csv(tmp_path / "in.csv", 100)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
        progress_interval_seconds=0,
    )

    assert calls == list(range(1, 101))


def test_row_interval_still_triggers_when_the_time_trigger_cannot_fire(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 250)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
        progress_interval_rows=100,
        progress_interval_seconds=10_000,
    )

    assert calls == [100, 200]


def test_time_trigger_fires_independently_of_the_row_trigger(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 50)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
        progress_interval_rows=10_000,  # never reached
        progress_interval_seconds=0,
    )

    assert calls == list(range(1, 51))


def test_absent_progress_callback_does_not_raise_and_output_is_unchanged(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 600)
    output_path = str(tmp_path / "out.csv")

    process_csv(input_path, output_path, KEY, "encrypt", NAME_COLUMN)

    with open(output_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == HEADERS
    assert len(rows) == 601
    assert rows[1][0] == "0"  # untouched column
    assert rows[1][1] != "Person 0"  # encrypted column


def test_reported_progress_values_strictly_increase(tmp_path):
    input_path = _write_csv(tmp_path / "in.csv", 1500)
    calls = []

    process_csv(
        input_path,
        str(tmp_path / "out.csv"),
        KEY,
        "encrypt",
        NAME_COLUMN,
        progress_callback=lambda u: calls.append(u.rows),
    )

    assert len(calls) >= 2
    assert all(later > earlier for earlier, later in zip(calls, calls[1:])), calls


def test_completion_log_reports_the_data_row_count(tmp_path, caplog):
    input_path = _write_csv(tmp_path / "in.csv", 250)

    with caplog.at_level(logging.INFO, logger=PROCESSOR_LOGGER):
        process_csv(input_path, str(tmp_path / "out.csv"), KEY, "encrypt", NAME_COLUMN)

    messages = _messages(caplog, PROCESSOR_LOGGER)
    assert any("rows=250" in m for m in messages), messages


def test_completion_log_reports_zero_rows_for_a_header_only_file(tmp_path, caplog):
    input_path = _write_csv(tmp_path / "in.csv", 0)

    with caplog.at_level(logging.INFO, logger=PROCESSOR_LOGGER):
        process_csv(input_path, str(tmp_path / "out.csv"), KEY, "encrypt", NAME_COLUMN)

    messages = _messages(caplog, PROCESSOR_LOGGER)
    assert any("rows=0" in m for m in messages), messages


def test_encoding_detection_and_run_start_are_logged(tmp_path, caplog):
    input_path = _write_csv(tmp_path / "in.csv", 5)

    with caplog.at_level(logging.INFO, logger=PROCESSOR_LOGGER):
        process_csv(input_path, str(tmp_path / "out.csv"), KEY, "encrypt", NAME_COLUMN)

    messages = [m.lower() for m in _messages(caplog, PROCESSOR_LOGGER)]
    # Presence only: another change owns how these lines are worded/redacted.
    assert any("encoding" in m for m in messages), messages
    assert any("start" in m for m in messages), messages


def test_spacy_model_load_logs_a_heartbeat_before_and_after(tmp_path, caplog, monkeypatch):
    # The only test that deliberately takes the NER path: a "Notes" column
    # is not a whole-cell header, so find_pii_spans -> spaCy runs. One row
    # keeps it to a single model load.
    from npimasker import pii_detect

    monkeypatch.setattr(pii_detect, "_nlp", None)

    input_path = tmp_path / "in.csv"
    with open(input_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Notes"])
        writer.writerow(["1", "spoke with Kang Li today"])

    with caplog.at_level(logging.INFO, logger=DETECT_LOGGER):
        process_csv(str(input_path), str(tmp_path / "out.csv"), KEY, "encrypt", [1])

    messages = [m.lower() for m in _messages(caplog, DETECT_LOGGER)]
    loading = [i for i, m in enumerate(messages) if "loading" in m and "spacy" in m]
    loaded = [i for i, m in enumerate(messages) if "loaded" in m and "spacy" in m]
    assert loading, messages
    assert loaded, messages
    assert loading[0] < loaded[0], messages


# -- the fraction and phase carried alongside the row count ----------------
#
# A determinate progress bar needs a total. Counting rows would mean a whole
# extra pass over the file before any work starts, so the fraction is driven
# by input bytes consumed, which the reader already knows.


def test_progress_reports_a_fraction_that_advances_to_completion(tmp_path):
    calls = []
    input_path = tmp_path / "in.csv"
    _write_csv(input_path, 3000)

    process_csv(
        str(input_path), str(tmp_path / "out.csv"), KEY, "encrypt", [1],
        progress_callback=calls.append,
    )

    fractions = [c.fraction for c in calls]
    assert fractions, "expected at least one report"
    assert all(0.0 <= f <= 1.0 for f in fractions), fractions
    assert fractions == sorted(fractions), fractions
    assert fractions[-1] > 0.5, fractions


def test_progress_phase_is_processing_when_verification_is_off(tmp_path):
    calls = []
    input_path = tmp_path / "in.csv"
    _write_csv(input_path, 1000)

    process_csv(
        str(input_path), str(tmp_path / "out.csv"), KEY, "encrypt", [1],
        verify=False, progress_callback=calls.append,
    )

    assert {c.phase for c in calls} == {"processing"}


def test_verification_reports_its_own_phase(tmp_path):
    """Otherwise the bar sits at 100% for the whole verification pass and
    the app looks hung - which is the failure this feature exists to fix."""
    calls = []
    input_path = tmp_path / "in.csv"
    _write_csv(input_path, 40_000)

    process_csv(
        str(input_path), str(tmp_path / "out.csv"), KEY, "encrypt", [1],
        verify=True, progress_callback=calls.append,
    )

    phases = [c.phase for c in calls]
    assert "verifying" in phases, phases
    # Verification runs after processing, never interleaved with it.
    assert phases == sorted(phases, key=lambda p: p == "verifying"), phases


def test_fraction_is_well_defined_for_an_empty_data_section(tmp_path):
    """A header-only file has no rows to report, and must not divide by
    zero or emit a fraction outside 0..1."""
    input_path = tmp_path / "in.csv"
    input_path.write_text("ID,Full Name\r\n", encoding="utf-8")
    calls = []

    process_csv(
        str(input_path), str(tmp_path / "out.csv"), KEY, "encrypt", [1],
        progress_callback=calls.append, progress_interval_seconds=0,
    )

    assert all(0.0 <= c.fraction <= 1.0 for c in calls)
