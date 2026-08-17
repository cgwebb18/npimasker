"""Integration tests for the background-thread/queue rework in npimasker.gui.

These drive a real `App` (no mainloop - the event loop is pumped manually
with `app.update()`), so they cover the whole surface: validation, worker
thread, progress queue, poll loop, button state and error routing.

Every `messagebox.*` entry point is stubbed before anything is triggered:
a real modal dialog would block the test forever.
"""

import csv
import gc
import logging
import queue
import sys
import threading
import time
import types

import pytest

# Tk can be missing in two different ways and both have to skip, not error.
# A Python built without _tkinter fails at *import*, which a bare TclError
# guard does not catch - the module then errors during collection and takes
# the whole run down with it. That is the usual case on a Linux CI runner,
# where the interpreter often ships without Tk at all.
try:
    import tkinter as tk

    from npimasker import gui  # imports tkinter itself
except ImportError as exc:
    pytest.skip(f"tkinter is unavailable: {exc}", allow_module_level=True)

from npimasker.crypto import WrongKeyError, derive_key, looks_like_token
from npimasker.csv_processor import ProgressUpdate, process_csv

try:
    _probe = tk.Tk()
    # Withdraw before destroying: leaving a mapped toplevel behind makes the
    # *next* root in the same process abort on macOS/Tk 9.
    _probe.withdraw()
    _probe.destroy()
except tk.TclError as exc:  # Tk is installed, but there is no display
    pytest.skip(f"Tk has no display: {exc}", allow_module_level=True)


# Only whole-cell headers (name/phone/address), so no run in this module
# loads the spaCy NER model.
HEADERS = ["ID", "Full Name", "Phone Number", "Address"]
COLUMNS = (1, 2, 3)

PASSPHRASE = "right-key"
WRONG_PASSPHRASE = "wrong-key"
# derive_key() is ~0.3s of PBKDF2; do it once for the whole module and hand
# the results to the GUI through a patched gui.derive_key.
KEY = derive_key(PASSPHRASE)
WRONG_KEY = derive_key(WRONG_PASSPHRASE)
_KEYS = {PASSPHRASE: KEY, WRONG_PASSPHRASE: WRONG_KEY}


@pytest.fixture(autouse=True)
def _collect_tk_garbage():
    """Finalize each test's discarded Tk objects here, on the main thread.
    Otherwise a later gc pass can run tkinter's Variable.__del__ from a
    worker thread, which raises "main thread is not in main loop"."""
    yield
    gc.collect()


def _write_csv(path, n_rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for i in range(n_rows):
            writer.writerow([str(i), f"Jane Doe {i}", "555-1234", "12 Elm St"])


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


def _make_app(tmp_path, monkeypatch, askyesno=True):
    """Build an App with every modal dialog replaced by a recorder.

    Returns (app, dialogs) where dialogs is a list of (kind, title, message).
    """
    dialogs = []

    def _recorder(kind, answer=None):
        def _dialog(title="", message="", *args, **kwargs):
            dialogs.append((kind, title, message))
            return answer

        return _dialog

    monkeypatch.setattr(gui.messagebox, "showinfo", _recorder("info"))
    monkeypatch.setattr(gui.messagebox, "showerror", _recorder("error"))
    monkeypatch.setattr(gui.messagebox, "showwarning", _recorder("warning"))
    monkeypatch.setattr(gui.messagebox, "askyesno", _recorder("askyesno", askyesno))
    monkeypatch.setattr(gui, "derive_key", lambda p: _KEYS.get(p) or derive_key(p))

    app = gui.App(tmp_path / "npimasker.log")
    # Keep the toplevel unmapped: update() blocks on the window server if a
    # real window is shown from a non-interactive session. Everything under
    # test (widget state, after(), the queue) works fine withdrawn.
    app.withdraw()
    return app, dialogs


def _configure(app, input_path, output_path, mode="encrypt", passphrase=PASSPHRASE,
               columns=COLUMNS, treatment=gui.WHOLE):
    app.mode.set(mode)
    app.input_path.set(str(input_path))
    app.output_path.set(str(output_path))
    app.key_entry.delete(0, tk.END)
    app.key_entry.insert(0, passphrase)
    app._populate_columns(list(HEADERS))
    for index in range(len(HEADERS)):
        app.set_column_treatment(index, treatment if index in columns else gui.SKIP)


def _tree_rows(app):
    """The (column, treatment) pairs the Treeview is actually displaying."""
    tree = app.columns_tree
    return [tuple(tree.item(iid, "values")) for iid in tree.get_children("")]


def _tree_headers(app):
    return [row[0] for row in _tree_rows(app)]


def _active(app):
    """Indices the user has asked to be processed, whatever the treatment."""
    return {i for i, t in app.column_treatments().items() if t != gui.SKIP}


def _state(app):
    return str(app.run_button.cget("state"))


def _exists(app):
    try:
        return bool(app.winfo_exists())
    except tk.TclError:
        return False


def _close(app):
    try:
        app.destroy()
    except tk.TclError:
        pass


def _pump(app, predicate, what, timeout=60.0, on_tick=None):
    """Drive the Tk event loop until predicate() holds. Returns the number
    of successful update() iterations, which is also the 'did the UI stay
    responsive' measurement."""
    deadline = time.monotonic() + timeout
    ticks = 0
    while time.monotonic() < deadline:
        app.update()
        ticks += 1
        if on_tick is not None:
            on_tick()
        if predicate():
            return ticks
        time.sleep(0.02)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def _pump_for(app, seconds):
    """Keep pumping for a fixed time, e.g. to prove nothing extra fires."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.update()
        time.sleep(0.02)


def _run_to_completion(app, dialogs, timeout=60.0):
    before = len(dialogs)
    app._run()
    return _pump(
        app,
        lambda: len(dialogs) > before and _state(app) == "normal",
        "the run to finish",
        timeout=timeout,
    )


# -- Happy path ----------------------------------------------------------


def test_full_run_writes_output_and_reports_success(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        output_path = tmp_path / "out.csv"
        _write_csv(input_path, 25)
        _configure(app, input_path, output_path, mode="encrypt")

        _run_to_completion(app, dialogs)

        assert output_path.exists()
        rows = _read_csv(output_path)
        assert rows[0] == HEADERS
        assert len(rows) == 26
        assert rows[1][0] == "0"  # unselected column untouched
        assert rows[1][1] != "Jane Doe 0"  # selected column encrypted

        # The output really is the input, encrypted with the entered key.
        round_trip = tmp_path / "round_trip.csv"
        process_csv(str(output_path), str(round_trip), KEY, "decrypt", list(COLUMNS))
        assert _read_csv(round_trip) == _read_csv(input_path)

        assert app.status_var.get().startswith("Last run: ")
        assert str(output_path) in app.status_var.get()
        assert [d[0] for d in dialogs] == ["info"]
        assert str(output_path) in dialogs[0][2]
    finally:
        _close(app)


def test_run_button_disabled_during_run_and_reenabled_after(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        output_path = tmp_path / "out.csv"
        _write_csv(input_path, 10)
        _configure(app, input_path, output_path)

        assert _state(app) == "normal"
        app._run()
        # _run() hands off to a worker thread and returns immediately, with
        # the button already disabled.
        assert _state(app) == "disabled"
        assert app.status_var.get() == "Running..."

        _pump(app, lambda: len(dialogs) > 0, "the success dialog")
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_ui_keeps_pumping_events_while_the_worker_runs(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "big.csv"
        output_path = tmp_path / "big_out.csv"
        _write_csv(input_path, 30_000)
        _configure(app, input_path, output_path)

        # A self-rescheduling after() callback: it can only advance if the
        # Tk event loop is being serviced while the worker thread works.
        ticks = {"n": 0}

        def _tick():
            ticks["n"] += 1
            app.after(10, _tick)

        app.after(10, _tick)

        statuses = []
        app._run()
        updates = _pump(
            app,
            lambda: len(dialogs) > 0,
            "the long run to finish",
            on_tick=lambda: statuses.append(app.status_var.get()),
        )

        assert updates > 10, f"only {updates} event-loop iterations during the run"
        assert ticks["n"] > 10, f"only {ticks['n']} after() callbacks during the run"
        # Progress was reported mid-run, i.e. the loop was live *while* the
        # worker was still going, not just after it finished.
        assert any(
            s.startswith("Processing... ") and s.endswith("%)") for s in statuses
        ), statuses
        assert _state(app) == "normal"
        assert [d[0] for d in dialogs] == ["info"]
    finally:
        _close(app)


def test_two_sequential_runs_do_not_leak_poll_loops(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        first_out = tmp_path / "out1.csv"
        second_out = tmp_path / "out2.csv"
        _write_csv(input_path, 20)
        _configure(app, input_path, first_out)

        _run_to_completion(app, dialogs)
        assert len(dialogs) == 1
        assert _state(app) == "normal"
        # A stale poll loop from run one would fire a second dialog here.
        _pump_for(app, 0.4)
        assert len(dialogs) == 1

        app.output_path.set(str(second_out))
        _run_to_completion(app, dialogs)
        assert len(dialogs) == 2
        assert [d[0] for d in dialogs] == ["info", "info"]
        assert _state(app) == "normal"
        _pump_for(app, 0.4)
        assert len(dialogs) == 2

        assert first_out.exists() and second_out.exists()
        assert str(second_out) in app.status_var.get()
    finally:
        _close(app)


# -- Error routing -------------------------------------------------------


def test_wrong_key_failure_routes_to_error_dialog_with_context(tmp_path, monkeypatch, caplog):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        plain = tmp_path / "in.csv"
        encrypted = tmp_path / "enc.csv"
        _write_csv(plain, 5)
        process_csv(str(plain), str(encrypted), KEY, "encrypt", list(COLUMNS))

        _configure(
            app, encrypted, tmp_path / "dec.csv",
            mode="decrypt", passphrase=WRONG_PASSPHRASE,
        )

        with caplog.at_level(logging.ERROR, logger="npimasker.gui"):
            _run_to_completion(app, dialogs)

        assert app.status_var.get() == "Failed: wrong key or corrupted file."
        assert [d[0] for d in dialogs] == ["error"]
        message = dialogs[0][2]
        assert "Wrong key or corrupted file" in message
        assert "row 2" in message
        assert "column 'Full Name'" in message
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_unexpected_failure_reports_exception_type(tmp_path, monkeypatch, caplog):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        def _boom(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(gui, "process_csv", _boom)

        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 5)
        _configure(app, input_path, tmp_path / "out.csv")

        with caplog.at_level(logging.ERROR, logger="npimasker.gui"):
            _run_to_completion(app, dialogs)

        assert app.status_var.get() == "Failed."
        assert [d[0] for d in dialogs] == ["error"]
        message = dialogs[0][2]
        assert "RuntimeError" in message
        assert "boom" in message
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_report_callback_exception_logs_critical_and_shows_dialog(tmp_path, monkeypatch, caplog):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        try:
            raise ValueError("synthetic widget callback failure")
        except ValueError:
            exc_info = sys.exc_info()

        with caplog.at_level(logging.CRITICAL, logger="npimasker.gui"):
            app.report_callback_exception(*exc_info)

        criticals = [r for r in caplog.records if r.levelno == logging.CRITICAL]
        assert len(criticals) == 1
        assert criticals[0].exc_info is not None
        assert "Traceback (most recent call last)" in caplog.text
        assert "ValueError: synthetic widget callback failure" in caplog.text

        assert [d[0] for d in dialogs] == ["error"]
        message = dialogs[0][2]
        assert "ValueError" in message
        assert "synthetic widget callback failure" in message
    finally:
        _close(app)


# -- Validation ----------------------------------------------------------


def test_validation_short_circuits_before_any_thread_starts(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 3)

        cases = [
            ("missing input", "", str(tmp_path / "out.csv"), PASSPHRASE),
            ("missing output", str(input_path), "", PASSPHRASE),
            ("missing key", str(input_path), str(tmp_path / "out.csv"), ""),
        ]

        for label, in_value, out_value, passphrase in cases:
            dialogs.clear()
            before_threads = threading.active_count()
            _configure(app, input_path, tmp_path / "out.csv")
            app.input_path.set(in_value)
            app.output_path.set(out_value)
            app.key_entry.delete(0, tk.END)
            app.key_entry.insert(0, passphrase)

            app._run()

            assert [d[0] for d in dialogs] == ["warning"], f"{label}: {dialogs}"
            assert _state(app) == "normal", label
            assert app.status_var.get() != "Running...", label
            assert app._progress_queue is None, label
            assert threading.active_count() == before_threads, label
    finally:
        _close(app)


# -- Worker/queue contract ----------------------------------------------


def test_worker_only_emits_queue_messages_on_success(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        output_path = tmp_path / "out.csv"
        _write_csv(input_path, 1100)  # progress fires every 500 rows

        recorded = []
        app._progress_queue = types.SimpleNamespace(put=recorded.append)
        app.status_var.set("sentinel")

        thread = threading.Thread(
            target=app._process_worker,
            args=(str(input_path), str(output_path), KEY, "encrypt", list(COLUMNS), {}),
            daemon=True,
        )
        thread.start()
        thread.join(timeout=60)
        assert not thread.is_alive(), "worker thread did not finish"

        assert recorded[-1] == ("done", None)
        assert all(kind == "progress" for kind, _ in recorded[:-1])
        assert [u.rows for _, u in recorded[:-1]] == [500, 1000]
        assert all(0.0 <= u.fraction <= 1.0 for _, u in recorded[:-1])

        # Nothing in the worker touched Tk: no widget state changed and no
        # dialog was raised from the background thread.
        assert app.status_var.get() == "sentinel"
        assert _state(app) == "normal"
        assert dialogs == []
        assert output_path.exists()
    finally:
        _close(app)


def test_worker_puts_the_exception_on_the_queue_instead_of_raising(tmp_path, monkeypatch, caplog):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        plain = tmp_path / "in.csv"
        encrypted = tmp_path / "enc.csv"
        _write_csv(plain, 5)
        process_csv(str(plain), str(encrypted), KEY, "encrypt", list(COLUMNS))

        recorded = []
        app._progress_queue = types.SimpleNamespace(put=recorded.append)
        app.status_var.set("sentinel")

        with caplog.at_level(logging.ERROR, logger="npimasker.gui"):
            thread = threading.Thread(
                target=app._process_worker,
                args=(str(encrypted), str(tmp_path / "dec.csv"), WRONG_KEY, "decrypt",
                      list(COLUMNS), {}),
                daemon=True,
            )
            thread.start()
            thread.join(timeout=60)
        assert not thread.is_alive(), "worker thread did not finish"

        assert len(recorded) == 1
        kind, payload = recorded[0]
        assert kind == "error"
        assert isinstance(payload, WrongKeyError)
        assert "row 2" in str(payload)

        assert app.status_var.get() == "sentinel"
        assert dialogs == []
    finally:
        _close(app)


def test_progress_queue_messages_drive_the_status_line(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        output_path = tmp_path / "out.csv"
        app._progress_queue = queue.Queue()
        app._progress_queue.put(
            ("progress", ProgressUpdate(rows=500, fraction=0.25, phase="processing"))
        )
        app.run_button.config(state="disabled")

        app._poll_progress(str(output_path), "encrypt")
        assert app.status_var.get() == "Processing... 500 rows (25%)"
        assert _state(app) == "disabled"
        assert dialogs == []

        app._progress_queue.put(("done", None))
        _pump(app, lambda: len(dialogs) > 0, "the queued done message")
        assert _state(app) == "normal"
        assert app.status_var.get() == f"Last run: encrypt -> {output_path}"
    finally:
        _close(app)


# -- Degraded-environment and shutdown paths -----------------------------


def test_app_tolerates_a_missing_log_path(tmp_path, monkeypatch):
    dialogs = []

    def _recorder(kind):
        def _dialog(title="", message="", *args, **kwargs):
            dialogs.append((kind, title, message))

        return _dialog

    monkeypatch.setattr(gui.messagebox, "showinfo", _recorder("info"))
    monkeypatch.setattr(gui.messagebox, "showerror", _recorder("error"))
    monkeypatch.setattr(gui.messagebox, "showwarning", _recorder("warning"))
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(gui.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(gui.os, "startfile", lambda *a, **k: None, raising=False)

    # setup_logging() returns None when no log file could be opened.
    app = gui.App(None)
    try:
        app.withdraw()
        app._open_log_folder()

        app._show_run_error(RuntimeError("boom"))
        message = dialogs[-1][2]
        assert "RuntimeError" in message
        assert "Details were written to" not in message
        assert "None" not in message

        dialogs.clear()
        try:
            raise ValueError("synthetic")
        except ValueError:
            exc_info = sys.exc_info()
        app.report_callback_exception(*exc_info)
        assert "Details were written to" not in dialogs[-1][2]
        assert "None" not in dialogs[-1][2]
    finally:
        _close(app)


def test_close_during_run_is_guarded(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    release = threading.Event()
    try:
        def _blocking_process_csv(*args, **kwargs):
            release.wait(30)

        monkeypatch.setattr(gui, "process_csv", _blocking_process_csv)

        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 5)
        _configure(app, input_path, tmp_path / "out.csv")

        assert app._run_active is False
        assert app.protocol("WM_DELETE_WINDOW")  # handler is wired up

        app._run()
        assert app._run_active is True

        # Declining the confirmation must leave the app alive.
        monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: False)
        app._on_close()
        assert _exists(app), "app was destroyed even though the user declined"
        assert app._run_active is True

        # Accepting it closes the window.
        monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
        app._on_close()
        assert not _exists(app), "app was not destroyed after the user confirmed"
    finally:
        release.set()
        _close(app)


# -- Threaded column loading (Browse) -------------------------------------


def test_columns_load_off_the_main_thread(tmp_path, monkeypatch):
    """Sniffing the encoding scans the whole file, so reading headers
    inline froze the window as soon as a file was picked."""
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 5)

        worker_threads = []
        real_read_headers = gui.read_headers

        def _slow_read_headers(path):
            worker_threads.append(threading.current_thread())
            time.sleep(0.3)
            return real_read_headers(path)

        monkeypatch.setattr(gui, "read_headers", _slow_read_headers)

        app._load_columns_async(str(input_path))
        assert app._loading_columns is True
        assert _state(app) == "disabled", "Run must be blocked until columns exist"

        ticks = _pump(app, lambda: not app._loading_columns, "the columns to load")

        # The UI kept pumping while the read was in flight.
        assert ticks > 3, ticks
        # ...and the read happened somewhere other than the main thread.
        assert worker_threads and worker_threads[0] is not threading.main_thread()

        assert app.headers == HEADERS
        assert _tree_headers(app) == HEADERS
        # Sensitive columns pre-selected, ID left alone.
        assert _active(app) == {1, 2, 3}
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_run_is_refused_while_columns_are_still_loading(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 5)
        _configure(app, input_path, tmp_path / "out.csv")

        app._loading_columns = True
        app._run()

        assert [d[0] for d in dialogs] == ["warning"]
        assert "columns" in dialogs[0][2]
        assert app._run_active is False
    finally:
        _close(app)


def test_unreadable_file_reports_an_error_and_clears_the_columns(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))  # stale columns from a previous pick
        app._load_columns_async(str(tmp_path / "does_not_exist.csv"))
        _pump(app, lambda: not app._loading_columns, "the failed load to settle")

        assert [d[0] for d in dialogs] == ["error"]
        assert "Could not read CSV" in dialogs[0][2]
        assert app.headers == []
        assert _tree_headers(app) == []
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_browsing_during_a_run_does_not_re_enable_the_run_button(tmp_path, monkeypatch):
    """Browse stays available mid-run; finishing a header load must not
    hand the Run button back while the worker is still going."""
    app, dialogs = _make_app(tmp_path, monkeypatch)
    release = threading.Event()
    try:
        monkeypatch.setattr(gui, "process_csv", lambda *a, **k: release.wait(30))
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 5)
        _configure(app, input_path, tmp_path / "out.csv")

        app._run()
        assert app._run_active is True
        assert _state(app) == "disabled"

        app._load_columns_async(str(input_path))
        _pump(app, lambda: not app._loading_columns, "the columns to load")

        assert app._run_active is True
        assert _state(app) == "disabled", "run was still in progress"
        assert app.status_var.get() != "", "the run's status line was clobbered"
    finally:
        release.set()
        _close(app)


def test_already_encrypted_input_gets_its_own_message(tmp_path, monkeypatch):
    """A wrong-file mistake, not a crash: distinct status text, and no
    "see the log" pointer since there is nothing to diagnose."""
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        output_path = tmp_path / "out.csv"
        _write_csv(input_path, 5)
        _configure(app, input_path, output_path)

        def _raise(*a, **k):
            raise gui.AlreadyEncryptedError(
                "Row 2, column 'Notes' already contains NPIMasker encryption "
                "markers. This file looks like it has already been encrypted "
                "- decrypt it first, or choose a different input file."
            )

        monkeypatch.setattr(gui, "process_csv", _raise)
        _run_to_completion(app, dialogs)

        assert app.status_var.get() == "Failed: input is already encrypted."
        assert [d[0] for d in dialogs] == ["error"]
        assert "already been encrypted" in dialogs[0][2]
        assert "Details were written to" not in dialogs[0][2]
        assert _state(app) == "normal"
    finally:
        _close(app)


# -- per-column treatment --------------------------------------------------
#
# The column list is a three-state control (Skip / Scan / Whole cell) rather
# than a tick list. The defaults reproduce exactly what the tick list used to
# pre-select, so a user who touches nothing gets the behaviour they had
# before; the two non-default states are what is new.


def test_defaults_reproduce_the_old_preselection(tmp_path, monkeypatch):
    """The regression that matters most. Sensitive whole-cell headers start
    on Whole cell, sensitive scanned headers on Scan, everything else Skip -
    which is precisely the old tick-list default expressed in three states."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(["ID", "Full Name", "E-Mail", "Notes", "Widget count"])

        assert app.column_treatments() == {
            0: gui.SKIP,    # not sensitive
            1: gui.WHOLE,   # name -> whole-cell category
            2: gui.SCAN,    # sensitive, but scanned
            3: gui.SKIP,    # free text, not sensitive by header
            4: gui.SKIP,
        }
    finally:
        _close(app)


def test_clicking_cycles_through_all_three_states(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        app.set_column_treatment(0, gui.SKIP)

        seen = []
        for _ in range(4):
            app.cycle_column_treatment(0)
            seen.append(app.column_treatments()[0])

        assert seen == [gui.SCAN, gui.WHOLE, gui.SKIP, gui.SCAN]
    finally:
        _close(app)


def test_the_displayed_label_follows_the_treatment(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        for treatment in (gui.SKIP, gui.SCAN, gui.WHOLE):
            app.set_column_treatment(1, treatment)
            assert _tree_rows(app)[1] == ("Full Name", gui.TREATMENT_LABELS[treatment])
    finally:
        _close(app)


def test_decrypt_mode_collapses_the_two_encrypted_states(tmp_path, monkeypatch):
    """Decryption infers treatment from cell content, so Scan and Whole cell
    do the same thing there. Offering the choice would be asking the user a
    question with no consequence, so the control becomes a two-state toggle
    and both encrypted states read "Decrypt"."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        app.mode.set("decrypt")
        app._on_mode_change()

        app.set_column_treatment(1, gui.WHOLE)
        assert _tree_rows(app)[1] == ("Full Name", "Decrypt")
        app.set_column_treatment(1, gui.SCAN)
        assert _tree_rows(app)[1] == ("Full Name", "Decrypt")

        app.set_column_treatment(1, gui.SKIP)
        app.cycle_column_treatment(1)
        assert app.column_treatments()[1] == gui.SCAN
        app.cycle_column_treatment(1)
        assert app.column_treatments()[1] == gui.SKIP  # not WHOLE
    finally:
        _close(app)


def test_treatments_survive_a_mode_switch(tmp_path, monkeypatch):
    """Flipping to Decrypt and back must not quietly rewrite a Whole cell
    choice into something else - the mode changes the labels and the cycle,
    never the stored treatment."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        app.set_column_treatment(1, gui.WHOLE)
        app.set_column_treatment(2, gui.SCAN)
        before = app.column_treatments()

        for mode in ("decrypt", "encrypt"):
            app.mode.set(mode)
            app._on_mode_change()

        assert app.column_treatments() == before
        assert _tree_rows(app)[1] == ("Full Name", gui.TREATMENT_LABELS[gui.WHOLE])
    finally:
        _close(app)


def test_a_new_file_resets_the_treatments(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        app.set_column_treatment(1, gui.SKIP)
        app.set_column_treatment(0, gui.WHOLE)

        app._populate_columns(["ID", "Full Name"])

        assert app.column_treatments() == {0: gui.SKIP, 1: gui.WHOLE}
        assert _tree_headers(app) == ["ID", "Full Name"]
    finally:
        _close(app)


def test_keyboard_and_mouse_both_cycle(tmp_path, monkeypatch):
    """The Treeview must not be mouse-only: the app is used on locked-down
    machines where a keyboard path matters.

    The handlers are driven directly rather than through event_generate.
    Tk will not deliver key events to a withdrawn toplevel, and these tests
    deliberately never map a window - so the binding being wired and the
    handler being correct are asserted separately.
    """
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        tree = app.columns_tree

        # Wired up at all.
        for sequence in ("<space>", "<Return>", "<Button-1>"):
            assert tree.bind(sequence), f"{sequence} is not bound"

        # Keyboard: acts on the focused row.
        app.set_column_treatment(1, gui.SKIP)
        tree.focus("1")
        app._on_tree_key(None)
        assert app.column_treatments()[1] == gui.SCAN
        app._on_tree_key(None)
        assert app.column_treatments()[1] == gui.WHOLE

        # Mouse: acts on the row under the pointer, not the focused one.
        # bbox() needs a mapped window; identify_row() does not.
        y = next((y for y in range(400) if tree.identify_row(y) == "2"), None)
        assert y is not None, "Treeview never reports row 2 under the pointer"
        app.set_column_treatment(2, gui.SKIP)
        app._on_tree_click(types.SimpleNamespace(x=5, y=y))
        assert app.column_treatments()[2] == gui.SCAN
        assert app.column_treatments()[1] == gui.WHOLE  # focused row untouched
    finally:
        _close(app)


def test_a_click_outside_any_row_changes_nothing(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._populate_columns(list(HEADERS))
        before = app.column_treatments()
        app._on_tree_click(types.SimpleNamespace(x=5, y=5000))
        assert app.column_treatments() == before
    finally:
        _close(app)


def test_run_passes_treatments_through_to_process_csv(tmp_path, monkeypatch):
    """The seam between the control and the backend: Skip columns are not
    selected at all, and the other two map onto whole_cell_overrides."""
    captured = {}

    def _fake(input_path, output_path, key, mode, selected, **kwargs):
        captured["selected"] = list(selected)
        captured["overrides"] = kwargs.get("whole_cell_overrides")

    app, _ = _make_app(tmp_path, monkeypatch)
    monkeypatch.setattr(gui, "process_csv", _fake)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 3)
        _configure(app, input_path, tmp_path / "out.csv")
        app.set_column_treatment(0, gui.SKIP)
        app.set_column_treatment(1, gui.WHOLE)
        app.set_column_treatment(2, gui.SCAN)
        app.set_column_treatment(3, gui.SKIP)

        app._run()
        _pump(app, lambda: not app._run_active, "the run to finish")

        assert captured["selected"] == [1, 2]
        assert captured["overrides"] == {1: True, 2: False}
    finally:
        _close(app)


def test_all_skip_still_asks_for_confirmation(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch, askyesno=False)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 3)
        _configure(app, input_path, tmp_path / "out.csv", columns=())

        app._run()

        assert [d[0] for d in dialogs] == ["askyesno"]
        assert "nothing will be changed" in dialogs[0][2]
        assert app._run_active is False
    finally:
        _close(app)


def test_forcing_whole_cell_end_to_end(tmp_path, monkeypatch):
    """The feature working for real, through the GUI and back: a free-text
    column the heuristic would scan is encrypted whole instead, and still
    decrypts without the user having to say so again."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        input_path = tmp_path / "in.csv"
        encrypted = tmp_path / "enc.csv"
        with open(input_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Notes"])
            writer.writerow(["1", "spoke to lilly petlock about the referral"])

        _configure(app, input_path, encrypted)
        app._populate_columns(["ID", "Notes"])
        app.set_column_treatment(0, gui.SKIP)
        app.set_column_treatment(1, gui.WHOLE)
        app._run()
        _pump(app, lambda: not app._run_active, "the encrypt to finish")

        cell = _read_csv(encrypted)[1][1]
        assert looks_like_token(cell)          # whole cell, not spans
        assert "petlock" not in cell           # what the scanner would miss

        decrypted = tmp_path / "dec.csv"
        _configure(app, encrypted, decrypted, mode="decrypt")
        app._populate_columns(["ID", "Notes"])
        app.set_column_treatment(1, gui.SCAN)  # deliberately the "wrong" one
        app._run()
        _pump(app, lambda: not app._run_active, "the decrypt to finish")

        assert _read_csv(decrypted) == _read_csv(input_path)
    finally:
        _close(app)


def test_a_wide_file_does_not_stall_the_event_loop(tmp_path, monkeypatch):
    """A Treeview row is heavier than a Listbox line. Populating a few
    hundred columns has to stay well inside a frame, or picking a wide file
    reintroduces exactly the freeze this whole branch removed."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        headers = [f"Column {i}" for i in range(500)]
        start = time.monotonic()
        app._populate_columns(headers)
        elapsed = time.monotonic() - start

        assert len(app.column_treatments()) == 500
        assert elapsed < 1.0, f"populating 500 columns took {elapsed:.2f}s"
    finally:
        _close(app)


# -- progress bar, verify checkbox, tooltip --------------------------------


def test_the_bar_advances_and_resets(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        output_path = tmp_path / "out.csv"
        app._progress_queue = queue.Queue()
        assert app.progress_bar.cget("value") == 0

        app._progress_queue.put(
            ("progress", ProgressUpdate(rows=500, fraction=0.5, phase="processing"))
        )
        app._poll_progress(str(output_path), "encrypt")
        assert app.progress_bar.cget("value") == gui._PROGRESS_SCALE // 2

        # A finished run must not leave the bar full: done and failed have
        # to look different, and the next run starts from zero.
        app._progress_queue.put(("done", None))
        app._poll_progress(str(output_path), "encrypt")
        assert app.progress_bar.cget("value") == 0
    finally:
        _close(app)


def test_the_bar_resets_after_a_failure_too(tmp_path, monkeypatch):
    app, dialogs = _make_app(tmp_path, monkeypatch)
    try:
        app._progress_queue = queue.Queue()
        app._progress_queue.put(
            ("progress", ProgressUpdate(rows=10, fraction=0.9, phase="processing"))
        )
        app._poll_progress(str(tmp_path / "out.csv"), "encrypt")
        app._progress_queue.put(("error", WrongKeyError("nope")))
        app._poll_progress(str(tmp_path / "out.csv"), "encrypt")

        assert app.progress_bar.cget("value") == 0
        assert _state(app) == "normal"
    finally:
        _close(app)


def test_the_verifying_phase_is_named_in_the_status_line(tmp_path, monkeypatch):
    """Without this the bar sits near 100% through verification and the
    app looks hung - the exact impression this feature exists to remove."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._progress_queue = queue.Queue()
        app._progress_queue.put(
            ("progress", ProgressUpdate(rows=900, fraction=0.6, phase="verifying"))
        )
        app._poll_progress(str(tmp_path / "out.csv"), "encrypt")
        assert app.status_var.get() == "Verifying... 900 rows (60%)"
    finally:
        _close(app)


def test_the_bar_is_indeterminate_while_headers_load(tmp_path, monkeypatch):
    """Reading headers means sniffing the encoding, which has no total to
    report - so the bar must animate rather than claim a percentage."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        app._set_loading_columns(True)
        assert str(app.progress_bar.cget("mode")) == "indeterminate"
        app._set_loading_columns(False)
        assert str(app.progress_bar.cget("mode")) == "determinate"
        assert app.progress_bar.cget("value") == 0
    finally:
        _close(app)


# -- the verify checkbox ---------------------------------------------------


def test_verification_is_off_by_default(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        assert app.verify_var.get() is False
    finally:
        _close(app)


@pytest.mark.parametrize("checked", [False, True])
def test_the_checkbox_reaches_process_csv(tmp_path, monkeypatch, checked):
    captured = {}

    def _fake(input_path, output_path, key, mode, selected, **kwargs):
        captured["verify"] = kwargs.get("verify")

    app, _ = _make_app(tmp_path, monkeypatch)
    monkeypatch.setattr(gui, "process_csv", _fake)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 3)
        _configure(app, input_path, tmp_path / "out.csv")
        app.verify_var.set(checked)

        app._run()
        _pump(app, lambda: not app._run_active, "the run to finish")

        assert captured["verify"] is checked
    finally:
        _close(app)


def test_verification_failure_surfaces_as_an_error(tmp_path, monkeypatch):
    """A verification failure has to reach the user as a dialog, not vanish
    into a background thread - and no output may be left behind."""
    from npimasker.csv_processor import VerificationError

    def _fake(*args, **kwargs):
        raise VerificationError("Row 7, column 'Full Name' does not decrypt back.")

    app, dialogs = _make_app(tmp_path, monkeypatch)
    monkeypatch.setattr(gui, "process_csv", _fake)
    try:
        input_path = tmp_path / "in.csv"
        _write_csv(input_path, 3)
        _configure(app, input_path, tmp_path / "out.csv")
        app.verify_var.set(True)

        app._run()
        _pump(app, lambda: not app._run_active, "the run to fail")

        assert [d[0] for d in dialogs] == ["error"]
        assert "Row 7" in dialogs[0][2]
        assert not (tmp_path / "out.csv").exists()
        assert app.progress_bar.cget("value") == 0
    finally:
        _close(app)


# -- the tooltip -----------------------------------------------------------


def test_the_checkbox_has_a_tooltip_explaining_the_trade(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        text = app.verify_tooltip.text
        assert "decrypts back" in text        # what it checks
        assert "no file is written" in text   # what happens on failure
        assert "doubles" in text              # what it costs
    finally:
        _close(app)


def test_the_tooltip_is_bound_to_hover(tmp_path, monkeypatch):
    """Tk will not deliver synthetic enter/leave to a withdrawn toplevel
    and these tests never map a window, so the binding and the handler are
    asserted separately."""
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        for sequence in ("<Enter>", "<Leave>"):
            assert app.verify_check.bind(sequence), f"{sequence} is not bound"
    finally:
        _close(app)


def test_the_tooltip_appears_and_goes_away(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        tip = app.verify_tooltip
        assert tip._tip is None
        tip.show()
        assert tip._tip is not None and tip._tip.winfo_exists()
        tip._hide()
        assert tip._tip is None
    finally:
        _close(app)


def test_showing_the_tooltip_twice_makes_only_one_window(tmp_path, monkeypatch):
    app, _ = _make_app(tmp_path, monkeypatch)
    try:
        tip = app.verify_tooltip
        tip.show()
        first = tip._tip
        tip.show()
        assert tip._tip is first
        tip._hide()
    finally:
        _close(app)


def test_a_pending_tooltip_does_not_outlive_the_app(tmp_path, monkeypatch):
    """A scheduled after() firing into a destroyed widget is the classic
    way a Tk app dies on close with no visible error."""
    app, _ = _make_app(tmp_path, monkeypatch)
    tip = app.verify_tooltip
    tip._schedule()
    assert tip._after_id is not None
    _close(app)
    tip._hide()      # must not raise even though the widget is gone
    tip.show()       # nor must this
