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
import tkinter as tk
import types

import pytest

from npimasker import gui
from npimasker.crypto import WrongKeyError, derive_key
from npimasker.csv_processor import process_csv

try:
    _probe = tk.Tk()
    # Withdraw before destroying: leaving a mapped toplevel behind makes the
    # *next* root in the same process abort on macOS/Tk 9.
    _probe.withdraw()
    _probe.destroy()
except tk.TclError as exc:  # headless CI has no display
    pytest.skip(f"Tk is unavailable: {exc}", allow_module_level=True)


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
               columns=COLUMNS):
    app.mode.set(mode)
    app.input_path.set(str(input_path))
    app.output_path.set(str(output_path))
    app.key_entry.delete(0, tk.END)
    app.key_entry.insert(0, passphrase)
    app.headers = list(HEADERS)
    app.columns_list.delete(0, tk.END)
    for header in HEADERS:
        app.columns_list.insert(tk.END, header)
    for index in columns:
        app.columns_list.selection_set(index)


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
        assert any(s.startswith("Processing... row ") for s in statuses), statuses
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
            args=(str(input_path), str(output_path), KEY, "encrypt", list(COLUMNS)),
            daemon=True,
        )
        thread.start()
        thread.join(timeout=60)
        assert not thread.is_alive(), "worker thread did not finish"

        assert recorded[-1] == ("done", None)
        assert recorded[:-1] == [("progress", 500), ("progress", 1000)]
        assert all(kind == "progress" for kind, _ in recorded[:-1])

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
                      list(COLUMNS)),
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
        app._progress_queue.put(("progress", 500))
        app.run_button.config(state="disabled")

        app._poll_progress(str(output_path), "encrypt")
        assert app.status_var.get() == "Processing... row 500"
        assert _state(app) == "disabled"
        assert dialogs == []

        app._progress_queue.put(("done", None))
        _pump(app, lambda: len(dialogs) > 0, "the queued done message")
        assert _state(app) == "normal"
        assert app.status_var.get() == f"Last run: encrypt -> {output_path}"
    finally:
        _close(app)


# -- Not implemented yet -------------------------------------------------


@pytest.mark.xfail(strict=True, reason="plan item: App must tolerate log_path=None")
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


@pytest.mark.xfail(
    strict=True, reason="plan item: close-during-run guard (_run_active + _on_close)"
)
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
