"""Tests for npimasker.logging_setup (plan item (a)).

setup_logging() runs before anything else in a `--onefile --windowed`
build, so it is the one function that must never be the reason the app
fails to start: an unwritable log directory has to degrade to a temp dir,
and a completely unwritable machine has to degrade to "no file logging"
rather than a crash the user can't even see.
"""

import logging
import os
import sys
import tempfile
import threading
import types
from pathlib import Path

import pytest

from npimasker import __version__, logging_setup


@pytest.fixture(autouse=True)
def _isolated_logging_state():
    """Keep setup_logging()'s global side effects inside this test file.

    Also hands each test a root logger with no handlers, so
    logging.basicConfig() inside setup_logging() behaves the way it does
    in a real process rather than being a no-op because pytest's logging
    plugin got there first.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    saved_excepthook = sys.excepthook
    saved_thread_excepthook = threading.excepthook

    root.handlers[:] = []
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            if handler not in saved_handlers:
                handler.close()
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        sys.excepthook = saved_excepthook
        threading.excepthook = saved_thread_excepthook


def _reset_root():
    """Make the root logger look like a fresh process.

    pytest's logging plugin re-attaches its capture handlers to the root
    logger at the start of every test phase, which would silently turn
    the logging.basicConfig() call inside setup_logging() into a no-op.
    """
    logging.getLogger().handlers[:] = []


def _setup_logging():
    _reset_root()
    return logging_setup.setup_logging()


def _read_log(path):
    return Path(path).read_text(encoding="utf-8")


def _skip_if_permissions_not_enforced():
    if sys.platform == "win32":
        pytest.skip("directory mode bits do not block writes on Windows")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root ignores directory permission bits")


def _boom():
    raise ZeroDivisionError("synthetic-boom")


def _exc_info():
    try:
        _boom()
    except ZeroDivisionError:
        return sys.exc_info()


def _fake_ctypes(windll=None, avail_phys=0):
    """Stand-in for the ctypes module as seen from inside a Win32 call."""

    class _Structure:
        def __getattr__(self, name):
            if name == "ullAvailPhys":
                return avail_phys
            return 0

    fake = types.SimpleNamespace(
        Structure=_Structure,
        c_ulong=int,
        c_ulonglong=int,
        sizeof=lambda obj: 64,
        byref=lambda obj: obj,
    )
    if windll is not None:
        fake.windll = windll
    return fake


def _fake_windll(result):
    kernel32 = types.SimpleNamespace(GlobalMemoryStatusEx=lambda ref: result)
    return types.SimpleNamespace(kernel32=kernel32)


def test_setup_logging_writes_under_localappdata(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    path = _setup_logging()

    assert path == tmp_path / "NPIMasker" / "logs" / "npimasker.log"
    assert path.exists()
    logging.getLogger("npimasker.x").info("hello-from-test")
    assert "hello-from-test" in _read_log(path)


def test_setup_logging_writes_startup_banner(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    text = _read_log(_setup_logging())

    assert "NPIMasker v%s starting" % __version__ in text
    assert "Platform: " in text
    assert "Python: " in text
    assert "Frozen (PyInstaller): " in text


def test_setup_logging_falls_back_to_temp_dir(tmp_path, monkeypatch):
    _skip_if_permissions_not_enforced()
    primary = tmp_path / "appdata"
    primary.mkdir()
    fallback = tmp_path / "fallback-temp"
    fallback.mkdir()
    real_tempdir = Path(tempfile.gettempdir())
    monkeypatch.setenv("LOCALAPPDATA", str(primary))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fallback))

    primary.chmod(0o500)
    try:
        path = _setup_logging()

        assert path is not None
        assert primary not in path.parents
        assert fallback in path.parents or real_tempdir in path.parents
        assert path.exists()
        logging.getLogger("npimasker.fallback").info("fallback-line")
        assert "fallback-line" in _read_log(path)
    finally:
        primary.chmod(0o700)


def test_setup_logging_returns_none_when_no_dir_is_writable(tmp_path, monkeypatch):
    def _deny(*args, **kwargs):
        raise PermissionError("denied")

    original_sys_hook = sys.excepthook
    original_thread_hook = threading.excepthook
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nope"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path / "also-nope"))
    monkeypatch.setattr(Path, "mkdir", _deny)
    monkeypatch.setattr(os, "makedirs", _deny)

    assert _setup_logging() is None
    # The app still has to report crashes even with no log file.
    assert sys.excepthook is not original_sys_hook
    assert threading.excepthook is not original_thread_hook


def test_setup_logging_falls_back_to_home_without_localappdata(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    path = _setup_logging()

    assert path == fake_home / "NPIMasker" / "logs" / "npimasker.log"
    assert path.exists()


def test_setup_logging_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    _reset_root()
    first = logging_setup.setup_logging()
    second = logging_setup.setup_logging()  # deliberately no reset in between

    assert first == second
    assert len(logging.getLogger().handlers) == 1


def test_setup_logging_installs_excepthooks(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    original_sys_hook = sys.excepthook
    original_thread_hook = threading.excepthook

    _setup_logging()

    assert sys.excepthook is not original_sys_hook
    assert threading.excepthook is not original_thread_hook


def test_excepthook_logs_critical_with_traceback(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = _setup_logging()

    sys.excepthook(*_exc_info())

    text = _read_log(path)
    assert "CRITICAL" in text
    assert "Unhandled exception" in text
    assert "ZeroDivisionError: synthetic-boom" in text
    assert "_boom" in text  # the traceback, not just the exception line


def test_excepthook_survives_missing_stderr(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = _setup_logging()
    # PyInstaller --windowed: no console, sys.stderr is None.
    monkeypatch.setattr(sys, "stderr", None)

    sys.excepthook(*_exc_info())

    assert "ZeroDivisionError: synthetic-boom" in _read_log(path)


def test_thread_excepthook_logs_uncaught_thread_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = _setup_logging()

    def _target():
        raise RuntimeError("thread-boom")

    thread = threading.Thread(target=_target, name="worker-thread")
    thread.start()
    thread.join()

    text = _read_log(path)
    assert "worker-thread" in text
    assert "RuntimeError: thread-boom" in text


@pytest.mark.skipif(sys.platform == "win32", reason="this assertion is about the non-Windows branch")
def test_available_memory_mb_is_none_off_windows():
    assert logging_setup._available_memory_mb() is None


def test_available_memory_mb_reads_win32_value(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(
        sys.modules,
        "ctypes",
        _fake_ctypes(windll=_fake_windll(result=1), avail_phys=2048 * 1024 * 1024),
    )

    assert logging_setup._available_memory_mb() == 2048


def test_available_memory_mb_swallows_non_oserror(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    # No .windll attribute: exactly what a stripped/mismatched ctypes looks like.
    monkeypatch.setitem(sys.modules, "ctypes", _fake_ctypes())

    assert logging_setup._available_memory_mb() is None


def test_available_memory_mb_none_when_win32_call_fails(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(
        sys.modules,
        "ctypes",
        _fake_ctypes(windll=_fake_windll(result=0), avail_phys=2048 * 1024 * 1024),
    )

    assert logging_setup._available_memory_mb() is None


def test_setup_logging_survives_broken_memory_probe(tmp_path, monkeypatch):
    """A crashing memory probe must not cost the app its log file."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "ctypes", _fake_ctypes())

    path = _setup_logging()

    assert path is not None
    assert "NPIMasker v%s starting" % __version__ in _read_log(path)
