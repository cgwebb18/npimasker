"""Rotating file logging + crash capture for NPIMasker.

The Windows build is a `--onefile --windowed` PyInstaller app: there is no
console, so print()/stderr are invisible to the user, and a plain
try/except around one call site (as in gui.py's `_run`) can't catch
exceptions raised from a Tk widget callback or a background thread. This
module gives every run a log file on disk and installs hooks so unhandled
exceptions land in it no matter where they're raised.
"""

import logging
import os
import platform
import sys
import tempfile
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from npimasker import __version__

_LOG_FILENAME = "npimasker.log"

# The log file actually in use, which may be a fallback location rather
# than the preferred one, or None if file logging couldn't be set up.
_active_path: Path | None = None


def _log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path.home()
    return root / "NPIMasker" / "logs"


def log_path() -> Path:
    return _log_dir() / _LOG_FILENAME


def _candidate_dirs():
    """Log locations to try, best first. The preferred spot can be
    unusable on a locked-down corporate Windows machine (LOCALAPPDATA
    redirected to an offline network share, restrictive ACLs), and
    failing to log must never stop the app from starting."""
    yield _log_dir()
    yield Path(tempfile.gettempdir()) / "NPIMasker" / "logs"


def _available_memory_mb():
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return status.ullAvailPhys // (1024 * 1024)
    except Exception:
        # Diagnostics are strictly best-effort: a missing ctypes symbol
        # raises AttributeError, not OSError, and must not take startup
        # down with it.
        return None


def _excepthook(exc_type, exc_value, exc_tb):
    logging.getLogger(__name__).critical(
        "Unhandled exception", exc_info=(exc_type, exc_value, exc_tb)
    )
    sys.__excepthook__(exc_type, exc_value, exc_tb)


def _thread_excepthook(args):
    logging.getLogger(__name__).critical(
        "Unhandled exception in thread %r",
        args.thread.name if args.thread else "?",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def _attach_handler() -> Path | None:
    """Attach a rotating file handler at the first usable location.
    Returns the active log file path, or None if nowhere was writable."""
    for directory in _candidate_dirs():
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / _LOG_FILENAME
            handler = RotatingFileHandler(
                path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
            )
        except Exception:
            continue
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        # Attach explicitly rather than via basicConfig, which silently
        # does nothing whenever the root logger already has a handler.
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.addHandler(handler)
        return path
    return None


def setup_logging() -> Path | None:
    """Configure a rotating log file and install crash-capturing hooks.

    Must be called once, before the GUI is built, so startup failures
    (e.g. a bad PyInstaller bundle) are captured too. Returns the log
    file path, or None if no location was writable.

    Never raises: losing diagnostics is survivable, failing to launch is
    not, and in a --windowed build a startup exception is invisible.
    """
    global _active_path
    if any(isinstance(h, RotatingFileHandler) for h in logging.getLogger().handlers):
        return _active_path  # already configured; don't duplicate handlers

    path = _active_path = _attach_handler()

    logger = logging.getLogger(__name__)
    logger.info("NPIMasker v%s starting", __version__)
    logger.info("Platform: %s", platform.platform())
    logger.info("Python: %s", sys.version.replace("\n", " "))
    logger.info("Frozen (PyInstaller): %s", getattr(sys, "frozen", False))
    mem_mb = _available_memory_mb()
    if mem_mb is not None:
        logger.info("Available physical memory: %d MB", mem_mb)

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook

    return path
