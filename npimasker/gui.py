"""Tkinter GUI for NPIMasker."""

import contextlib
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from npimasker import __version__
from npimasker.crypto import (
    AlreadyEncryptedError,
    WrongKeyError,
    derive_key,
    generate_passphrase,
)
from npimasker.csv_processor import process_csv, read_headers
from npimasker.logging_setup import setup_logging
from npimasker.sensitive_fields import detect_sensitive_columns, is_whole_cell_header

logger = logging.getLogger(__name__)

# How a column is treated. The old control was a tick list, which could only
# say "process this column" and left the how to the header heuristic. Three
# states let the user say it directly - which matters both for correctness
# (a wholly-sensitive free-text column is safer encrypted whole than
# partially scanned) and for speed (scanning is where all the runtime goes).
SKIP = "skip"
SCAN = "scan"
WHOLE = "whole"

TREATMENT_LABELS = {
    SKIP: "Skip",
    SCAN: "Scan for sensitive text",
    WHOLE: "Encrypt whole cell",
}

# Decryption infers each cell's treatment from its content, so Scan and
# Whole cell do exactly the same thing there. Showing the distinction would
# be asking the user a question with no consequence.
DECRYPT_LABELS = {SKIP: "Skip", SCAN: "Decrypt", WHOLE: "Decrypt"}

_CYCLE = (SKIP, SCAN, WHOLE)

VERIFY_TOOLTIP = (
    "Re-reads the finished file and checks every value: columns you did "
    "not select are unchanged, and every encrypted cell decrypts back to "
    "exactly what it was.\n\n"
    "If anything does not match, the run fails and no file is written.\n\n"
    "Roughly doubles the time on a fast run. On a slow one - where columns "
    "are scanned for sensitive text - it costs almost nothing."
)

# ttk.Progressbar is integer-valued, so a fraction is scaled onto this.
_PROGRESS_SCALE = 1000


class Tooltip:
    """A hover label, because Tk has no native tooltip.

    Deliberately small: a borderless Toplevel shown after a short delay
    and destroyed on leave. The delay matters - without it the tip flashes
    up whenever the pointer crosses the widget on its way somewhere else.
    """

    def __init__(self, widget, text: str, delay_ms: int = 500):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self.show)

    def _cancel(self):
        if self._after_id is not None:
            with contextlib.suppress(tk.TclError):
                self.widget.after_cancel(self._after_id)
            self._after_id = None

    def show(self):
        if self._tip is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
            tip = tk.Toplevel(self.widget)
            tip.wm_overrideredirect(True)   # no title bar or border
            tip.wm_geometry(f"+{x}+{y}")
            tk.Label(
                tip, text=self.text, justify="left", wraplength=340,
                background="#ffffe0", relief="solid", borderwidth=1, padx=6, pady=4,
            ).pack()
        except tk.TclError:
            return  # widget went away mid-hover
        self._tip = tip

    def _hide(self, _event=None):
        self._cancel()
        if self._tip is not None:
            with contextlib.suppress(tk.TclError):
                self._tip.destroy()
            self._tip = None


class App(tk.Tk):
    def __init__(self, log_path):
        super().__init__()
        self.log_path = log_path
        self.title(f"NPIMasker v{__version__}")
        # Tall enough for the progress bar and status line beneath the Run
        # row: at the previous 520 the status text was clipped off the
        # bottom edge, which is exactly the text a long run needs to show.
        self.geometry("580x600")
        self.minsize(500, 520)

        self.mode = tk.StringVar(value="encrypt")
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.headers: list[str] = []
        self._treatments: dict[int, str] = {}
        self._progress_queue = None
        self._header_queue = None
        self._run_active = False
        self._loading_columns = False

        self._build_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def report_callback_exception(self, exc, val, tb):
        """Tkinter routes exceptions raised inside widget callbacks here
        instead of to sys.excepthook, and its default behavior is to just
        print to stderr - invisible in a --windowed build. Log and surface
        them like any other failure."""
        logger.critical("Unhandled error in UI callback", exc_info=(exc, val, tb))
        messagebox.showerror(
            "NPIMasker", f"Unexpected error: {exc.__name__}: {val}{self._log_hint()}"
        )

    # -- Progress bar ------------------------------------------------------

    def _progress_reset(self):
        with contextlib.suppress(tk.TclError):
            self.progress_bar.stop()
            self.progress_bar.config(mode="determinate", value=0)

    def _progress_indeterminate(self):
        """For work with no knowable total - reading a file's header means
        sniffing its encoding, which has no progress to report."""
        with contextlib.suppress(tk.TclError):
            self.progress_bar.config(mode="indeterminate", value=0)
            self.progress_bar.start(15)

    def _progress_set(self, fraction: float):
        with contextlib.suppress(tk.TclError):
            self.progress_bar.stop()
            self.progress_bar.config(
                mode="determinate",
                value=max(0, min(_PROGRESS_SCALE, int(fraction * _PROGRESS_SCALE))),
            )

    def _log_hint(self) -> str:
        """Trailing '...see the log' line for error dialogs, omitted when
        no log file could be opened (see logging_setup.setup_logging)."""
        if self.log_path is None:
            return ""
        return f"\n\nDetails were written to:\n{self.log_path}"

    # -- UI construction -------------------------------------------------

    def _build_widgets(self):
        pad = {"padx": 10, "pady": 6}

        mode_frame = ttk.Frame(self)
        mode_frame.pack(fill="x", **pad)
        ttk.Label(mode_frame, text="Mode:").pack(side="left")
        ttk.Radiobutton(
            mode_frame, text="Encrypt", variable=self.mode, value="encrypt",
            command=self._on_mode_change,
        ).pack(side="left", padx=8)
        ttk.Radiobutton(
            mode_frame, text="Decrypt", variable=self.mode, value="decrypt",
            command=self._on_mode_change,
        ).pack(side="left")

        file_frame = ttk.Frame(self)
        file_frame.pack(fill="x", **pad)
        ttk.Label(file_frame, text="Input CSV:").pack(anchor="w")
        row = ttk.Frame(file_frame)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.input_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self._browse_input).pack(side="left", padx=6)

        cols_frame = ttk.Frame(self)
        cols_frame.pack(fill="both", expand=True, **pad)
        ttk.Label(
            cols_frame,
            text="Columns (click a row, or press Space, to change how it is treated):",
        ).pack(anchor="w")
        list_row = ttk.Frame(cols_frame)
        list_row.pack(fill="both", expand=True)
        self.columns_tree = ttk.Treeview(
            list_row, columns=("column", "treatment"), show="headings", selectmode="browse"
        )
        self.columns_tree.heading("column", text="Column")
        self.columns_tree.heading("treatment", text="Treatment")
        self.columns_tree.column("column", width=240, anchor="w")
        self.columns_tree.column("treatment", width=180, anchor="w")
        self.columns_tree.pack(side="left", fill="both", expand=True)
        # Mouse and keyboard both cycle: the app is used on locked-down
        # machines, and a mouse-only three-state control would be unusable
        # for anyone driving it from the keyboard.
        self.columns_tree.bind("<Button-1>", self._on_tree_click)
        self.columns_tree.bind("<space>", self._on_tree_key)
        self.columns_tree.bind("<Return>", self._on_tree_key)
        scrollbar = ttk.Scrollbar(list_row, orient="vertical", command=self.columns_tree.yview)
        scrollbar.pack(side="left", fill="y")
        self.columns_tree.config(yscrollcommand=scrollbar.set)

        key_frame = ttk.Frame(self)
        key_frame.pack(fill="x", **pad)
        ttk.Label(key_frame, text="Key:").pack(anchor="w")
        key_row = ttk.Frame(key_frame)
        key_row.pack(fill="x")
        self.key_entry = ttk.Entry(key_row, show="*")
        self.key_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(key_row, text="Show", command=self._toggle_key_visibility).pack(side="left", padx=4)
        key_btn_row = ttk.Frame(key_frame)
        key_btn_row.pack(fill="x", pady=(4, 0))
        ttk.Button(key_btn_row, text="Generate & Save Key...", command=self._generate_key).pack(side="left")
        ttk.Button(key_btn_row, text="Load Key from File...", command=self._load_key).pack(side="left", padx=6)

        out_frame = ttk.Frame(self)
        out_frame.pack(fill="x", **pad)
        ttk.Label(out_frame, text="Output CSV:").pack(anchor="w")
        out_row = ttk.Frame(out_frame)
        out_row.pack(fill="x")
        ttk.Entry(out_row, textvariable=self.output_path).pack(side="left", fill="x", expand=True)
        ttk.Button(out_row, text="Save As...", command=self._browse_output).pack(side="left", padx=6)

        run_frame = ttk.Frame(self)
        run_frame.pack(fill="x", **pad)
        ttk.Button(run_frame, text="Open Log Folder", command=self._open_log_folder).pack(
            side="left"
        )
        # Off by default: on a fast run verification roughly doubles the
        # time, and most runs are small. The tooltip explains the trade so
        # the choice is informed rather than a mystery checkbox.
        self.verify_var = tk.BooleanVar(value=False)
        self.verify_check = ttk.Checkbutton(
            run_frame, text="Verify output", variable=self.verify_var
        )
        self.verify_check.pack(side="left", padx=12)
        self.verify_tooltip = Tooltip(self.verify_check, VERIFY_TOOLTIP)
        self.run_button = ttk.Button(run_frame, text="Run", command=self._run)
        self.run_button.pack(side="right")

        self.progress_bar = ttk.Progressbar(
            self, mode="determinate", maximum=_PROGRESS_SCALE, value=0
        )
        self.progress_bar.pack(fill="x", padx=10)

        self.status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status_var, foreground="gray").pack(
            fill="x", padx=10, pady=(0, 10)
        )

    # -- Actions -----------------------------------------------------------

    def _on_mode_change(self):
        self._suggest_output_path()
        self._refresh_all_rows()

    def _browse_input(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        self.input_path.set(path)
        self._suggest_output_path()
        self._load_columns_async(path)

    def _load_columns_async(self, path: str):
        """Read the header row on a worker thread.

        Reading headers means sniffing the encoding first, which scans the
        whole file - so on a large CSV, or one on a network share, doing
        this inline froze the window the moment the user picked a file.
        That was the second of the two freezes; moving process_csv off the
        main thread only fixed the first.
        """
        self._header_queue = queue.Queue()
        self._set_loading_columns(True)
        threading.Thread(
            target=self._header_worker, args=(path,), daemon=True
        ).start()
        self.after(50, self._poll_headers)

    def _header_worker(self, path: str):
        try:
            headers = read_headers(path)
        except Exception as exc:  # surface everything: a windowed app has no stderr
            logger.exception("read_headers failed")
            self._header_queue.put(("error", exc))
        else:
            self._header_queue.put(("headers", headers))

    def _poll_headers(self):
        try:
            kind, payload = self._header_queue.get_nowait()
        except queue.Empty:
            self.after(50, self._poll_headers)
            return

        self._set_loading_columns(False)
        if kind == "error":
            messagebox.showerror("NPIMasker", f"Could not read CSV: {payload}{self._log_hint()}")
            self._populate_columns([])
        else:
            self._populate_columns(payload)

    def _set_loading_columns(self, loading: bool):
        self._loading_columns = loading
        # Don't stomp on a run in progress: Browse stays available during
        # one, and the run owns the status line and the Run button.
        if self._run_active:
            return
        self.run_button.config(state="disabled" if loading else "normal")
        self.status_var.set("Reading columns..." if loading else "")
        if loading:
            self._progress_indeterminate()
        else:
            self._progress_reset()

    def _populate_columns(self, headers: list[str]):
        """Rebuild the column list, seeding each row's default treatment.

        The defaults are exactly what the old tick list pre-selected,
        expressed in three states: a sensitive header is ticked, and the
        header heuristic already decided whether it would then be encrypted
        whole or scanned. A user who touches nothing gets what they had.
        """
        self.headers = headers
        self.columns_tree.delete(*self.columns_tree.get_children(""))
        sensitive = set(detect_sensitive_columns(self.headers))
        self._treatments = {}
        for i, header in enumerate(self.headers):
            if i not in sensitive:
                treatment = SKIP
            else:
                treatment = WHOLE if is_whole_cell_header(header) else SCAN
            self._treatments[i] = treatment
            self.columns_tree.insert(
                "", tk.END, iid=str(i), values=(header, self._label(treatment))
            )

    # -- Column treatments -------------------------------------------------

    def _label(self, treatment: str) -> str:
        labels = DECRYPT_LABELS if self.mode.get() == "decrypt" else TREATMENT_LABELS
        return labels[treatment]

    def column_treatments(self) -> dict[int, str]:
        """The chosen treatment for every column, by index."""
        return dict(self._treatments)

    def set_column_treatment(self, index: int, treatment: str):
        self._treatments[index] = treatment
        self._refresh_row(index)

    def cycle_column_treatment(self, index: int):
        """Advance one row to its next state.

        In decrypt mode this is a two-state toggle, because Scan and Whole
        cell are indistinguishable there - cycling through both would show
        the label not changing and read as a broken control. The stored
        treatment is never rewritten on a mode change, only relabelled, so
        a Whole cell choice survives a trip through Decrypt and back.
        """
        current = self._treatments.get(index, SKIP)
        if self.mode.get() == "decrypt":
            self._treatments[index] = SCAN if current == SKIP else SKIP
        else:
            self._treatments[index] = _CYCLE[(_CYCLE.index(current) + 1) % len(_CYCLE)]
        self._refresh_row(index)

    def _refresh_row(self, index: int):
        iid = str(index)
        if self.columns_tree.exists(iid):
            self.columns_tree.set(iid, "treatment", self._label(self._treatments[index]))

    def _refresh_all_rows(self):
        for index in self._treatments:
            self._refresh_row(index)

    def _on_tree_click(self, event):
        row = self.columns_tree.identify_row(event.y)
        if row:
            self.cycle_column_treatment(int(row))

    def _on_tree_key(self, _event):
        row = self.columns_tree.focus()
        if row:
            self.cycle_column_treatment(int(row))
        return "break"  # Space would otherwise also scroll the Treeview

    def _suggest_output_path(self):
        input_path = self.input_path.get()
        if not input_path:
            return
        base, ext = os.path.splitext(input_path)
        suffix = "_encrypted" if self.mode.get() == "encrypt" else "_decrypted"
        self.output_path.set(f"{base}{suffix}{ext or '.csv'}")

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            self.output_path.set(path)

    def _toggle_key_visibility(self):
        self.key_entry.config(show="" if self.key_entry.cget("show") == "*" else "*")

    def _generate_key(self):
        passphrase = generate_passphrase()
        save_path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")],
            title="Save new key file",
        )
        if not save_path:
            return
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(passphrase)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, passphrase)
        messagebox.showinfo(
            "NPIMasker",
            f"New key saved to:\n{save_path}\n\n"
            "Keep this file safe and separate from the encrypted CSV. "
            "Without it, the encrypted data cannot be recovered.",
        )

    def _load_key(self):
        path = filedialog.askopenfilename(
            filetypes=[("Key files", "*.key"), ("All files", "*.*")], title="Load key file"
        )
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            passphrase = f.read().strip()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, passphrase)

    def _open_log_folder(self):
        if self.log_path is None:
            messagebox.showinfo(
                "NPIMasker",
                "No log file is available - NPIMasker could not write to any "
                "log location on this machine.",
            )
            return
        log_dir = self.log_path.parent
        try:
            if sys.platform == "win32":
                os.startfile(log_dir)  # noqa: S606 - opening our own log folder
            elif sys.platform == "darwin":
                subprocess.run(["open", str(log_dir)], check=False)
            else:
                subprocess.run(["xdg-open", str(log_dir)], check=False)
        except OSError as exc:
            messagebox.showerror("NPIMasker", f"Could not open log folder:\n{log_dir}\n\n{exc}")

    def _run(self):
        input_path = self.input_path.get()
        output_path = self.output_path.get()
        passphrase = self.key_entry.get()
        # Skip means "don't select it at all"; the other two become the
        # explicit whole-cell override, so the backend never has to re-guess
        # from the header what the user already told us.
        selected = sorted(i for i, t in self._treatments.items() if t != SKIP)
        overrides = {i: self._treatments[i] == WHOLE for i in selected}
        mode = self.mode.get()

        if self._loading_columns:
            messagebox.showwarning(
                "NPIMasker", "Still reading that file's columns - try again in a moment."
            )
            return
        if not input_path:
            messagebox.showwarning("NPIMasker", "Choose an input CSV file first.")
            return
        if not output_path:
            messagebox.showwarning("NPIMasker", "Choose where to save the output CSV.")
            return
        if not passphrase:
            messagebox.showwarning("NPIMasker", "Enter or generate a key first.")
            return
        if not selected:
            if not messagebox.askyesno(
                "NPIMasker",
                "Every column is set to Skip, so nothing will be changed. "
                "Continue anyway?",
            ):
                return

        key = derive_key(passphrase)
        self._progress_queue = queue.Queue()
        self._run_active = True
        self.run_button.config(state="disabled")
        self.status_var.set("Running...")
        self._progress_set(0.0)

        thread = threading.Thread(
            target=self._process_worker,
            args=(input_path, output_path, key, mode, selected, overrides,
                  self.verify_var.get()),
            daemon=True,
        )
        thread.start()
        self.after(100, self._poll_progress, output_path, mode)

    def _process_worker(self, input_path, output_path, key, mode, selected, overrides,
                        verify=False):
        """Runs on a background thread so the Tk event loop keeps pumping
        messages during long CSV runs, instead of Windows showing the app
        as unresponsive for the whole run."""
        try:
            process_csv(
                input_path,
                output_path,
                key,
                mode,
                selected,
                whole_cell_overrides=overrides,
                verify=verify,
                progress_callback=lambda u: self._progress_queue.put(("progress", u)),
            )
        except Exception as exc:  # surface everything: a windowed app has no stderr
            logger.exception("process_csv failed")
            self._progress_queue.put(("error", exc))
        else:
            self._progress_queue.put(("done", None))

    def _poll_progress(self, output_path, mode):
        try:
            while True:
                kind, payload = self._progress_queue.get_nowait()
                if kind == "progress":
                    verb = "Verifying" if payload.phase == "verifying" else "Processing"
                    self.status_var.set(
                        f"{verb}... {payload.rows:,} rows ({payload.fraction:.0%})"
                    )
                    self._progress_set(payload.fraction)
                elif kind == "error":
                    self._finish_run()
                    self._show_run_error(payload)
                    return
                elif kind == "done":
                    self._finish_run()
                    messagebox.showinfo("NPIMasker", f"Done. Output written to:\n{output_path}")
                    self.status_var.set(f"Last run: {mode} -> {output_path}")
                    return
        except queue.Empty:
            pass
        self.after(100, self._poll_progress, output_path, mode)

    def _finish_run(self):
        self._run_active = False
        self.run_button.config(state="disabled" if self._loading_columns else "normal")
        # Reset rather than leave the bar full: a finished run and a failed
        # one must not look the same, and the next run starts from zero.
        self._progress_reset()

    def _on_close(self):
        """Confirm before quitting mid-run. The worker is a daemon thread,
        so closing the window kills it wherever it happens to be and the
        part-written output is discarded - fine, but the user should know
        the job won't finish rather than assume it did."""
        if self._run_active and not messagebox.askyesno(
            "NPIMasker",
            "A run is still in progress. Quitting now will cancel it and "
            "no output file will be written.\n\nQuit anyway?",
        ):
            return
        self.destroy()

    def _show_run_error(self, exc):
        if isinstance(exc, WrongKeyError):
            messagebox.showerror("NPIMasker", str(exc))
            self.status_var.set("Failed: wrong key or corrupted file.")
        elif isinstance(exc, AlreadyEncryptedError):
            # A wrong-file mistake, not a failure - no log pointer needed.
            messagebox.showerror("NPIMasker", str(exc))
            self.status_var.set("Failed: input is already encrypted.")
        else:
            messagebox.showerror(
                "NPIMasker", f"Failed: {type(exc).__name__}: {exc}{self._log_hint()}"
            )
            self.status_var.set("Failed.")


def main():
    log_path = setup_logging()
    app = App(log_path)
    app.mainloop()


if __name__ == "__main__":
    main()
