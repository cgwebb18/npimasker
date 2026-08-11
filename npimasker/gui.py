"""Tkinter GUI for NPIMasker."""

import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from npimasker import __version__
from npimasker.crypto import WrongKeyError, derive_key, generate_passphrase
from npimasker.csv_processor import process_csv, read_headers
from npimasker.logging_setup import setup_logging
from npimasker.sensitive_fields import detect_sensitive_columns

logger = logging.getLogger(__name__)


class App(tk.Tk):
    def __init__(self, log_path):
        super().__init__()
        self.log_path = log_path
        self.title(f"NPIMasker v{__version__}")
        self.geometry("560x520")
        self.minsize(480, 440)

        self.mode = tk.StringVar(value="encrypt")
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.headers: list[str] = []
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
            text="Columns to scan for sensitive data (sensitive-looking ones are pre-selected):",
        ).pack(anchor="w")
        list_row = ttk.Frame(cols_frame)
        list_row.pack(fill="both", expand=True)
        self.columns_list = tk.Listbox(list_row, selectmode=tk.MULTIPLE, exportselection=False)
        self.columns_list.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_row, orient="vertical", command=self.columns_list.yview)
        scrollbar.pack(side="left", fill="y")
        self.columns_list.config(yscrollcommand=scrollbar.set)

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
        self.run_button = ttk.Button(run_frame, text="Run", command=self._run)
        self.run_button.pack(side="right")

        self.status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status_var, foreground="gray").pack(
            fill="x", padx=10, pady=(0, 10)
        )

    # -- Actions -----------------------------------------------------------

    def _on_mode_change(self):
        self._suggest_output_path()

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

    def _populate_columns(self, headers: list[str]):
        self.headers = headers
        self.columns_list.delete(0, tk.END)
        sensitive = set(detect_sensitive_columns(self.headers))
        for i, header in enumerate(self.headers):
            self.columns_list.insert(tk.END, header)
            if i in sensitive:
                self.columns_list.selection_set(i)

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
        selected = list(self.columns_list.curselection())
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
                "NPIMasker", "No columns are selected, so nothing will be changed. Continue anyway?"
            ):
                return

        key = derive_key(passphrase)
        self._progress_queue = queue.Queue()
        self._run_active = True
        self.run_button.config(state="disabled")
        self.status_var.set("Running...")

        thread = threading.Thread(
            target=self._process_worker,
            args=(input_path, output_path, key, mode, selected),
            daemon=True,
        )
        thread.start()
        self.after(100, self._poll_progress, output_path, mode)

    def _process_worker(self, input_path, output_path, key, mode, selected):
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
                progress_callback=lambda row: self._progress_queue.put(("progress", row)),
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
                    self.status_var.set(f"Processing... {payload:,} rows")
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
