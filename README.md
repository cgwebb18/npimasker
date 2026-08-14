# NPIMasker

A small local tool that finds and encrypts sensitive data (name, email, phone,
address, SSN, date of birth, NPI/medical record/insurance ID, etc.) in a CSV
file, and decrypts it back with the same key. Everything runs locally — no
data is sent anywhere.

For free-text columns (e.g. "Notes"), it only encrypts the sensitive part of
the text, not the whole cell — e.g. in `"...his name is Kang Li"`, only
`"Kang Li"` gets encrypted. See "How detection works" below for exactly which
columns get this treatment vs. whole-cell encryption.

## Using the Windows app

1. Get `NPIMasker.exe` (see "Building the .exe" below) and double-click it.
2. Choose **Encrypt** or **Decrypt**.
3. Click **Browse...** and pick your CSV file. The column list shows every
   column with how it will be treated. Click a row (or select it and press
   **Space**) to cycle through the three options:
   - **Skip** — copied through unchanged.
   - **Scan for sensitive text** — only the sensitive parts of the cell are
     encrypted, leaving the rest of the text readable. Use this for
     free-text columns like "Notes".
   - **Encrypt whole cell** — the entire value is encrypted, whatever it
     contains.

   Sensitive-looking columns (name, email, phone, address, etc.) start on a
   sensible default, so you can leave this alone if you want. Two reasons to
   change it:
   - **Certainty.** Scanning is best-effort — it can miss an unusual or
     all-lowercase name. If a free-text column is sensitive throughout (a
     clinical note, say), set it to **Encrypt whole cell** and nothing can
     slip through.
   - **Speed.** Scanning is where nearly all the running time goes. On a
     large file, switching free-text columns to **Encrypt whole cell** turns
     a run that takes many minutes into one that takes seconds.

   In **Decrypt** mode the two encrypted options collapse into a single
   **Decrypt**, because decryption works out for itself how each value was
   encrypted (see below).
4. Set the key:
   - First time: click **Generate & Save Key...** to create a strong random
     key and save it to a `.key` file. **Keep this file safe** — anyone who
     has it (and the encrypted CSV) can decrypt your data, and without it the
     data cannot be recovered by anyone, including you.
   - To decrypt later, or to encrypt more files with the same key: click
     **Load Key from File...** and pick that same `.key` file.
5. Confirm the output path (auto-filled next to the input file) and click
   **Run**.
6. Optionally tick **Verify output** before running. It re-reads the
   finished file and checks every value — see "What NPIMasker does not
   change" below. It's off by default because on a quick run it roughly
   doubles the time; on a slow one (where columns are scanned for
   sensitive text) it costs almost nothing, so it's worth ticking there.
7. A progress bar and a row count show what's happening during the run.
   Large files take a while — see the timings below — and the window stays
   responsive throughout, so you can move it around while it works.
8. Store or send the encrypted CSV and the `.key` file **separately** (e.g.
   don't email them in the same message).

If you decrypt with the wrong key, or a value got corrupted, NPIMasker shows
a clear error instead of silently producing garbage.

If you accidentally point **Encrypt** at a file that has already been
encrypted, NPIMasker stops and tells you, naming the row and column, rather
than encrypting it a second time. Decrypt that file first, or pick a
different input.

## What NPIMasker does not change

Everything other than the values you asked to encrypt comes back exactly as
it went in — same bytes, not merely the same content.

- **The file's encoding is preserved.** A Windows-1252 export comes back as
  Windows-1252; a UTF-16 file comes back as UTF-16. Output used to always be
  UTF-8, which meant accented characters and smart quotes turned to mojibake
  the moment Excel reopened the file.
- **A byte-order mark is neither added nor removed.**
- **Line endings are preserved** — a file with Unix line endings doesn't
  come back with Windows ones, and a file that didn't end with a newline
  doesn't grow one.
- **Quoting and spacing are preserved.** Any row you didn't change is copied
  through verbatim rather than rewritten, so `"1","Zoe"` stays exactly that
  instead of becoming `1,Zoe`.
- **Rows and columns you didn't select are untouched**, including blank
  lines, ragged rows, leading zeros and formula-looking cells.

Two limits worth knowing, both deliberate:

- In a row that *did* change, cells other than the encrypted one may lose
  quotes they didn't strictly need. They always read back as identical
  values; only the punctuation around them can differ.
- Encrypted text is plain ASCII. If *every* accented character in a file
  happens to sit in an encrypted column, the encrypted file no longer
  carries any clue about the original encoding, so decrypting it later
  produces UTF-8. The text is recovered exactly; only the encoding differs.
  Any untouched column containing an accent prevents this.

**Verify output** (the checkbox next to Run) checks all of this on the
finished file before handing it to you: unselected columns unchanged, every
encrypted value decrypting back to exactly what it was, no encrypted value
left behind after a decrypt, and matching row and column counts. If anything
doesn't line up the run fails and no file is written — an existing file from
a previous run is left alone.

## Troubleshooting

Every run writes a log file with timing/progress info and full tracebacks
for any error or crash. If something goes wrong, click **Open Log Folder**
(next to Run) and send us `npimasker.log` from that folder.

The log lives at `%LOCALAPPDATA%\NPIMasker\logs\npimasker.log` on Windows. If
that folder can't be written to, NPIMasker falls back to your temp folder,
and if that fails too it carries on without a log rather than refusing to
start — **Open Log Folder** always tells you which case you're in.

The log records timings, row counts, and the *names* of the columns you
selected. It deliberately does **not** record any cell values, or the folder
your file came from — only the file's name — since a path like
`\\share\patients\Smith_John_1970\` is itself sensitive.

If a run fails or you quit partway through, no output file is written at all:
you'll never be left with a half-encrypted CSV that looks finished. An
existing output file from a previous run is left untouched unless the new run
succeeds.

## Building the app

- **Windows (.exe):**
  - **GitHub Actions (recommended):** push this repo to GitHub. The workflow
    in `.github/workflows/build-exe.yml` builds `NPIMasker.exe` on a Windows
    runner automatically and attaches it as a downloadable artifact on the
    Actions run.
  - **Build it yourself on a Windows PC:** install Python 3.11+, then run
    `build_windows.bat` in this folder. The exe will be in `dist\NPIMasker.exe`.
- **macOS (.app), for testing locally while developing:**
  - Run `./build_macos.sh` in this folder (installs PyInstaller if needed).
    The app will be at `dist/NPIMasker.app` — double-click it, or `open
    dist/NPIMasker.app` from the terminal.
  - The same GitHub Actions workflow also builds `NPIMasker-macos` on a
    `macos-latest` runner and uploads it as an artifact on every push, so you
    don't have to build locally if you don't want to.

Both builds bundle spaCy and its `en_core_web_sm` model for embedded-name
detection, which noticeably increases build time and app size (packaged app
is roughly 150-250MB) compared to a build without NLP.

## Running from source (any OS, for development)

Requires **Python 3.10+** (spaCy's dependencies require it).

```
pip install -r requirements.txt
python main.py
```

**macOS note:** Apple's built-in `python3` (`/usr/bin/python3`) links against
the system Tcl/Tk 8.5, which is deprecated and known to render a **blank
window** on recent macOS versions. If you see a blank window or a
`DEPRECATION WARNING` about system Tk, install a Python build with a modern
Tk instead:

```
brew install python@3.12 python-tk@3.12
/opt/homebrew/bin/python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python main.py
```

`build_macos.sh` already does this automatically (it creates its own `.venv`
using Homebrew's `python3.12`), so packaged `.app` builds aren't affected —
this only matters when running `main.py` directly with `python3`.

## Running the tests

```
pip install -r requirements.txt pytest
pytest tests/
```

## How detection works

When **encrypting**, each selected column is treated according to what you
picked in the column list. The defaults come from the column header:

- **Whole-cell columns** — headers matching Name, Phone, Address/Street/
  City/State/Zip, or NPI/Medical record/MRN/Insurance/Policy number are
  encrypted as a whole cell, like before. These categories either have no
  reliable text pattern to search for (phone/address formats vary too much,
  medical/insurance IDs have no fixed format) or benefit from a guarantee
  that the whole value is always protected regardless of what it contains.
- **Scanned columns** — every other selected column (Email/SSN/DOB columns,
  and any free-text column like Notes/Comments) is scanned for PII *within*
  the text, and only the detected substrings are encrypted:
  - Emails, SSNs, and dates (covers DOB) are found with regular expressions.
  - Person names are found anywhere in the text using
    [spaCy](https://spacy.io/)'s named-entity recognition
    (`en_core_web_sm`) — this is what catches a name embedded in a sentence
    like `"...his name is Kang Li"`.
  - Organization names are encrypted too, deliberately: the NER model often
    mislabels unusual person names as organizations (e.g. "Lilly Petlock"),
    and leaking a name is worse than over-encrypting the name of a hospital
    or insurer (which is often itself identifying). Detected name spans are
    also extended over an immediately following attached word the model left
    out (catches "petlock" when only "Lilly" was tagged).
  - This is best-effort, not a guarantee: an all-lowercase name (e.g.
    "lilly petlock") can still be missed entirely, and there's no attempt to
    detect embedded street addresses or phone numbers in free text (put
    those in dedicated, whole-cell columns instead if you need them
    protected reliably).

### File encodings

NPIMasker works out a file's encoding before reading it, checking for a
byte-order mark first (UTF-8, UTF-16 and UTF-32, either byte order), then
falling back to UTF-8, Windows-1252 and Latin-1 in that order.

UTF-16 matters more than it sounds: files big enough to be awkward usually
don't come from Excel, which stops at about a million rows — they come from
PowerShell, where `Out-File` and `>` write UTF-16 by default. Such a file
used to be misread as Windows-1252, which made every column name after the
first show up **blank** in the column list, and produced a corrupted output
file without reporting anything wrong.

If a file contains bytes that can't be text in any encoding NPIMasker
supports, it says so and stops rather than guessing.

### Decrypting

When **decrypting**, the header is not consulted at all: each cell says what
it is. A cell holding `[[ENC:...]]` markers has those markers swapped back
for plaintext; a cell that is entirely one encrypted value is decrypted
whole; anything else was never encrypted and is passed through untouched.

This is why you don't have to remember what you chose when you encrypted, and
why renaming a column between encrypting and decrypting is harmless. (It used
to be actively dangerous: decryption made the same header-based guess
independently, and if the two disagreed it could hand back a file that still
held encrypted values without reporting anything wrong.)

A value that *starts* like an encrypted value but has been damaged — a
spreadsheet clipping a long field, say — is reported as an error rather than
passed through, so a corrupted file can't quietly look like a successful
decryption.

## How the encryption works

- Each detected piece of sensitive text (a whole cell, or a substring found
  by the scanner above) is encrypted independently with
  [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128 + HMAC), so
  identical values produce different ciphertext each time.
- In scanned columns, an encrypted substring is replaced in place with a
  `[[ENC:<token>]]` marker; decrypting finds these markers and swaps back in
  the original plaintext, leaving the rest of the cell's text untouched.
- The key you provide (or generate) is run through PBKDF2-HMAC-SHA256 with a
  fixed, application-level salt to derive the actual encryption key. This is
  a deliberate simplicity trade-off for a local, single-user tool: it means
  a given key string always derives the same encryption key without needing
  to manage a separate salt file. If you need protection against attackers
  who might precompute keys for this fixed salt, don't reuse a weak/guessable
  key — use **Generate & Save Key** rather than typing your own passphrase.
- Only the columns you select are touched; everything else in the CSV is
  copied through unchanged.
