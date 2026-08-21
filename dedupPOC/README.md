# Exact-match row collapser — how to use it

A single web page that removes duplicate rows from a spreadsheet.

**Your file never leaves your computer.** The page has no internet connection and sends nothing anywhere. You can unplug the network cable and it still works. Everything happens inside the browser tab, and closing the tab erases it.

---

## Before you start

You need two things in the same folder:

- `collapse-duplicates.html` — the tool
- your data file — `.xlsx`, `.xlsm`, or `.csv`

Your file must have **column headings in the first row** and **one sheet** of data. Close it in Excel before you begin, or the tool may not be able to read it.

---

## Step 1 — Open the tool

Double-click `collapse-duplicates.html`. It opens in Edge or Chrome like a normal web page.

If nothing happens, right-click it → **Open with** → **Microsoft Edge**.

## Step 2 — Load your file

Drag your spreadsheet onto the box at the top, or click the box and browse to it.

The tool confirms how many rows and columns it found. **Check that row count against your file.** If it doesn't match, stop — something is wrong with the file, not with the tool.

## Step 3 — Choose the match columns

Click the columns that decide whether two rows are duplicates. Rows count as duplicates only when **every** one of those columns is identical.

Identical means genuinely identical — capital letters and spaces count. `Smith` and `smith` are two different values. `Smith ` with a space on the end is a third.

## Step 4 — Fill in any prefixes to ignore

If a column's values sometimes start with a fixed prefix that shouldn't count, type that prefix into the box next to that column.

For example, with `This is my Prefix:` typed in, these two are treated as the same value:

```
This is my Prefix: All Prefix need to be ignored
All Prefix need to be ignored
```

Type the prefix exactly as it appears in the data. Leave the box empty for columns with no prefix.

The prefix is only ignored **when comparing**. It is never deleted from your data — if the row that survives happens to carry the prefix, it keeps it.

## Pick the dataset

The picker at the top of step 02 starts you from a known setup rather than a blank page. **Casenotes**, **Assessments**, **HMIS Services** and **HRM Services** are built in; anything you save joins the list underneath them.

A built-in preset cannot know your column names for certain, so some leave a column for you to choose. When one does, the tool says which and will not run until you have picked it. That is deliberate — it is the difference between "waiting for you" and "quietly using the wrong column".

If a preset names a column your file does not have at all, the tool says so by name and switches that criterion **off**. It never attaches a criterion to a column it merely resembles.

---

## Saving a setup so you only do it once

Once the match columns and the criteria are right, click **Save these settings…** and give them a name.

Two things happen. The settings go into **Pick the dataset** at the top, so next time you open the tool they are already in the list — nothing to load. And a `.json` file is downloaded, which is the copy you can keep, email, or drop on a shared drive.

On another machine, click **Load from a file…** and choose that `.json`. It joins the list there too.

Settings are stored by **column name**, not by position, so they still work when next month's export has the columns in a different order. If a column is missing entirely the tool says so by name and switches the affected criterion off, rather than quietly attaching it to the wrong column.

Two things worth knowing:

- The in-browser list lives in that browser on that machine. Clearing your browsing data clears it. The `.json` file is the durable copy — keep it.
- The tool cannot read a shared folder by itself; a page opened from a file has no way to list one. The `.json` file is how a setup travels between people.

---

## Step 5 — Set the survivor rules

When rows collide, the tool keeps one of them and drops the rest. You decide which, by building a list of rules.

The rules run **in order**. The first rule looks at every row in the group and keeps only the best ones. If that leaves a single row, it wins. If it leaves several tied, the second rule looks at just those, and so on. If the rules run out and rows are still tied, the row **nearest the top of the file** wins.

That last line never changes and cannot be removed. It is what guarantees the tool always picks exactly one row.

### The kinds of rule

| Rule | What it does |
|---|---|
| **Carries a value** | A row with something in the chosen column beats a row without. |
| **Earliest / latest date** | Compares dates in the chosen column. |
| **Lowest / highest number** | Compares numbers in the chosen column, ignoring any prefix you name. |
| **Most values filled** | Counts how many of several columns a row actually fills, and keeps the fullest. |

Use **Add a rule** to add a level, the arrows to reorder, and **×** to remove. Underneath, the tool restates your whole chain as a sentence. Read it. It is the fastest way to catch a rule in the wrong order.

### About dates

The tool works out the date format by looking at the column. If it finds a day above 12 it knows the format is day-first; a month slot above 12 means month-first.

If nothing in the column settles it — every value could be read either way, like `04/03/2026` — the tool **stops and asks**. It will not guess. Picking wrong would silently keep the wrong rows, and nothing in the output would look unusual.

A column of plain numbers like `46085` may be Excel dates that lost their formatting. The tool offers **Excel serial number** but never chooses it for you, because those are indistinguishable from ordinary numbers.

### About numbers with prefixes

Type the prefix into the rule's **Ignore prefix** box, exactly as it appears. `INV-000123` with `INV-` ignored compares as **123**.

Type it in even if it looks obvious. Without it the tool has to guess where the number starts, and `INV-000123` reads as **minus** 123 — which would win "lowest" every time.

Cells the rule cannot read as a number are passed over, not counted as zero. An empty cell never wins "lowest".

## Step 6 — Run it

Click **Collapse duplicates**. On a large file this takes a few seconds.

---

## Reading the result

| What it says | What it means |
|---|---|
| **Rows in / Rows removed / Rows out** | The arithmetic. Rows in minus rows removed should equal rows out. |
| **Colliding groups** | How many sets of duplicate rows were found. |
| **Rules overrode order** | Groups where the top row was *not* the one kept, because a rule chose a later one. |
| **Groups joined by prefix** | Collisions that only exist because a prefix was ignored. If this looks wrong, the prefix you typed is probably wrong. |
| **Near-miss keys** | Values that would have matched if capitals and spacing were ignored — but they weren't, so these rows were **left alone**. A high number means the source data is inconsistent. |

Under the numbers, a line shows **which rule decided each collision** — how many groups each level settled, and how many fell all the way through to file order. If a level decided nothing, it is doing no work and can probably come out.

Below that, the **collision inspector** shows real examples: each group of duplicate rows, which one was kept, and why. Read a few. This is the quickest way to confirm the rule is doing what you expect before you trust the whole file.

Anything the tool thinks is worth a second look appears in a highlighted box above the inspector.

---

## The files you get

| File | Contains | Where it goes |
|---|---|---|
| **Cleaned rows** (`.xlsx` or `.csv`) | Your data with duplicates removed | Stays on your machine |
| **Removed rows** (`.xlsx` or `.csv`) | Every row that was dropped, so you can check them | Stays on your machine |
| **Run summary** (`.txt`) | Counts, column names and the rule that was applied — **no cell values from any row** | Safe to email out |
| **Collision inspector** (`.txt`) | Every colliding group, which row was kept and why, and the values each criterion compared — **holds real cell values** | Stays on your machine |

The summary is the one file that can be shared. Open it in Notepad first and confirm you're happy with what's in it.

Downloading two files one after another makes Chrome ask *"Download multiple files?"* — click **Allow**.

---

## Try it on the sample first

`sample_shape.csv` is 29 rows of made-up data built to exercise every rule. Run it before your real file.

Match on `ref_id`, `site_code`, `service_date`, `category`, `sub_category`. Tiebreak on `status_note`. Prefix `REF NOTE:` on `category`.

You should get:

```
18 rows out          11 rows removed        9 colliding groups
2 rules overrode order  3 groups joined by prefix   4 near-miss keys
```

If those numbers match, the tool arrived intact and is working correctly.

### Then try the rules

`sample_rules.csv` is 15 rows built so every kind of rule gets used, and one group defeats all of them.

Match on `ref_id` and `site_code`. Then build three rules, in this order:

1. **Latest** date on `service_date`
2. **Lowest** number on `invoice_no`, ignoring prefix `INV-`
3. **Most values filled** across `phone`, `email` and `address`

You should get:

```
15 rows in           7 rows removed          8 rows out
5 colliding groups   1 unreadable date cell
```

and the decided-by line should read:

```
rule 1 -> 2 groups    rule 2 -> 1 group    rule 3 -> 1 group    file order -> 1 group
```

That spread is the point. Every level does real work, and one group ties all the way down to the fallback. If the counts match but the spread does not, your rules are in the wrong order.

---

## If something goes wrong

**The page won't open.** Your IT policy may block local web pages in Chrome. Try Edge.

**"Could not read that file."** Close the file in Excel and try again. Check the first row really is the headings.

**Accented names look wrong.** The tool works out the encoding from the file itself and tells you which one it used, next to the row count. Excel's plain **CSV (Comma delimited)** is not UTF-8 — it is Windows-1252 — and the tool reads it correctly either way. If a name still looks wrong, re-save the source as **CSV UTF-8** and run it again.

**The browser says the page is unresponsive.** Writing a very large `.xlsx` can take 10–20 seconds. Wait, or use the `.csv` download button instead — it's much faster.

**A download says the file is too large for `.xlsx`.** There is a hard ceiling on how much a browser can write into one `.xlsx`. Use the `.csv` button next to it, which handles far more and is much faster. Both hold the same rows.

**Fewer duplicates removed than expected.** Look at the near-miss count. The tool matches exactly, so inconsistent spacing or capitals in the source data will leave rows uncollapsed. That's the setting behaving as specified, not a fault.

**You want to start over.** Refresh the page (F5) and load the file again. Nothing is saved between runs.
