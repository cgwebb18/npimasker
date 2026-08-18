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

## Step 5 — Choose the tiebreak column

When rows collide, the tool keeps one of them and drops the rest. It decides like this:

1. If any of the colliding rows has a value in the tiebreak column, keep the **last** of those rows.
2. If none of them has a value there, keep the **last** row of the group.

"Last" means furthest down in your original file.

## Step 6 — Run it

Click **Collapse duplicates**. On a large file this takes a few seconds.

---

## Reading the result

| What it says | What it means |
|---|---|
| **Rows in / Rows removed / Rows out** | The arithmetic. Rows in minus rows removed should equal rows out. |
| **Colliding groups** | How many sets of duplicate rows were found. |
| **Tiebreak overrode order** | Groups where the last row was *not* the one kept, because an earlier row had a tiebreak value. |
| **Groups joined by prefix** | Collisions that only exist because a prefix was ignored. If this looks wrong, the prefix you typed is probably wrong. |
| **Near-miss keys** | Values that would have matched if capitals and spacing were ignored — but they weren't, so these rows were **left alone**. A high number means the source data is inconsistent. |

Below the numbers, the **collision inspector** shows real examples: each group of duplicate rows, which one was kept, and why. Read a few. This is the quickest way to confirm the rule is doing what you expect before you trust the whole file.

Anything the tool thinks is worth a second look appears in a highlighted box above the inspector.

---

## The files you get

| File | Contains | Where it goes |
|---|---|---|
| **Cleaned rows** (`.xlsx` or `.csv`) | Your data with duplicates removed | Stays on your machine |
| **Removed rows** (`.xlsx`) | Every row that was dropped, so you can check them | Stays on your machine |
| **Run summary** (`.txt`) | Counts, column names and the rule that was applied — **no cell values from any row** | Safe to email out |

The summary is the one file that can be shared. Open it in Notepad first and confirm you're happy with what's in it.

Downloading two files one after another makes Chrome ask *"Download multiple files?"* — click **Allow**.

---

## Try it on the sample first

`sample_shape.csv` is 29 rows of made-up data built to exercise every rule. Run it before your real file.

Match on `ref_id`, `site_code`, `service_date`, `category`, `sub_category`. Tiebreak on `status_note`. Prefix `REF NOTE:` on `category`.

You should get:

```
18 rows out          11 rows removed        9 colliding groups
3 tiebreak overrides  3 groups joined by prefix   4 near-miss keys
```

If those numbers match, the tool arrived intact and is working correctly.

---

## If something goes wrong

**The page won't open.** Your IT policy may block local web pages in Chrome. Try Edge.

**"Could not read that file."** Close the file in Excel and try again. Check the first row really is the headings.

**The browser says the page is unresponsive.** Writing a very large `.xlsx` can take 10–20 seconds. Wait, or use the `.csv` download button instead — it's much faster.

**Fewer duplicates removed than expected.** Look at the near-miss count. The tool matches exactly, so inconsistent spacing or capitals in the source data will leave rows uncollapsed. That's the setting behaving as specified, not a fault.

**You want to start over.** Refresh the page (F5) and load the file again. Nothing is saved between runs.
