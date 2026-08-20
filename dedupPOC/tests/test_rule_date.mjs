/* "Choose the oldest of the duplicates ... detect date format to do comparison."
 *
 * Direction is explicit rather than named "oldest", because that word and
 * "maximum date" point at opposite rows. Default is LATEST.
 *
 * Measured against the tool's own read path: because it reads with raw:false,
 * one underlying value (serial 46085) reaches ROWS as "2026-03-04",
 * "03/04/2026", "04/03/2026" or "46085" depending purely on the cell's number
 * format. new Date() gets two of those four wrong -- silently -- so format has
 * to be settled per column, from evidence, before anything is compared.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadRules, cellsOf } from "./harness.mjs";

const R = loadRules();
const D = (y, m, d) => Date.UTC(y, m - 1, d);

/* ---------- parsing a known format ---------- */

test("ISO dates parse to UTC midnight", () => {
  assert.equal(R.parseDateWith("2026-03-04", "iso"), D(2026, 3, 4));
});

test("parsing is timezone-independent", () => {
  // Date.UTC is the definition; a local-time parse would drift by the offset
  // and reorder rows for anyone west of Greenwich.
  assert.equal(R.parseDateWith("2026-03-04", "iso") % 86400000, 0,
    "lands exactly on a UTC day boundary");
});

test("a time component is accepted and ordered within the day", () => {
  const morning = R.parseDateWith("2026-03-04 09:30", "iso");
  const evening = R.parseDateWith("2026-03-04T18:45:00", "iso");
  assert.ok(evening > morning);
  assert.equal(morning - D(2026, 3, 4), 9.5 * 3600000);
});

test("day-first and month-first read the same text differently", () => {
  assert.equal(R.parseDateWith("04/03/2026", "dmy"), D(2026, 3, 4));
  assert.equal(R.parseDateWith("04/03/2026", "mdy"), D(2026, 4, 3));
});

test("dots and dashes work as separators too", () => {
  assert.equal(R.parseDateWith("04.03.2026", "dmy"), D(2026, 3, 4));
  assert.equal(R.parseDateWith("04-03-2026", "dmy"), D(2026, 3, 4));
});

test("impossible dates are rejected rather than rolled over", () => {
  assert.equal(R.parseDateWith("31/02/2026", "dmy"), null,
    "Date.UTC would silently make this 3 March");
  assert.equal(R.parseDateWith("2026-02-31", "iso"), null);
  assert.equal(R.parseDateWith("2026-13-01", "iso"), null);
});

test("two-digit years use the standard 69/70 pivot", () => {
  assert.equal(R.parseDateWith("04/03/26", "dmy"), D(2026, 3, 4));
  assert.equal(R.parseDateWith("04/03/98", "dmy"), D(1998, 3, 4));
});

test("month-name forms parse", () => {
  assert.equal(R.parseDateWith("4-Mar-2026", "mon"), D(2026, 3, 4));
  assert.equal(R.parseDateWith("4 March 2026", "mon"), D(2026, 3, 4));
});

test("Excel serial numbers parse only when that format is chosen", () => {
  assert.equal(R.parseDateWith("46085", "serial"), D(2026, 3, 4));
  assert.equal(R.parseDateWith("46085", "iso"), null);
});

test("junk yields nothing at all", () => {
  assert.equal(R.parseDateWith("", "iso"), null);
  assert.equal(R.parseDateWith("not a date", "dmy"), null);
});

/* ---------- detecting the format from a column ---------- */

const detect = vals => R.detectDateFormat(vals);

test("an ISO column is recognised outright", () => {
  const d = detect(["2026-03-04", "2025-11-27", "2024-01-01"]);
  assert.equal(d.status, "ok");
  assert.equal(d.format, "iso");
});

test("a day above 12 anywhere proves the column is day-first", () => {
  const d = detect(["04/03/2026", "27/11/2026", "05/06/2026"]);
  assert.equal(d.status, "ok");
  assert.equal(d.format, "dmy");
});

test("a month-slot above 12 anywhere proves it is month-first", () => {
  const d = detect(["03/04/2026", "11/27/2026"]);
  assert.equal(d.status, "ok");
  assert.equal(d.format, "mdy");
});

test("a column with no disambiguating value is reported as ambiguous", () => {
  const d = detect(["04/03/2026", "05/06/2026", "01/02/2026"]);
  assert.equal(d.status, "ambiguous");
  assert.deepEqual(d.candidates, ["dmy", "mdy"]);
  assert.equal(d.format, null, "the caller must ask; guessing a locale is not allowed");
  assert.ok(d.sample, "a real value to show the user when asking");
});

test("evidence for both orders at once is a contradiction, not a coin toss", () => {
  const d = detect(["27/11/2026", "11/27/2026"]);
  assert.equal(d.status, "contradictory");
  assert.equal(d.format, null);
});

test("an all-integer column offers Excel serial without selecting it", () => {
  const d = detect(["46085", "46353", "45000"]);
  assert.equal(d.status, "ambiguous");
  assert.ok(d.candidates.includes("serial"));
  assert.equal(d.format, null, "these are indistinguishable from ordinary numbers");
});

test("a column with no dates in it at all says so", () => {
  const d = detect(["apple", "pear", ""]);
  assert.equal(d.status, "none");
  assert.equal(d.format, null);
});

test("blank cells are ignored by detection", () => {
  const d = detect(["2026-03-04", "", "   ", "2025-11-27"]);
  assert.equal(d.status, "ok");
  assert.equal(d.format, "iso");
  assert.equal(d.total, 2, "only non-empty values are evidence");
});

test("detection counts what it could not read", () => {
  const d = detect(["2026-03-04", "2025-11-27", "whenever"]);
  assert.equal(d.format, "iso");
  assert.equal(d.unparsed, 1);
});

/* ---------- as a rule ---------- */

const ROWS = [["2026-03-04"], ["2026-11-27"], ["2025-01-15"], [""], ["junk"]];
const cellAt = cellsOf(ROWS);
const mk = o => R.makeDateRule(cellAt, ROWS.length, 0, Object.assign({ format: "iso" }, o));

test("the latest date wins by default", () => {
  const rule = mk({});
  assert.equal(rule.dir, +1, "default direction is latest");
  assert.equal(R.pickWinner([0, 1, 2], [rule]).winner, 1, "2026-11-27");
});

test("direction can be flipped to keep the earliest", () => {
  assert.equal(R.pickWinner([0, 1, 2], [mk({ dir: -1 })]).winner, 2, "2025-01-15");
});

test("rows with no readable date are eliminated when others have one", () => {
  const got = R.pickWinner([0, 3, 4], [mk({})]);
  assert.equal(got.winner, 0);
});

test("a group with no readable dates skips the level", () => {
  const got = R.pickWinner([3, 4], [mk({})]);
  assert.equal(got.trail[0].outcome, "skipped");
  assert.equal(got.winner, 4);
});

test("reports its type, column and unreadable count", () => {
  const rule = mk({});
  assert.equal(rule.type, "date");
  assert.equal(rule.col, 0);
  assert.equal(rule.unreadable, 2, "the blank and the junk");
});
