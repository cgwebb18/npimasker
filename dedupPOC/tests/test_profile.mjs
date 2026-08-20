/* "What is in each column?" -- the summary that guides the column pick.
   Ported from Version_08_19, with one change: it counted date-ish values by
   parsing them as MDY, which is a guess. Shape is counted here instead, so the
   summary never implies an order the tool itself refuses to assume. */
import test from "node:test";
import assert from "node:assert/strict";
import { loadProfile } from "./harness.mjs";
import { cellsOf } from "./harness.mjs";

const P = loadProfile();
const ROWS = [
  ["A", "1",  "2026-03-04", "", "same"],
  ["B", "2",  "2026-11-27", "", "same"],
  ["C", "x",  "04/03/2026", "", "same"],
  ["D", "",   "",           "", "same"],
];
const prof = c => P.profileColumn(cellsOf(ROWS), ROWS.length, c);

test("counts filled, blank and distinct values", () => {
  const p = prof(1);
  assert.equal(p.filled, 3);
  assert.equal(p.blank, 1);
  assert.equal(p.distinct, 3);
});

test("an entirely empty column is reported as such", () => {
  const p = prof(3);
  assert.equal(p.filled, 0);
  assert.equal(P.profileFlag(p, ROWS.length).text, "entirely empty");
});

test("a column with one value throughout is flagged", () => {
  const p = prof(4);
  assert.equal(p.distinct, 1);
  assert.equal(P.profileFlag(p, ROWS.length).text, "one value throughout");
});

test("a column unique on every row is flagged", () => {
  const p = prof(0);
  assert.equal(P.profileFlag(p, ROWS.length).text, "unique on every row");
});

test("shape words describe what is actually in the column", () => {
  assert.equal(P.shapeWord(prof(2)), "all dates");
  assert.equal(P.shapeWord(prof(4)), "text");
  assert.match(P.shapeWord(prof(1)), /numeric/);
});

test("a fully numeric column says so", () => {
  const rows = [["1"], ["2"], ["30"]];
  assert.equal(P.shapeWord(P.profileColumn(cellsOf(rows), 3, 0)), "all numbers");
});

test("date shape is counted without assuming day-first or month-first", () => {
  // 04/03/2026 is date-shaped whichever way it is read; the summary must not
  // silently pick one to decide that.
  const rows = [["04/03/2026"], ["05/06/2026"]];
  const p = P.profileColumn(cellsOf(rows), 2, 0);
  assert.equal(p.dateish, 2);
  assert.equal(P.shapeWord(p), "all dates");
});

test("counting stops at a cap on very wide data, and says it did", () => {
  const n = 5;
  const rows = Array.from({ length: n }, (_, i) => ["v" + i]);
  const p = P.profileColumn(cellsOf(rows), n, 0, 3);
  assert.ok(p.capped, "distinct counting was capped");
  assert.ok(p.distinct <= 3);
});

test("a flagged column is not an error, just a warning", () => {
  assert.equal(P.profileFlag(prof(0), ROWS.length).level, "warn");
  assert.equal(P.profileFlag(prof(3), ROWS.length).level, "no");
  assert.equal(P.profileFlag(prof(1), ROWS.length).level, "");
});
