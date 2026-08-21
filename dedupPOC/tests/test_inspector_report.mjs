/* The downloadable collision inspector.
 *
 * Same information the panel shows, for every colliding group rather than the
 * first thirty, as plain text a person can read in Notepad. Unlike the run
 * summary this holds real cell values, so it is labelled accordingly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadReport } from "./harness.mjs";

const R = loadReport();
const NUL = String.fromCharCode(0);

const HEADERS = ["ref_id", "site", "service_date", "invoice_no"];
const ROWS = [
  ["A-1", "S1", "2026-01-10", "INV-100"],
  ["A-1", "S1", "2026-05-20", "INV-900"],
  ["A-1", "S1", "2026-03-15", "INV-050"],
];
const cellAt = (i, c) => ROWS[i][c];

const GROUP = {
  k: "A-1" + NUL + "S1" + NUL,
  idxs: [0, 1, 2],
  winner: 1,
  reason: "Kept the row with the newest service_date.",
  decidedBy: 0,
  pfx: [false, false, false],
  shown: [["2026-01-10", "100"], ["2026-05-20", "900"], ["2026-03-15", "50"]],
};
const CTX = {
  headers: HEADERS, keys: [0, 1], cellAt,
  chain: ["keep the newest service_date", "keep the lowest invoice_no"],
  chainCol: [2, 3],
  anyPfx: false,
};

const lines = (g, n) => R.collisionLines(g, n === undefined ? 1 : n, CTX);
const text = (g, n) => lines(g, n).join("\n");

test("a group is headed by its number and its matched values", () => {
  const t = text(GROUP);
  assert.match(t, /GROUP 1\b/);
  assert.match(t, /ref_id = A-1/);
  assert.match(t, /site = S1/);
});

test("the kept row is marked and the removed ones are not", () => {
  const l = lines(GROUP);
  const kept = l.filter(x => /\bKEPT\b/.test(x));
  const gone = l.filter(x => /\bremoved\b/.test(x));
  assert.equal(kept.length, 1);
  assert.equal(gone.length, 2);
  assert.match(kept[0], /row 3/, "row 1 of the file is the header, so index 1 is row 3");
});

test("row numbers match the spreadsheet, not the array", () => {
  const t = text(GROUP);
  for (const n of ["row 2", "row 3", "row 4"]) assert.ok(t.includes(n), n);
});

test("each criterion's value is shown, numbered as in the chain", () => {
  const t = text(GROUP);
  assert.match(t, /1\. 2026-05-20/);
  assert.match(t, /2\. 900/);
});

test("a criterion with no usable value says so rather than showing blank", () => {
  const g = Object.assign({}, GROUP, { shown: [[null, "100"], ["2026-05-20", "900"], ["2026-03-15", "50"]] });
  assert.match(text(g), /no value/);
});

test("the raw cell is shown when it differs from the compared value", () => {
  const g = Object.assign({}, GROUP, { shown: [["100", null], ["900", null], ["50", null]] });
  const ctx = Object.assign({}, CTX, { chain: ["keep the lowest invoice_no"], chainCol: [3] });
  const t = R.collisionLines(g, 1, ctx).join("\n");
  assert.match(t, /100 \(INV-100\)/, "so a stripped prefix is visible");
});

test("the reason closes the group, after every row", () => {
  const l = lines(GROUP).filter(x => x.trim().length && !/^-+$/.test(x));
  assert.match(l[l.length - 1], /newest service_date/);
  const lastRow = l.map(x => /\brow \d+/.test(x)).lastIndexOf(true);
  const reasonAt = l.map(x => /newest service_date/.test(x)).lastIndexOf(true);
  assert.ok(reasonAt > lastRow, "the explanation comes after the rows it explains");
});

test("a row whose key had a prefix cut is marked", () => {
  const g = Object.assign({}, GROUP, { pfx: [true, false, false] });
  assert.match(text(g), /prefix cut/);
});

test("an empty matched value reads as empty rather than vanishing", () => {
  const g = Object.assign({}, GROUP, { k: "A-1" + NUL + NUL });
  assert.match(text(g), /site = \(empty\)/);
});

test("group numbering follows the position it is given", () => {
  assert.match(text(GROUP, 812), /GROUP 812\b/);
});

/* ---------- the file's own header ---------- */

test("the header states the rule chain and the fallback", () => {
  const h = R.reportHeader({
    name: "export", when: "2026-08-21T00:00:00.000Z",
    stats: { rowsIn: 3, removed: 2, rowsOut: 1, dupGroups: 1 },
    chainAll: ["keep the newest service_date"],
    keys: [0, 1], headers: HEADERS,
  }).join("\n");
  assert.match(h, /keep the newest service_date/);
  assert.match(h, /nearest the top/i, "the fallback must be stated, as it is in the UI");
});

test("the header warns that this file holds cell values", () => {
  const h = R.reportHeader({
    name: "export", when: "2026-08-21T00:00:00.000Z",
    stats: { rowsIn: 3, removed: 2, rowsOut: 1, dupGroups: 1 },
    chainAll: [], keys: [0], headers: HEADERS,
  }).join("\n");
  assert.match(h, /cell values/i,
    "unlike the run summary, this one is not safe to send on");
});

test("the header carries the counts the result panel shows", () => {
  const h = R.reportHeader({
    name: "export", when: "2026-08-21T00:00:00.000Z",
    stats: { rowsIn: 30, removed: 11, rowsOut: 19, dupGroups: 9 },
    chainAll: [], keys: [0], headers: HEADERS,
  }).join("\n");
  for (const n of ["30", "11", "19", "9"]) assert.ok(h.includes(n), n);
});
