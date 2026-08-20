/* "Lowest number of a column where values can contain prefixes that must be
   stripped out to compare the number."

   The traps here are real and were measured against the tool's own data:
     INV-000123  ->  -123  if you pull digits out before stripping the prefix
     ""          ->     0  via Number(), which then wins "lowest"
     1.234,56    -> 1.234  via parseFloat, wrong by 1000x
   None of these may reach a comparison.
*/
import test from "node:test";
import assert from "node:assert/strict";
import { loadRules, cellsOf } from "./harness.mjs";

const R = loadRules();
const num = (v, opts) => R.parseNumberWith(String(v), opts || {});

/* ---------- parsing ---------- */

test("a declared prefix is stripped before the number is read", () => {
  assert.equal(num("INV-000123", { prefixes: ["INV-"] }), 123);
});

test("the hyphen in a prefix is not read as a minus sign", () => {
  assert.equal(num("INV-000123", { prefixes: ["INV-"] }), 123,
    "the whole point: -123 here would invert the ordering");
  assert.notEqual(num("INV-000123", { prefixes: ["INV-"] }), -123);
});

test("an empty cell has no number, and is never zero", () => {
  assert.equal(num("", {}), null);
  assert.equal(num("   ", {}), null);
});

test("text with no digits has no number", () => {
  assert.equal(num("N/A", {}), null);
  assert.equal(num("pending", {}), null);
});

test("a plain number parses", () => {
  assert.equal(num("4521", {}), 4521);
  assert.equal(num("-17", {}), -17);
  assert.equal(num("0012.50", {}), 12.5);
});

test("surrounding whitespace is ignored", () => {
  assert.equal(num("  42  ", {}), 42);
});

test("US grouping is honoured when declared", () => {
  assert.equal(num("1,234.56", { decimal: "us" }), 1234.56);
});

test("EU grouping is honoured when declared", () => {
  assert.equal(num("1.234,56", { decimal: "eu" }), 1234.56,
    "parseFloat would have said 1.234");
});

test("the decimal convention is never guessed per value", () => {
  assert.equal(num("1.234", { decimal: "us" }), 1.234);
  assert.equal(num("1.234", { decimal: "eu" }), 1234);
});

test("accounting negatives are opt-in", () => {
  assert.equal(num("(500)", {}), null, "off by default: parentheses are not digits");
  assert.equal(num("(500)", { accounting: true }), -500);
});

test("several prefixes can be declared; the first match wins", () => {
  const o = { prefixes: ["INV-", "REF: "] };
  assert.equal(num("REF: 4521", o), 4521);
  assert.equal(num("INV-88", o), 88);
});

test("prefix matching can ignore case when asked", () => {
  assert.equal(num("inv-77", { prefixes: ["INV-"] }), null);
  assert.equal(num("inv-77", { prefixes: ["INV-"], ci: true }), 77);
});

test("auto mode pulls the first number out without a declared prefix", () => {
  assert.equal(num("#88", { mode: "auto" }), 88);
  assert.equal(num("ID_007", { mode: "auto" }), 7);
});

test("auto mode does not turn a joining hyphen into a minus", () => {
  assert.equal(num("ACC-12-99", { mode: "auto" }), 12,
    "the hyphen follows letters, so it joins rather than negates");
  assert.equal(num("-17", { mode: "auto" }), -17, "but a genuine leading sign survives");
});

test("scientific notation is not silently expanded", () => {
  assert.equal(num("12E3", {}), null,
    "Excel mangles long ids into this shape; treating it as 12000 would be a guess");
});

/* ---------- as a rule ---------- */

const ROWS = [["INV-0300"], ["INV-0025"], ["INV-1000"], [""], ["junk"]];
const cellAt = cellsOf(ROWS);
const mk = o => R.makeNumberRule(cellAt, ROWS.length, 0,
  Object.assign({ prefixes: ["INV-"] }, o));

test("lowest number wins when direction is minimum", () => {
  assert.equal(R.pickWinner([0, 1, 2], [mk({ dir: -1 })]).winner, 1);
});

test("highest number wins when direction is maximum", () => {
  assert.equal(R.pickWinner([0, 1, 2], [mk({ dir: +1 })]).winner, 2);
});

test("rows with no readable number are eliminated, not treated as zero", () => {
  const got = R.pickWinner([0, 1, 3, 4], [mk({ dir: -1 })]);
  assert.equal(got.winner, 1, "INV-0025; the blank and the junk row must not win lowest");
});

test("a group where nothing parses skips the level entirely", () => {
  const got = R.pickWinner([3, 4], [mk({ dir: -1 })]);
  assert.equal(got.trail[0].outcome, "skipped");
  assert.equal(got.winner, 4, "falls through to file order");
});

test("reports its type, column and direction", () => {
  const rule = mk({ dir: -1 });
  assert.equal(rule.type, "number");
  assert.equal(rule.col, 0);
  assert.equal(rule.dir, -1);
});
