/* The merged rule vocabulary.
 *
 * Version_08_19's wording wins wherever the two versions disagreed, because
 * that is what its documentation and its saved settings say: `type:"minmax"`
 * with a separate `parse`, `dir:"min"|"max"`, and `field`/`fields` rather than
 * `col`/`cols`. Our engine and our parsers are unchanged underneath.
 *
 * Two of its ideas fold in as new capability: comparing text, and counting
 * fields that are above zero rather than merely filled. Two more are per-rule
 * switches: empty-counts-as-zero, and switching a criterion off without
 * deleting it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadRules, cellsOf } from "./harness.mjs";

const R = loadRules();

const HEAD = ["id", "when", "amount", "note", "a", "b", "c"];
const ROWS = [
  //  id     when          amount      note      a     b     c
  ["1", "2026-03-04", "INV-0300", "beta",  "0",  "5",  ""   ],
  ["2", "2026-05-20", "INV-0025", "alpha", "3",  "0",  "7"  ],
  ["3", "2026-01-15", "",         "gamma", "",   "2",  "9"  ],
];
const cellAt = cellsOf(ROWS);
const build = cfgs => R.buildRules(cfgs, cellAt, ROWS.length, true);
const win = cfgs => R.pickWinner([0, 1, 2], build(cfgs)).winner;

/* ---------- minmax over the three parsers ---------- */

test("minmax/date reads the date column", () => {
  assert.equal(win([{ type:"minmax", parse:"date", dir:"max", field:1, fmt:"ISO" }]), 1);
  assert.equal(win([{ type:"minmax", parse:"date", dir:"min", field:1, fmt:"ISO" }]), 2);
});

test("minmax/number reads past a named prefix", () => {
  assert.equal(win([{ type:"minmax", parse:"number", dir:"min", field:2,
                      strip:"prefix", pfx:"INV-" }]), 1, "INV-0025");
});

test("minmax/text compares the value as written", () => {
  assert.equal(win([{ type:"minmax", parse:"text", dir:"min", field:3 }]), 1, "alpha");
  assert.equal(win([{ type:"minmax", parse:"text", dir:"max", field:3 }]), 2, "gamma");
});

test("text comparison treats an empty cell as no value, not as the lowest", () => {
  assert.equal(win([{ type:"minmax", parse:"text", dir:"min", field:2 }]), 1,
    "row 3's amount is empty, so it is not a candidate at all");
});

test("dir accepts min and max as words, the way saved settings read", () => {
  const [r] = build([{ type:"minmax", parse:"number", dir:"min", field:2, strip:"prefix", pfx:"INV-" }]);
  assert.equal(r.dir, -1, "normalised for the engine, but written as a word");
});

/* ---------- reading past a prefix by digits ---------- */

test("strip:digits jumps to the first digit without naming the prefix", () => {
  assert.equal(win([{ type:"minmax", parse:"number", dir:"min", field:2, strip:"digits" }]), 1,
    "0025 < 0300, and neither prefix had to be typed in");
});

test("strip:digits cannot produce a negative, whatever the prefix looks like", () => {
  // Reading from the first digit onward means a prefix hyphen is never in
  // scope, which is the whole point: pulling the first numeric run out of
  // "INV-000123" instead would yield -123 and win "lowest" every time.
  const rows = [["INV-0300"], ["ACC-000123"]];
  const [r] = R.buildRules([{ type:"minmax", parse:"number", dir:"min", field:0, strip:"digits" }],
                           cellsOf(rows), 2, true);
  assert.equal(r.score(0), 300);
  assert.equal(r.score(1), 123);
  assert.ok(r.score(1) > 0);
});

test("strip:digits refuses a value with more digits after a separator", () => {
  // "ACC-12-99" leaves "12-99", which is not a number. Guessing which of the
  // two the user meant is exactly the kind of guess this tool does not make.
  const [r] = R.buildRules([{ type:"minmax", parse:"number", dir:"min", field:0, strip:"digits" }],
                           cellsOf([["ACC-12-99"]]), 1, true);
  assert.equal(r.score(0), null);
});

/* ---------- empty counts as zero ---------- */

test("zero:true makes an empty cell score 0 instead of dropping out", () => {
  const cfg = { type:"minmax", parse:"number", dir:"min", field:2, strip:"prefix", pfx:"INV-" };
  assert.equal(win([cfg]), 1, "without zero, the empty amount is not a candidate");
  assert.equal(win([Object.assign({}, cfg, { zero:true })]), 2,
    "with zero, row 3's empty amount is the lowest");
});

test("zero:true does not turn unreadable text into 0", () => {
  const rows = [["12"], ["nonsense"], [""]];
  const [r] = R.buildRules([{ type:"minmax", parse:"number", dir:"min", field:0, zero:true }],
                           cellsOf(rows), 3, true);
  assert.equal(r.score(0), 12);
  assert.equal(r.score(1), null, "text is still unreadable; only blank means zero");
  assert.equal(r.score(2), 0);
});

/* ---------- counting ---------- */

test("count/above-zero counts fields holding a number greater than zero", () => {
  const cfg = { type:"count", dir:"max", fields:[4, 5, 6], counts:"above-zero" };
  const [r] = build([cfg]);
  assert.equal(r.score(0), 1, "0, 5, '' -> only the 5");
  assert.equal(r.score(1), 2, "3, 0, 7");
  assert.equal(r.score(2), 2, "'', 2, 9");
});

test("count/filled counts fields that merely have something in them", () => {
  const [r] = build([{ type:"count", dir:"max", fields:[4, 5, 6], counts:"filled" }]);
  assert.equal(r.score(0), 2, "'0' and '5' are both present");
  assert.equal(r.score(1), 3);
  assert.equal(r.score(2), 2);
});

test("above-zero and filled are genuinely different questions", () => {
  const above = build([{ type:"count", dir:"max", fields:[4, 5, 6], counts:"above-zero" }]);
  const filled = build([{ type:"count", dir:"max", fields:[4, 5, 6], counts:"filled" }]);
  assert.notEqual(above[0].score(0), filled[0].score(0),
    "a cell holding '0' is filled but not above zero");
});

test("counts defaults to above-zero, matching the preset wording", () => {
  const [r] = build([{ type:"count", dir:"max", fields:[4, 5, 6] }]);
  assert.equal(r.score(0), 1);
});

/* ---------- switching a criterion off ---------- */

test("a rule marked off is not built into the chain", () => {
  const rules = build([
    { type:"minmax", parse:"date", dir:"max", field:1, fmt:"ISO", on:false },
    { type:"minmax", parse:"text", dir:"min", field:3 },
  ]);
  assert.equal(rules.length, 1, "the disabled criterion does not run");
  assert.equal(rules[0].type, "text");
});

test("on:true and an absent on are both active", () => {
  assert.equal(build([{ type:"minmax", parse:"text", dir:"min", field:3, on:true }]).length, 1);
  assert.equal(build([{ type:"minmax", parse:"text", dir:"min", field:3 }]).length, 1);
});

test("switching a rule off changes which row survives", () => {
  const date = { type:"minmax", parse:"date", dir:"max", field:1, fmt:"ISO" };
  const text = { type:"minmax", parse:"text", dir:"min", field:3 };
  assert.equal(win([date, text]), 1, "the date decides");
  assert.equal(win([Object.assign({}, date, { on:false }), text]), 1, "now the text decides: alpha");
});

/* ---------- hasvalue survives, it is what reproduces the base tool ---------- */

test("hasvalue still works under the new wording", () => {
  const [r] = build([{ type:"hasvalue", field:6 }]);
  assert.equal(r.score(0), null, "row 1's c is empty");
  assert.equal(r.score(1), 1);
});

/* ---------- the chain sentence ---------- */

test("the chain reads in the preset's own vocabulary", () => {
  const parts = R.describeChain([
    { type:"minmax", parse:"date", dir:"min", field:1, fmt:"ISO" },
    { type:"minmax", parse:"number", dir:"min", field:2, strip:"prefix", pfx:"INV-" },
    { type:"count", dir:"max", fields:[4, 5, 6], counts:"above-zero" },
  ], i => HEAD[i]);
  assert.match(parts[0], /oldest when/);
  assert.match(parts[1], /lowest amount/);
  assert.match(parts[2], /most fields above zero across 3/);
});

test("a disabled rule is described as such rather than omitted", () => {
  const parts = R.describeChain([{ type:"minmax", parse:"text", dir:"min", field:3, on:false }],
                                i => HEAD[i]);
  assert.match(parts[0], /off/i, "the reader should see it exists and is not running");
});
