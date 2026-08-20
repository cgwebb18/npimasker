/* "Highest number of non-null values for a given set of columns". */
import test from "node:test";
import assert from "node:assert/strict";
import { loadRules, cellsOf } from "./harness.mjs";

const R = loadRules();

//            0      1        2       3
const ROWS = [
  ["Ann", "555-1234", "a@x.com", "12 High St"],  // 0 -> 4 filled
  ["Bob", "",         "b@x.com", ""          ],  // 1 -> 2 filled
  ["Cid", "555-9999", "",        "9 Low Rd"  ],  // 2 -> 3 filled
  ["",    "",         "",        ""          ],  // 3 -> 0 filled
  ["Eve", "   ",      "e@x.com", "  "        ],  // 4 -> 2 filled (ws = empty)
];
const COLS = [0, 1, 2, 3];
const cellAt = cellsOf(ROWS);

test("scores the count of non-empty cells in the chosen columns", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true });
  assert.equal(rule.score(0), 4);
  assert.equal(rule.score(1), 2);
  assert.equal(rule.score(2), 3);
  assert.equal(rule.score(3), 0);
});

test("a fully empty row scores zero, not null", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true });
  assert.equal(rule.score(3), 0, "0 is a real score; the row is a valid candidate");
  assert.notEqual(rule.score(3), null);
});

test("whitespace-only cells count as empty when the setting is on", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true });
  assert.equal(rule.score(4), 2, "Eve: name and email only");
});

test("whitespace-only cells count as filled when the setting is off", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: false });
  assert.equal(rule.score(4), 4);
});

test("the most complete row wins by default", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true });
  assert.equal(R.pickWinner([0, 1, 2, 3], [rule]).winner, 0);
});

test("direction can be flipped to keep the least complete row", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true, dir: -1 });
  assert.equal(R.pickWinner([0, 1, 2, 3], [rule]).winner, 3);
});

test("equal completeness ties, leaving it to the next level", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, COLS, { wsBlank: true });
  const got = R.pickWinner([1, 4], [rule]);   // both score 2
  assert.equal(got.trail[0].outcome, "tied");
  assert.equal(got.winner, 4, "unbroken tie falls through to file order");
});

test("only the chosen columns are counted", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, [2, 3], { wsBlank: true });
  assert.equal(rule.score(0), 2);
  assert.equal(rule.score(1), 1);
  assert.equal(rule.score(4), 1);
});

test("reports its type and column set", () => {
  const rule = R.makeCompletenessRule(cellAt, ROWS.length, [1, 2], { wsBlank: true });
  assert.equal(rule.type, "complete");
  assert.deepEqual(rule.cols, [1, 2]);
  assert.equal(rule.dir, 1);
});
