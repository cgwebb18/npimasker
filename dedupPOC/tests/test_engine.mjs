/* The narrowing engine and the has-value rule (plan phase 1). */
import test from "node:test";
import assert from "node:assert/strict";
import { loadRules, cellsOf } from "./harness.mjs";

const R = loadRules();

/* A rule built straight from a score table, for testing the engine itself
   without dragging a real rule type into it. null = no usable value. */
function ruleFrom(scores, dir = +1){
  return { type: "test", dir, score: i => scores[i] };
}

test("no rules at all: the row nearest the top of the file wins", () => {
  const got = R.pickWinner([3, 7, 11], []);
  assert.equal(got.winner, 3);
  assert.equal(got.decidedBy, null);
});

test("a single-row group returns that row", () => {
  const got = R.pickWinner([5], [ruleFrom({ 5: 1 })]);
  assert.equal(got.winner, 5);
  assert.equal(got.decidedBy, null, "nothing was decided; there was no contest");
});

test("one level, one clear best: that row wins regardless of position", () => {
  const got = R.pickWinner([0, 1, 2], [ruleFrom({ 0: 5, 1: 9, 2: 3 })]);
  assert.equal(got.winner, 1);
  assert.equal(got.decidedBy, 0);
});

test("direction -1 picks the lowest score", () => {
  const got = R.pickWinner([0, 1, 2], [ruleFrom({ 0: 5, 1: 9, 2: 3 }, -1)]);
  assert.equal(got.winner, 2);
});

test("rows scoring null are eliminated when others have a value", () => {
  const got = R.pickWinner([0, 1, 2], [ruleFrom({ 0: null, 1: 4, 2: null })]);
  assert.equal(got.winner, 1);
});

test("when no row has a usable value the level is skipped, not failed", () => {
  const got = R.pickWinner([0, 1, 2], [ruleFrom({ 0: null, 1: null, 2: null })]);
  assert.equal(got.winner, 0, "falls through to file order");
  assert.equal(got.decidedBy, null);
  assert.equal(got.trail[0].outcome, "skipped");
});

test("a later level breaks a tie left by an earlier one", () => {
  const lvl1 = ruleFrom({ 0: 7, 1: 7, 2: 1 });   // 0 and 1 tie at the top
  const lvl2 = ruleFrom({ 0: 2, 1: 9, 2: 9 });   // among {0,1}, row 1 wins
  const got = R.pickWinner([0, 1, 2], [lvl1, lvl2]);
  assert.equal(got.winner, 1);
  assert.equal(got.decidedBy, 1, "level 2 is what actually decided it");
});

test("a level that cannot separate the candidates is recorded as tied", () => {
  const lvl1 = ruleFrom({ 0: 3, 1: 3 });
  const got = R.pickWinner([0, 1], [lvl1]);
  assert.equal(got.trail[0].outcome, "tied");
  assert.equal(got.winner, 0, "unbroken tie falls through to file order");
  assert.equal(got.decidedBy, null);
});

test("later levels cannot re-admit a row an earlier level eliminated", () => {
  const lvl1 = ruleFrom({ 0: 1, 1: 9, 2: 9 });   // row 0 is out
  const lvl2 = ruleFrom({ 0: 100, 1: 5, 2: 2 }); // row 0 would win if re-admitted
  const got = R.pickWinner([0, 1, 2], [lvl1, lvl2]);
  assert.notEqual(got.winner, 0, "monotone: eliminated rows stay eliminated");
  assert.equal(got.winner, 1);
});

test("evaluation stops once one candidate remains", () => {
  let level2Ran = false;
  const lvl1 = ruleFrom({ 0: 1, 1: 9 });
  const lvl2 = { type: "test", dir: +1, score(){ level2Ran = true; return 1; } };
  R.pickWinner([0, 1], [lvl1, lvl2]);
  assert.equal(level2Ran, false, "no point scoring a field of one");
});

test("ties preserve file order, so the fallback is the genuine first row", () => {
  const all = ruleFrom({ 10: 1, 4: 1, 22: 1, 7: 1 });
  const got = R.pickWinner([4, 7, 10, 22], [all]);
  assert.equal(got.winner, 4);
});

test("every group yields exactly one winner drawn from the group", () => {
  const groups = [[0], [0, 1], [2, 5, 9], [1, 3, 4, 8, 12]];
  const rules = [ruleFrom({ 0: null, 1: 2, 2: 2, 3: null, 4: 2, 5: null, 8: 2, 9: 2, 12: null })];
  for (const g of groups){
    const got = R.pickWinner(g, rules);
    assert.ok(g.includes(got.winner), "winner must come from the group");
  }
});

/* ---------- the has-value rule ---------- */

test("has-value keeps the first row carrying a value", () => {
  const rows = [["a", ""], ["b", "x"], ["c", "y"], ["d", ""]];
  const rule = R.makeHasValueRule(cellsOf(rows), 1, true);
  const got = R.pickWinner([0, 1, 2, 3], [rule]);
  assert.equal(got.winner, 1);
});

test("has-value with nothing filled falls through to the first row", () => {
  const rows = [["a", ""], ["b", ""], ["c", ""]];
  const rule = R.makeHasValueRule(cellsOf(rows), 1, true);
  const got = R.pickWinner([0, 1, 2], [rule]);
  assert.equal(got.winner, 0);
  assert.equal(got.decidedBy, null);
});

test("whitespace counts as empty when the setting is on", () => {
  const rows = [["a", "   "], ["b", "v"]];
  const rule = R.makeHasValueRule(cellsOf(rows), 1, true);
  assert.equal(R.pickWinner([0, 1], [rule]).winner, 1,
    "only row 1 carries a value, so position does not save row 0");
});

test("whitespace counts as a value when the setting is off", () => {
  const rows = [["a", "v"], ["b", "   "]];
  const rule = R.makeHasValueRule(cellsOf(rows), 1, false);
  assert.equal(R.pickWinner([0, 1], [rule]).winner, 0,
    "both carry a value, so the first one wins");
});

test("has-value is direction-maximum and reports its column", () => {
  const rule = R.makeHasValueRule(cellsOf([["a"]]), 0, true);
  assert.equal(rule.dir, 1);
  assert.equal(rule.col, 0);
  assert.equal(rule.type, "hasvalue");
});
