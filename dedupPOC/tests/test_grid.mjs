/* Turning a raw parsed grid into headers + rows.
 *
 * Field report: partners saw "(unnamed column)" chips on their largest file.
 * Root cause is not the file's size or its very long values -- both were tested
 * and are harmless. SheetJS 0.18.5 takes the sheet's column range straight from
 * the xlsx <dimension> tag, which Excel routinely over-declares after columns
 * are deleted or stray formatting is left behind. sheet_to_json then pads every
 * row out to that declared width with empty strings, and each phantom column
 * arrives as an unnamed one.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { loadGrid } from "./harness.mjs";

const G = loadGrid();

test("columns that are empty in every row are dropped", () => {
  const t = G.gridToTable([
    ["Id", "Account", "", "", ""],
    ["1", "Acme", "", "", ""],
    ["2", "Globex", "", "", ""],
  ]);
  assert.equal(t.width, 2, "the three phantom columns go");
  assert.deepEqual(t.headers, ["Id", "Account"]);
  assert.deepEqual(t.rows[0], ["1", "Acme"]);
});

test("a trailing column carrying data anywhere is kept", () => {
  const t = G.gridToTable([
    ["Id", "Account", ""],
    ["1", "Acme", ""],
    ["2", "Globex", "late value"],
  ]);
  assert.equal(t.width, 3, "one value in one row is enough to make it real");
  assert.equal(t.headers[2], "", "it has no header, but it exists");
});

test("an interior column with a header but no data is kept", () => {
  const t = G.gridToTable([
    ["Id", "Notes", "Owner"],
    ["1", "", "Ann"],
    ["2", "", "Bob"],
  ]);
  assert.equal(t.width, 3);
  assert.deepEqual(t.headers, ["Id", "Notes", "Owner"]);
});

test("data wider than the header is preserved, not truncated", () => {
  // The old behaviour took the width from the header row alone and silently
  // dropped everything past it.
  const t = G.gridToTable([
    ["Id", "Account"],
    ["1", "Acme", "EXTRA"],
    ["2", "Globex", "ALSO"],
  ]);
  assert.equal(t.width, 3);
  assert.deepEqual(t.rows[0], ["1", "Acme", "EXTRA"]);
  assert.deepEqual(t.rows[1], ["2", "Globex", "ALSO"]);
  assert.equal(t.headers[2], "", "no header for it, but the data survives");
});

test("short rows are padded so every row is the same width", () => {
  const t = G.gridToTable([
    ["Id", "Account", "Owner"],
    ["1"],
    ["2", "Globex"],
  ]);
  assert.equal(t.rows[0].length, 3);
  assert.deepEqual(t.rows[0], ["1", "", ""]);
  assert.deepEqual(t.rows[1], ["2", "Globex", ""]);
});

test("everything is a string, including numbers and nulls", () => {
  const t = G.gridToTable([["Id", "N"], [1, null], [2, undefined]]);
  assert.deepEqual(t.rows[0], ["1", ""]);
  assert.deepEqual(t.rows[1], ["2", ""]);
});

test("blank rows are dropped", () => {
  const t = G.gridToTable([
    ["Id", "Account"],
    ["", ""],
    ["1", "Acme"],
  ]);
  assert.equal(t.rows.length, 1);
});

test("a grid with no content at all yields no columns", () => {
  const t = G.gridToTable([["", ""], ["", ""]]);
  assert.equal(t.width, 0);
});

/* ---------- how a column with no header is described ---------- */

test("a headerless column is named by its letter, not called unnamed", () => {
  // "(unnamed 6)" reads like a fault. "column F" is just a fact about a real
  // column that happens to have no heading, and it points at where to look.
  assert.equal(G.headerLabel(["Id", ""], 1), "column B");
  assert.equal(G.headerLabel(["Id", "Account"], 1), "Account");
});

test("column letters continue past Z", () => {
  assert.equal(G.colLetter(0), "A");
  assert.equal(G.colLetter(25), "Z");
  assert.equal(G.colLetter(26), "AA");
  assert.equal(G.colLetter(701), "ZZ");
  assert.equal(G.colLetter(702), "AAA");
});

test("NUL characters are stripped from cell values", () => {
  // NUL is the separator the grouping keys are built from. A NUL inside a cell
  // lets ("a\0b","c") and ("a","b\0c") build the same key, which would merge
  // two genuinely different rows.
  const Z = String.fromCharCode(0);
  const t = G.gridToTable([["Id", "Name"], ["1", "An" + Z + "n"]]);
  assert.equal(t.rows[0][1], "Ann");
  assert.ok(!t.rows[0][1].includes(Z));
});
