/* The rule-builder UI actually running: attaching handlers, rendering rows,
   validating, and driving a real collapse through runCollapse(). */
import test from "node:test";
import assert from "node:assert/strict";
import { bootPage } from "./domshim.mjs";

const HEADERS = ["ref_id", "site", "service_date", "invoice_no", "phone", "email"];
const ROWS = [
  ["A-1", "S1", "2026-01-10", "INV-000100", "555-1", ""],
  ["A-1", "S1", "2026-05-20", "INV-000900", "555-2", "a@x.com"],
  ["B-2", "S2", "2026-04-01", "INV-000420", "", ""],
  ["B-2", "S2", "2026-04-01", "INV-000042", "555-3", "b@x.com"],
];

function boot(){
  const p = bootPage();
  p.setData(HEADERS, ROWS);
  p.buildPickers();
  return p;
}

test("the page loads and wires its handlers without throwing", () => {
  const p = bootPage();
  assert.ok(p.el("addRule").listeners.click, "the add-rule button is wired");
  assert.ok(p.el("run").listeners.click, "the run button is wired");
});

test("loading a file seeds exactly one rule", () => {
  const p = boot();
  assert.equal(p.RULECFG.length, 1);
  assert.equal(p.RULECFG[0].type, "hasvalue");
});

test("the add-rule button appends a level", () => {
  const p = boot();
  p.el("addRule").fire("click");
  assert.equal(p.RULECFG.length, 2);
  p.el("addRule").fire("click");
  assert.equal(p.RULECFG.length, 3);
});

test("each rule renders a row carrying its level number", () => {
  const p = boot();
  p.RULECFG = [
    { type: "date", col: 2, dir: +1, format: "iso" },
    { type: "number", col: 3, dir: -1, prefixes: ["INV-"], decimal: "us", mode: "strict" },
  ];
  p.renderRules();
  const labels = p.el("ruleList").findAll(e => e.className === "rule-lvl").map(e => e.textContent);
  assert.deepEqual(labels, ["LEVEL 1", "LEVEL 2"]);
});

test("the chain sentence names every level and ends with the fallback", () => {
  const p = boot();
  p.RULECFG = [
    { type: "date", col: 2, dir: +1, format: "iso" },
    { type: "number", col: 3, dir: -1, prefixes: ["INV-"], decimal: "us", mode: "strict" },
    { type: "complete", cols: [4, 5], dir: +1 },
  ];
  p.renderRules();
  const text = p.el("ruleChain").innerHTML;
  assert.match(text, /latest service_date/);
  assert.match(text, /lowest invoice_no/);
  assert.match(text, /most of 2 columns/);
  assert.match(text, /nearest the top of the file/, "the fallback is always shown");
});

test("a completeness rule with no columns blocks the run and says why", () => {
  const p = boot();
  p.keySet.add(0);
  p.RULECFG = [{ type: "complete", cols: [], dir: +1 }];
  p.syncPick();
  assert.equal(p.el("run").disabled, true);
  assert.equal(p.el("ruleErr").hidden, false);
  assert.match(p.el("ruleErr").textContent, /choose at least one column/);
});

test("an ambiguous date column blocks the run rather than guessing", () => {
  const p = bootPage();
  p.setData(["id", "when"], [["1", "04/03/2026"], ["2", "05/06/2026"]]);
  p.buildPickers();
  p.keySet.add(0);
  p.RULECFG = [{ type: "date", col: 1, dir: +1 }];
  p.renderRules();
  p.syncPick();
  assert.equal(p.el("run").disabled, true);
  assert.match(p.el("ruleErr").textContent, /choose the date format/);
});

test("an unambiguous date column resolves itself and allows the run", () => {
  const p = bootPage();
  p.setData(["id", "when"], [["1", "27/11/2026"], ["2", "04/03/2026"]]);
  p.buildPickers();
  p.keySet.add(0);
  p.RULECFG = [{ type: "date", col: 1, dir: +1 }];
  p.renderRules();
  p.syncPick();
  assert.equal(p.RULECFG[0].format, "dmy", "day-first, proved by 27");
  assert.equal(p.el("run").disabled, false);
  assert.equal(p.el("ruleErr").hidden, true);
});

test("running a two-level chain produces the expected survivors", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [
    { type: "date", col: 2, dir: +1, format: "iso" },
    { type: "number", col: 3, dir: -1, prefixes: ["INV-"], decimal: "us", mode: "strict" },
  ];
  p.syncPick();
  assert.equal(p.el("run").disabled, false);
  p.runCollapse();

  const R = p.RESULT;
  assert.equal(R.stats.rowsIn, 4);
  assert.equal(R.stats.rowsOut, 2);
  assert.equal(R.stats.dupGroups, 2);
  assert.deepEqual(R.kept[0], ROWS[1], "A-1: latest date");
  assert.deepEqual(R.kept[1], ROWS[3], "B-2: dates tie, lowest invoice");
  assert.deepEqual(R.decidedAt, [1, 1, 0], "one group per level, none by fallback");
});

test("the result panel reports which rule decided each collision", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [
    { type: "date", col: 2, dir: +1, format: "iso" },
    { type: "number", col: 3, dir: -1, prefixes: ["INV-"], decimal: "us", mode: "strict" },
  ];
  p.syncPick();
  p.runCollapse();
  const attrib = p.el("attrib").innerHTML;
  assert.match(attrib, /Which rule decided/);
  assert.match(attrib, /latest service_date/);
  assert.match(attrib, /lowest invoice_no/);
});

test("loading a second file clears the first file's result and rules", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [{ type: "date", col: 2, dir: +1, format: "iso" }];
  p.syncPick();
  p.runCollapse();
  assert.ok(p.RESULT, "a result exists");

  // buildPickers is what a fresh file ends up calling
  p.setData(["a", "b"], [["1", "2"]]);
  p.buildPickers();
  assert.equal(p.RULECFG.length, 1, "rules are rebuilt for the new file");
  assert.equal(p.RULECFG[0].type, "hasvalue", "and reset to the default");
});

test("a failed .xlsx write reports itself instead of doing nothing", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [{ type: "hasvalue", col: 4, dir: +1 }];
  p.syncPick();
  p.runCollapse();
  // the shim's XLSX.write throws, standing in for the 128MiB ceiling
  p.el("dlClean").fire("click");
  assert.equal(p.el("dlErr").hidden, false, "the user must be told");
  assert.match(p.el("dlErr").textContent, /\.csv button instead/,
    "and pointed at the export that actually works at this size");
});

test("removed rows can be exported as CSV, not only as xlsx", () => {
  const p = boot();
  assert.ok(p.el("dlRemovedCsv").listeners.click,
    "above the xlsx ceiling this is the only way to get the audit file");
});
