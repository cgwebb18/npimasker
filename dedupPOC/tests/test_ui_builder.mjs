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

function boot(store){
  const p = bootPage(store);
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
    { type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" },
    { type:"minmax", parse:"number", dir:"min", field:3, strip:"prefix", pfx:"INV-" },
  ];
  p.renderRules();
  const labels = p.el("ruleList").findAll(e => e.className === "rule-lvl").map(e => e.textContent);
  assert.deepEqual(labels, ["LEVEL 1", "LEVEL 2"]);
});

test("the chain sentence names every level and ends with the fallback", () => {
  const p = boot();
  p.RULECFG = [
    { type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" },
    { type:"minmax", parse:"number", dir:"min", field:3, strip:"prefix", pfx:"INV-" },
    { type:"count", dir:"max", fields:[4, 5], counts:"filled" },
  ];
  p.renderRules();
  const text = p.el("ruleChain").innerHTML;
  assert.match(text, /newest service_date/);
  assert.match(text, /lowest invoice_no/);
  assert.match(text, /most columns filled across 2/);
  assert.match(text, /nearest the top of the file/, "the fallback is always shown");
});

test("a counting rule with no columns blocks the run and says why", () => {
  const p = boot();
  p.keySet.add(0);
  p.RULECFG = [{ type:"count", dir:"max", fields:[], counts:"above-zero" }];
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
  p.RULECFG = [{ type:"minmax", parse:"date", dir:"max", field:1 }];
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
  p.RULECFG = [{ type:"minmax", parse:"date", dir:"max", field:1 }];
  p.renderRules();
  p.syncPick();
  assert.equal(p.RULECFG[0].fmt, "DMY", "day-first, proved by 27");
  assert.equal(p.el("run").disabled, false);
  assert.equal(p.el("ruleErr").hidden, true);
});

test("running a two-level chain produces the expected survivors", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [
    { type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" },
    { type:"minmax", parse:"number", dir:"min", field:3, strip:"prefix", pfx:"INV-" },
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
    { type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" },
    { type:"minmax", parse:"number", dir:"min", field:3, strip:"prefix", pfx:"INV-" },
  ];
  p.syncPick();
  p.runCollapse();
  const attrib = p.el("attrib").innerHTML;
  assert.match(attrib, /Which rule decided/);
  assert.match(attrib, /newest service_date/);
  assert.match(attrib, /lowest invoice_no/);
});

test("loading a second file clears the first file's result and rules", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [{ type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" }];
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
  p.RULECFG = [{ type:"hasvalue", field:4 }];
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

test("a criterion can be switched off and back on from the rule row", () => {
  const p = boot();
  p.RULECFG = [{ type:"minmax", parse:"text", dir:"min", field:3 }];
  p.renderRules();
  const sw = p.el("ruleList").find(e => e.textContent === "on");
  assert.ok(sw, "the row carries an on/off switch");
  sw.fire("click");
  assert.equal(p.RULECFG[0].on, false, "kept in the list, not run");
  assert.match(p.el("ruleChain").innerHTML, /\(off\)/, "and the chain says so");
});

test("a switched-off criterion is not validated", () => {
  const p = boot();
  p.keySet.add(0);
  // no columns chosen would normally block the run
  p.RULECFG = [{ type:"count", dir:"max", fields:[], counts:"above-zero", on:false },
               { type:"hasvalue", field:4 }];
  p.syncPick();
  assert.equal(p.el("run").disabled, false, "an inactive rule cannot be invalid");
});

/* ---------- saved datasets ---------- */

test("saving writes a .json file and puts the settings in the picker", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [{ type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" }];
  p.setPrompt("Casenotes");
  p.el("presetSave").fire("click");

  const written = p.blobs.find(b => b.includes('"label"'));
  assert.ok(written, "a settings file was produced");
  const parsed = JSON.parse(written);
  assert.equal(parsed.label, "Casenotes");
  assert.deepEqual(parsed.match, ["ref_id", "site"], "saved by name, not position");
  assert.equal(parsed.rules[0].field, "service_date");
  assert.equal(p.SAVED.length, 1, "and it is in the list");
});

test("saved settings survive into the next session", () => {
  const p = boot();
  p.keySet.add(0);
  p.setPrompt("Casenotes");
  p.el("presetSave").fire("click");
  assert.ok(p.store.get("collapse-duplicates.presets.v1"), "kept in this browser");

  // a fresh page sharing the same storage
  const q = boot(p.store);
  assert.equal(q.SAVED.length, 1, "already in the list without loading a file");
  assert.equal(q.SAVED[0].label, "Casenotes");
});

test("applying a preset restores match columns and criteria", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [{ type:"minmax", parse:"number", dir:"min", field:3, strip:"prefix", pfx:"INV-" }];
  p.setPrompt("Invoices");
  p.el("presetSave").fire("click");

  const q = boot(p.store);                // fresh page, same storage
  q.applyPreset(q.SAVED[0]);
  assert.deepEqual([...q.keySet].sort(), [0, 1]);
  assert.equal(q.RULECFG[0].field, 3);
  assert.equal(q.RULECFG[0].pfx, "INV-");
});

test("a preset naming a column this file lacks warns and switches that rule off", () => {
  const p = boot();
  p.applyPreset({
    version: 1, label: "Elsewhere", note: "", match: ["ref_id"], prefix: {},
    rules: [{ type:"minmax", parse:"date", dir:"max", field:"Not A Column", fmt:"ISO", on:true }],
  });
  assert.equal(p.el("presetWarn").hidden, false);
  assert.match(p.el("presetWarn").textContent, /Not A Column/);
  assert.equal(p.RULECFG[0].on, false, "inert and visible, never silently rebound");
});

test("a preset with an unchosen column blocks the run and names it", () => {
  const p = boot();
  p.applyPreset({
    version:1, label:"Casenotes", note:"Choose Last Modified Date.",
    match:["ref_id"], prefix:{},
    rules:[{ type:"minmax", parse:"date", dir:"min", field:"__PICK_LAST_DATE__", on:true }],
  });
  assert.equal(p.RULECFG[0].on, true, "waiting on a person, not broken");
  assert.equal(p.RULECFG[0].needs, "__PICK_LAST_DATE__");
  assert.equal(p.el("run").disabled, true, "cannot run until it is chosen");
  assert.match(p.el("ruleErr").textContent, /__PICK_LAST_DATE__/);
  assert.match(p.el("presetWarn").textContent, /Choose Last Modified Date/);
});

test("choosing the column clears the block", () => {
  const p = boot();
  p.applyPreset({
    version:1, label:"x", note:"", match:["ref_id"], prefix:{},
    rules:[{ type:"minmax", parse:"date", dir:"min", field:"__PICK_LAST_DATE__", fmt:"ISO", on:true }],
  });
  p.RULECFG[0].field = 2; delete p.RULECFG[0].needs;
  p.syncPick();
  assert.equal(p.el("run").disabled, false);
});

test("a switched-off criterion does not shift the inspector's values", () => {
  const p = boot();
  p.keySet.add(0); p.keySet.add(1);
  p.RULECFG = [
    { type:"minmax", parse:"text", dir:"min", field:5, on:false },   // off
    { type:"minmax", parse:"date", dir:"max", field:2, fmt:"ISO" },
  ];
  p.syncPick();
  p.runCollapse();
  const R = p.RESULT;
  assert.equal(R.chain.length, 1, "only the active criterion is indexed with the values");
  assert.equal(R.chainAll.length, 2, "but the summary still lists both");
  assert.match(R.chainAll[0], /\(off\)/);
  const g = R.samples[0];
  assert.equal(g.shown[0].length, 1, "one value per active criterion, correctly aligned");
});
