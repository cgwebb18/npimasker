/* End-to-end acceptance for a multi-level rule chain, against sample_rules.csv.
 *
 * The fixture is built so each level decides at least one group and one group
 * reaches the fallback. Row counts alone would pass even with the levels
 * running in the wrong order, so the real assertion is the attribution:
 * which level decided which group.
 *
 *   Level 1  date, latest service_date
 *   Level 2  number, lowest invoice_no, "INV-" ignored
 *   Level 3  completeness across phone / email / address
 *   then     last row in file order
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadRules, loadCsv } from "./harness.mjs";

const R = loadRules();
const C = loadCsv();
const SAMPLE = new URL("../sample_rules.csv", import.meta.url);

const REF = 0, SITE = 1, SVC = 2, INV = 3, PHONE = 4, EMAIL = 5, ADDR = 6;
const KEYS = [REF, SITE];

function ingest(text){
  let grid = C.parseCSV(text);
  grid = grid.filter(row => row.some(c => String(c ?? "").length));
  const headers = grid[0].map(h => String(h ?? ""));
  const w = headers.length;
  const rows = grid.slice(1).map(row => {
    const out = new Array(w);
    for (let i = 0; i < w; i++) out[i] = String(row[i] ?? "");
    return out;
  });
  return { headers, rows };
}

const CHAIN = [
  { type: "date",     col: SVC, dir: +1, format: "iso" },
  { type: "number",   col: INV, dir: -1, prefixes: ["INV-"], decimal: "us", mode: "strict" },
  { type: "complete", cols: [PHONE, EMAIL, ADDR], dir: +1 },
];

function run(){
  const { headers, rows } = ingest(readFileSync(SAMPLE, "utf8"));
  const cellAt = (i, c) => rows[i][c];
  const out = R.collapseRows({
    n: rows.length,
    cellAt,
    keys: KEYS,
    norm: R.makeNorm(new Map(), {}),
    anyPfx: false,
    rules: R.buildRules(CHAIN, cellAt, rows.length, true),
    wsBlank: true,
    tie: SVC,
    sampleLimit: 30,
  });
  return { headers, rows, out };
}

/* Look up the group a given ref_id landed in. */
function groupFor(rows, out, ref){
  return out.samples.find(s => rows[s.idxs[0]][REF] === ref);
}

test("the fixture has the shape the plan describes", () => {
  const { headers, rows } = ingest(readFileSync(SAMPLE, "utf8"));
  assert.equal(headers[SVC], "service_date");
  assert.equal(headers[INV], "invoice_no");
  assert.equal(rows.length, 15, "15 rows in");
});

test("arithmetic: 15 in, 7 removed, 8 out, 5 colliding groups", () => {
  const { out } = run();
  assert.equal(out.stats.rowsIn, 15);
  assert.equal(out.stats.removed, 7);
  assert.equal(out.stats.rowsOut, 8);
  assert.equal(out.stats.dupGroups, 5);
  assert.equal(out.stats.rowsIn - out.stats.removed, out.stats.rowsOut);
});

test("every level decides a group, and one group reaches the fallback", () => {
  const { out } = run();
  assert.deepEqual(out.decidedAt, [2, 1, 1, 1],
    "level 1 decides 2 groups (A and E), level 2 one, level 3 one, file order one");
});

test("group A is decided by the date, keeping the latest", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "A-100");
  assert.equal(g.decidedBy, 0);
  assert.equal(rows[g.winner][SVC], "2026-05-20", "the latest of the three");
});

test("group B ties on date and is decided by the lowest invoice number", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "B-200");
  assert.equal(g.trail[0].outcome, "tied", "the dates are identical");
  assert.equal(g.decidedBy, 1);
  assert.equal(rows[g.winner][INV], "INV-000042", "lowest once INV- is ignored");
});

test("the invoice comparison ignores the prefix rather than sorting as text", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "B-200");
  const values = g.idxs.map(i => rows[i][INV]);
  assert.ok(values.includes("INV-000420"));
  assert.ok(values.includes("INV-000042"));
  assert.equal(rows[g.winner][INV], "INV-000042",
    "42 < 420 numerically; as text 000042 < 000420 too, so also assert the sign is right");
  assert.notEqual(rows[g.winner][INV], "INV-000420");
});

test("group C ties on date and invoice, and is decided by completeness", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "C-300");
  assert.equal(g.decidedBy, 2);
  const w = rows[g.winner];
  assert.equal([w[PHONE], w[EMAIL], w[ADDR]].filter(v => v.trim()).length, 3,
    "the row that fills all three contact columns");
});

test("group D ties everywhere and falls through to the last row in the file", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "D-400");
  assert.equal(g.decidedBy, null);
  assert.equal(g.winner, g.idxs[g.idxs.length - 1]);
  assert.match(g.reason, /last one in the file/);
});

test("group E: a row whose date cannot be read loses to one that can", () => {
  const { rows, out } = run();
  const g = groupFor(rows, out, "E-500");
  assert.equal(g.decidedBy, 0);
  assert.equal(rows[g.winner][SVC], "2026-02-01");
  const loser = g.idxs.find(i => i !== g.winner);
  assert.equal(rows[loser][SVC], "not recorded",
    "eliminated for having no readable date, not for being earlier");
});

test("the unreadable date is counted, not silently absorbed", () => {
  const { rows } = ingest(readFileSync(SAMPLE, "utf8"));
  const cellAt = (i, c) => rows[i][c];
  const rule = R.makeDateRule(cellAt, rows.length, SVC, { format: "iso" });
  assert.equal(rule.unreadable, 1);
});

test("reordering the chain changes the outcome, proving order is respected", () => {
  const { rows } = ingest(readFileSync(SAMPLE, "utf8"));
  const cellAt = (i, c) => rows[i][c];
  const swapped = [CHAIN[1], CHAIN[0], CHAIN[2]];   // number before date
  const out = R.collapseRows({
    n: rows.length, cellAt, keys: KEYS,
    norm: R.makeNorm(new Map(), {}), anyPfx: false,
    rules: R.buildRules(swapped, cellAt, rows.length, true),
    wsBlank: true, tie: SVC, sampleLimit: 30,
  });
  const g = out.samples.find(s => rows[s.idxs[0]][REF] === "A-100");
  assert.equal(g.decidedBy, 0, "now the invoice number decides group A");
  assert.notEqual(rows[g.winner][SVC], "2026-05-20",
    "a different row survives than when the date led");
});
